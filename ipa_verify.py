#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check that every Mach-O in an IPA is decrypted, slice by slice, on this computer.

frida-ios-dump decrypts only code loaded in the app's own process, so app extensions,
Watch apps and frameworks the app had not loaded yet can stay FairPlay-encrypted.

Usage: ipa_verify.py FILE.ipa [...]   (prints one line per IPA and the encrypted files)
"""

import stat
import struct
import sys
import zipfile

from app_info import arch_name

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
MAX_FAT_ARCHS = 32  # 0xCAFEBABE also starts Java class files, whose next field is a large version

# Results, also used as the IPA {type} once file names follow them.
DECRYPTED = 'decrypted'
PARTIAL_32BIT = 'partial-64bit-decrypted'  # only 32-bit slices of fat binaries with a decrypted arm64 slice
PARTIAL = 'partial-decrypted'
ARCH_ORDER = ('armv6', 'armv7', 'armv7s', 'arm64', 'arm64e')  # the order architectures appear in a type
NO_MACHO = 'no-macho'


def partial_type(archs):
    """'partial-decrypted-armv6-armv7' for the architectures that are decrypted; PARTIAL when none or unknown ones."""
    archs = set(archs)
    if not archs or not archs <= set(ARCH_ORDER):
        return PARTIAL
    return 'partial-decrypted-' + '-'.join(a for a in ARCH_ORDER if a in archs)


def all_types():
    """Every type an IPA name can get, partial ones for every combination of architectures (and the
    older 'partial-64bit-decrypted', so IPAs written by earlier versions are still found)."""
    types = [DECRYPTED, PARTIAL, PARTIAL_32BIT]
    for mask in range(1, 1 << len(ARCH_ORDER)):
        name = partial_type(a for i, a in enumerate(ARCH_ORDER) if mask >> i & 1)
        if name not in types:
            types.append(name)
    return tuple(types)


class Slice:
    """One architecture of a Mach-O file. Offsets are from the start of the file, so the encrypted
    range is [offset + cryptoff, offset + cryptoff + cryptsize) and cryptid sits at cryptid_at."""
    __slots__ = ('arch', 'encrypted', 'cpu', 'subtype', 'offset', 'cryptoff', 'cryptsize', 'cryptid', 'cryptid_at')

    def __init__(self, arch, encrypted, cpu=0, subtype=0, offset=0, cryptoff=0, cryptsize=0, cryptid=0,
                 cryptid_at=None):
        self.arch = arch
        self.encrypted = encrypted
        self.cpu = cpu
        self.subtype = subtype
        self.offset = offset
        self.cryptoff = cryptoff
        self.cryptsize = cryptsize
        self.cryptid = cryptid
        self.cryptid_at = cryptid_at

    @property
    def is_64bit(self):
        return self.arch.startswith('arm64') and self.arch != 'arm64_32'


class _Forward:
    """Forward-only reader that counts its position, so fat slices can be reached in a zip member."""

    def __init__(self, f):
        self.f = f
        self.position = 0

    def read(self, size):
        data = self.f.read(size)
        if len(data) != size:
            raise ValueError('truncated Mach-O')
        self.position += size
        return data

    def skip_to(self, offset):
        if offset < self.position:
            raise ValueError('overlapping fat slices')
        while self.position < offset:
            self.read(min(offset - self.position, 1 << 20))


def _thin_slice(f):
    """Parse the Mach-O header and load commands at f's position."""
    base = f.position
    magic = struct.unpack('<I', f.read(4))[0]
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        raise ValueError('fat slice is not a Mach-O')
    header_size = 32 if magic == MH_MAGIC_64 else 28
    header = f.read(header_size - 4)
    cpu, subtype, _, ncmds, sizeofcmds = struct.unpack_from('<iiIII', header, 0)
    commands = f.read(sizeofcmds)
    result = Slice(arch_name(cpu, subtype), False, cpu, subtype, base)
    offset = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', commands, offset)
        if size < 8:
            raise ValueError('bad load command')
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            cryptoff, cryptsize, cryptid = struct.unpack_from('<III', commands, offset + 8)
            if cryptid and not result.encrypted:
                result.encrypted = True
                result.cryptoff, result.cryptsize, result.cryptid = cryptoff, cryptsize, cryptid
                result.cryptid_at = base + header_size + offset + 16
        offset += size
    return result


def inspect(stream):
    """[Slice] for a Mach-O read sequentially from stream (forward reads only, so zip members stay
    cheap), or None when it is not a Mach-O file."""
    head = stream.read(8)
    if len(head) < 8:
        return None
    magic_le, magic_be = struct.unpack('<I', head[:4])[0], struct.unpack('>I', head[:4])[0]
    if magic_le not in (MH_MAGIC, MH_MAGIC_64) and magic_be not in (FAT_MAGIC, FAT_MAGIC_64):
        return None
    f = _Forward(_Prefixed(head, stream))
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        return [_thin_slice(f)]
    count = struct.unpack('>I', head[4:])[0]
    if not 0 < count <= MAX_FAT_ARCHS:
        return None
    entry_size = 32 if magic_be == FAT_MAGIC_64 else 20
    f.read(8)
    table = f.read(count * entry_size)
    offsets = sorted(struct.unpack_from('>Q' if magic_be == FAT_MAGIC_64 else '>I', table, i * entry_size + 8)[0]
                     for i in range(count))
    slices = []
    for offset in offsets:
        f.skip_to(offset)
        slices.append(_thin_slice(f))
    return slices


class _Prefixed:
    """Stream with some already-read bytes put back in front."""

    def __init__(self, prefix, stream):
        self.prefix = prefix
        self.stream = stream

    def read(self, size):
        if self.prefix:
            data, self.prefix = self.prefix[:size], self.prefix[size:]
            if len(data) < size:
                data += self.stream.read(size - len(data))
            return data
        return self.stream.read(size)


class FileResult:
    __slots__ = ('name', 'slices', 'error')

    def __init__(self, name, slices=None, error=None):
        self.name = name
        self.slices = slices or []
        self.error = error

    @property
    def encrypted_archs(self):
        return [s.arch for s in self.slices if s.encrypted]

    @property
    def only_32bit_encrypted(self):
        """True when every encrypted slice is 32-bit and a decrypted 64-bit slice exists beside it."""
        encrypted = [s for s in self.slices if s.encrypted]
        return (bool(encrypted) and not any(s.is_64bit for s in encrypted)
                and any(s.is_64bit and not s.encrypted for s in self.slices))


class Result:
    def __init__(self, files):
        self.files = files  # every Mach-O found, in archive order

    @property
    def encrypted(self):
        """Files with at least one encrypted slice (or that could not be read)."""
        return [f for f in self.files if f.error or f.encrypted_archs]

    @property
    def main(self):
        """The app's own executable (Payload/X.app/X), None when the IPA has none."""
        return next((f for f in self.files if len(f.name.split('/')) == 3 and f.name.startswith('Payload/')), None)

    @property
    def type(self):
        """Name of the result in file names: partial ones list the architectures of the main executable that
        are decrypted."""
        status = self.status
        if status in (DECRYPTED, NO_MACHO):
            return status
        main = self.main
        return partial_type(s.arch for s in main.slices if not s.encrypted) if main else PARTIAL

    @property
    def status(self):
        if not self.files:
            return NO_MACHO
        bad = self.encrypted
        if not bad:
            return DECRYPTED
        if all(not f.error and f.only_32bit_encrypted for f in bad):
            return PARTIAL_32BIT
        return PARTIAL


def _is_file(info):
    # Many zip tools store only permission bits, so exclude directories and symlinks instead.
    mode = info.external_attr >> 16
    return not info.is_dir() and not stat.S_ISDIR(mode) and not stat.S_ISLNK(mode)


def verify_ipa(path):
    """Inspect every Mach-O in the IPA at path; raises OSError/zipfile.BadZipFile for unreadable IPAs."""
    files = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not _is_file(info) or info.file_size < 28:
                continue
            with archive.open(info) as member:
                try:
                    slices = inspect(member)
                except (ValueError, struct.error, zipfile.BadZipFile, EOFError) as error:
                    files.append(FileResult(info.filename, error=str(error)))
                    continue
            if slices is not None:
                files.append(FileResult(info.filename, slices))
    return Result(files)


def short_name(name):
    """Payload/X.app/PlugIns/Y.appex/Y -> PlugIns/Y.appex/Y (the part inside the app bundle)."""
    parts = name.split('/')
    if len(parts) > 2 and parts[0] == 'Payload' and parts[1].endswith('.app'):
        return '/'.join(parts[2:])
    return name


def reason(file_result):
    """Why a file is probably still encrypted, as a key: unreadable, slice32, watch, appex,
    framework, main or other."""
    if file_result.error:
        return 'unreadable'
    encrypted = [s for s in file_result.slices if s.encrypted]
    if encrypted and not any(s.is_64bit for s in encrypted):
        return 'slice32'  # 64-bit devices only ever run (and so decrypt) the arm64 slice
    inner = short_name(file_result.name)
    if inner.startswith('Watch/'):
        return 'watch'
    if '.appex/' in inner:
        return 'appex'  # runs in its own process, which frida-ios-dump does not attach to
    if '.framework/' in inner or inner.endswith('.dylib'):
        return 'framework'  # the app had not loaded it when it was dumped
    if '/' not in inner:
        return 'main'
    return 'other'


def describe(file_result):
    if file_result.error:
        return '{} ({})'.format(short_name(file_result.name), file_result.error)
    return '{} ({})'.format(short_name(file_result.name), ', '.join(file_result.encrypted_archs))


def main(paths):
    worst = 0
    for path in paths:
        try:
            result = verify_ipa(path)
        except (OSError, zipfile.BadZipFile) as error:
            print('error\t{}\t{}'.format(path, error))
            worst = 2
            continue
        print('{}\t{}\t{} Mach-O'.format(result.status, path, len(result.files)))
        for file_result in result.encrypted:
            print('\tencrypted: ' + describe(file_result))
        if result.status != DECRYPTED:
            worst = max(worst, 1)
    return worst


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.exit(main(sys.argv[1:]))
