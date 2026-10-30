# -*- coding: utf-8 -*-
"""Read app metadata (Info.plist, encryption, code signature) over SFTP."""

import plistlib
import posixpath
import re
import string
import struct
import warnings

LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM64_32 = 0x0200000C
ARM_SUBTYPES = {5: 'armv4t', 6: 'armv6', 7: 'armv5', 9: 'armv7', 10: 'armv7f', 11: 'armv7s', 12: 'armv7k'}

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSSLOT_CODEDIRECTORY = 0
CSSLOT_SIGNATURESLOT = 0x10000

INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_filename(name):
    """Make a Windows-safe file name component."""
    name = INVALID_FILENAME_CHARS.sub('_', name).strip().rstrip('.')
    return name or 'app'


NAME_FIELDS = ('name', 'bundle', 'version', 'build', 'type')
DEFAULT_DECRYPTED_NAME = '{name}_{bundle}_{version}_{type}'
DEFAULT_ORIGINAL_NAME = '{name}_{bundle}_{version}_{type}'


class NameTemplateError(ValueError):
    """Invalid file name template; args are (string key, params) for the UI to translate."""


def check_name_template(template):
    if not template.strip():
        raise NameTemplateError('name_empty', {})
    try:
        fields = [field for _, field, _, _ in string.Formatter().parse(template) if field is not None]
    except ValueError:
        raise NameTemplateError('name_braces', {})
    for field in fields:
        if field not in NAME_FIELDS:
            raise NameTemplateError('name_unknown', {'field': field})
    try:
        # Format specs and conversions such as {name:d} or {name!x} pass the checks above.
        template.format(**{field: 'x' for field in NAME_FIELDS})
    except (ValueError, KeyError, IndexError):
        raise NameTemplateError('name_braces', {})


def format_ipa_name(template, name, bundle_id, version, build='', kind='decrypted'):
    """Build a Windows-safe IPA base name (without .ipa) from a template such as DEFAULT_DECRYPTED_NAME."""
    check_name_template(template)
    return safe_filename(template.format(name=name, bundle=bundle_id, version=version or 'unknown',
                                         build=build or 'unknown', type=kind))


def _c_string(data, offset):
    end = data.find(b'\0', offset)
    return data[offset:end if end >= 0 else len(data)].decode('utf-8', 'replace')


def arch_name(cpu, subtype):
    subtype &= 0xFFFFFF  # drop capability bits
    if cpu == CPU_TYPE_ARM64:
        return 'arm64e' if subtype == 2 else 'arm64'
    if cpu == CPU_TYPE_ARM64_32:
        return 'arm64_32'
    if cpu == CPU_TYPE_ARM:
        return ARM_SUBTYPES.get(subtype, 'arm')
    return 'cpu{}'.format(cpu)


def arch_bits(archs):
    """32, 64, or 0 when the executable has both 32- and 64-bit slices."""
    bits = {64 if name.startswith('arm64') and name != 'arm64_32' else 32 for name in archs}
    return bits.pop() if len(bits) == 1 else 0


def _thin_offset(f):
    """Return (arm64 slice offset, architecture names) of a (possibly fat) Mach-O file."""
    f.seek(0)
    header = f.read(12)
    magic = struct.unpack('>I', header[:4])[0]
    if magic not in (0xCAFEBABE, 0xCAFEBABF):
        cpu, subtype = struct.unpack_from('<ii', header, 4)
        return 0, [arch_name(cpu, subtype)]
    count = struct.unpack('>I', header[4:8])[0]
    if count > 32:
        raise ValueError('not a Mach-O file')  # 0xCAFEBABE also starts Java class files
    f.seek(8)
    entry_size = 32 if magic == 0xCAFEBABF else 20
    table = f.read(count * entry_size)
    slices = []
    for i in range(count):
        entry = table[i * entry_size:(i + 1) * entry_size]
        if magic == 0xCAFEBABF:
            cpu, subtype, offset = struct.unpack('>iiQ', entry[:16])
        else:
            cpu, subtype, offset = struct.unpack('>iiI', entry[:12])
        slices.append((cpu, subtype, offset))
    if not slices:
        raise ValueError('empty fat binary')
    archs = [arch_name(cpu, subtype) for cpu, subtype, _ in slices]
    return next((offset for cpu, _, offset in slices if cpu == CPU_TYPE_ARM64), slices[0][2]), archs


def parse_code_signature(blob):
    """Return (identifier, team_id, signer_cn) from an embedded signature SuperBlob."""
    identifier = team_id = signer = ''
    magic, _, count = struct.unpack_from('>III', blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return identifier, team_id, signer
    for i in range(count):
        slot, offset = struct.unpack_from('>II', blob, 12 + i * 8)
        blob_magic, length = struct.unpack_from('>II', blob, offset)
        if slot == CSSLOT_CODEDIRECTORY and blob_magic == CSMAGIC_CODEDIRECTORY:
            directory = blob[offset:offset + length]
            version = struct.unpack_from('>I', directory, 8)[0]
            identifier = _c_string(directory, struct.unpack_from('>I', directory, 20)[0])
            if version >= 0x20200:
                team_offset = struct.unpack_from('>I', directory, 48)[0]
                if team_offset:
                    team_id = _c_string(directory, team_offset)
        elif slot == CSSLOT_SIGNATURESLOT and blob_magic == CSMAGIC_BLOBWRAPPER and length > 8:
            signer = cms_signer(blob[offset + 8:offset + length])
    return identifier, team_id, signer


def cms_signer(der):
    """Common name of the leaf certificate in a DER PKCS#7 blob."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        from cryptography.x509.oid import NameOID
        # Apple signatures are BER encoded; the DER fallback warning is expected.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            certificates = pkcs7.load_der_pkcs7_certificates(der)
    except Exception:
        return ''
    issuers = {cert.issuer for cert in certificates}
    leaves = [cert for cert in certificates if cert.subject not in issuers] or certificates
    if not leaves:
        return ''
    names = leaves[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return names[0].value if names else leaves[0].subject.rfc4514_string()


def inspect_macho(f):
    """Return dict(encrypted, identifier, team_id, signer, archs) for an open Mach-O file."""
    base, archs = _thin_offset(f)
    f.seek(base)
    header = f.read(32)
    magic = struct.unpack('<I', header[:4])[0]
    if magic == 0xFEEDFACF:
        header_size = 32
    elif magic == 0xFEEDFACE:
        header_size = 28
    else:
        raise ValueError('not a Mach-O file')
    ncmds, sizeofcmds = struct.unpack_from('<II', header, 16)
    f.seek(base + header_size)
    commands = f.read(sizeofcmds)
    result = dict(encrypted=False, identifier='', team_id='', signer='', archs=archs)
    signature = None
    offset = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', commands, offset)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            result['encrypted'] = struct.unpack_from('<I', commands, offset + 16)[0] != 0
        elif cmd == LC_CODE_SIGNATURE:
            signature = struct.unpack_from('<II', commands, offset + 8)
        offset += size
    if signature:
        f.seek(base + signature[0])
        identifier, team_id, signer = parse_code_signature(f.read(signature[1]))
        result.update(identifier=identifier, team_id=team_id, signer=signer)
    return result


def _read_plist(sftp, path):
    with sftp.open(path, 'rb') as f:
        return plistlib.loads(f.read())


def provision_info(data):
    """Extract TeamName / Name from an embedded.mobileprovision CMS blob."""
    start = data.find(b'<?xml')
    end = data.find(b'</plist>')
    if start < 0 or end < 0:
        return {}
    try:
        return plistlib.loads(data[start:end + len(b'</plist>')])
    except Exception:
        return {}


def read_app_info(sftp, app_path):
    """Collect signing and bundle details for an installed .app directory.

    A part that cannot be read leaves the others in place; the executable's error is kept in 'error'.
    """
    plist = _read_plist(sftp, posixpath.join(app_path, 'Info.plist'))
    executable = plist.get('CFBundleExecutable', '')
    info = dict(executable=executable, min_os=plist.get('MinimumOSVersion', ''))
    if executable:
        try:
            with sftp.open(posixpath.join(app_path, executable), 'rb') as f:
                info.update(inspect_macho(f))
        except Exception as error:
            info['error'] = str(error)
    try:
        with sftp.open(posixpath.join(app_path, 'embedded.mobileprovision'), 'rb') as f:
            profile = provision_info(f.read())
        info['profile'] = profile.get('Name', '')
        info['profile_team'] = profile.get('TeamName', '')
    except Exception:  # only developer, ad hoc and enterprise builds have one
        pass
    try:
        metadata = _read_plist(sftp, posixpath.join(posixpath.dirname(app_path), 'iTunesMetadata.plist'))
        info['developer'] = metadata.get('artistName', '')
    except Exception:  # only App Store installs have one
        pass
    return info
