# -*- coding: utf-8 -*-
"""Builders and fixtures shared by several test files: Mach-O and IPA files, and the skip for a missing PySide6."""

import os
import struct
import tempfile
import unittest
from pathlib import Path

import app_info


ROOT = Path(__file__).resolve().parent.parent

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')       # the window tests draw into memory: no window appears

try:
    import PySide6
except ImportError:
    PySide6 = None

needs_window = unittest.skipIf(PySide6 is None, 'PySide6 is not installed (the window needs it, the command line does not)')


def code_directory(identifier, team):
    header_size = 52
    ident_offset = header_size
    team_offset = ident_offset + len(identifier) + 1
    body = identifier.encode() + b'\0' + team.encode() + b'\0'
    # magic, length, version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots,
    # codeLimit, hashSize, hashType, platform, pageSize, spare2, scatterOffset, teamOffset
    header = struct.pack('>IIIIIIIIIBBBBIII', app_info.CSMAGIC_CODEDIRECTORY, header_size + len(body),
                         0x20200, 0, 0, ident_offset, 0, 0, 0, 0, 0, 0, 0, 0, 0, team_offset)
    return header + body


def superblob(directory):
    offset = 12 + 8
    return struct.pack('>IIIII', app_info.CSMAGIC_EMBEDDED_SIGNATURE, offset + len(directory), 1,
                       app_info.CSSLOT_CODEDIRECTORY, offset) + directory


def macho(cryptid, signature):
    encryption = struct.pack('<IIIIII', app_info.LC_ENCRYPTION_INFO_64, 24, 0, 0, cryptid, 0)
    commands_size = len(encryption) + 16
    header = struct.pack('<IiiIIIII', 0xFEEDFACF, 0x0100000C, 0, 2, 2, commands_size, 0, 0)
    data_offset = len(header) + commands_size
    code_signature = struct.pack('<IIII', app_info.LC_CODE_SIGNATURE, 16, data_offset, len(signature))
    return header + encryption + code_signature + signature


def thin_macho(cpu, subtype, cryptid, is64=True):
    """Minimal Mach-O with one LC_ENCRYPTION_INFO(_64) and some code after the load commands."""
    if is64:
        command = struct.pack('<IIIIII', 0x2C, 24, 0x100, 0x40, cryptid, 0)
        header = struct.pack('<IiiIIIII', 0xFEEDFACF, cpu, subtype, 2, 1, len(command), 0, 0)
    else:
        command = struct.pack('<IIIII', 0x21, 20, 0x100, 0x40, cryptid)
        header = struct.pack('<IiiIIII', 0xFEEDFACE, cpu, subtype, 2, 1, len(command), 0)
    return header + command + b'\xAA' * 300


def fat_macho(*slices):
    """Fat binary; slices are placed at 0x4000-aligned offsets like real ones."""
    table = struct.pack('>II', 0xCAFEBABE, len(slices))
    body = b''
    offset = 0x4000
    entries = []
    for cpu, subtype, data in slices:
        entries.append(struct.pack('>iiIII', cpu, subtype, offset, len(data), 14))
        body += data.ljust(0x4000, b'\0')
        offset += 0x4000
    return (table + b''.join(entries)).ljust(0x4000, b'\0') + body


class IpaMixin:
    ARM64 = (app_info.CPU_TYPE_ARM64, 0)
    ARMV7 = (app_info.CPU_TYPE_ARM, 9)

    def ipa(self, files):
        import zipfile
        handle = tempfile.NamedTemporaryFile(suffix='.ipa', delete=False)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        with zipfile.ZipFile(handle.name, 'w', zipfile.ZIP_DEFLATED) as archive:
            if 'Info.plist' not in files:
                archive.writestr('Payload/X.app/Info.plist', b'<plist/>' * 10)
            archive.writestr('Payload/X.app/icon.png', b'\x89PNG' + b'\0' * 100)
            archive.writestr('Payload/X.app/Java.class', struct.pack('>II', 0xCAFEBABE, 0x34) + b'\0' * 40)
            for name, data in files.items():
                archive.writestr('Payload/X.app/' + name, data)
        return handle.name

    def verify(self, files):
        import ipa_verify
        return ipa_verify.verify_ipa(self.ipa(files))
