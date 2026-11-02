import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import app_info

ROOT = Path(__file__).resolve().parent.parent


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


class AppInfoTests(unittest.TestCase):
    def test_reads_encryption_and_team(self):
        binary = macho(1, superblob(code_directory('com.example.app', 'ABCDE12345')))
        info = app_info.inspect_macho(io.BytesIO(binary))
        self.assertEqual(info['encrypted'], True)
        self.assertEqual(info['identifier'], 'com.example.app')
        self.assertEqual(info['team_id'], 'ABCDE12345')

    def test_selects_arm64_slice_of_fat_binary(self):
        thin = macho(0, superblob(code_directory('com.example.app', 'TEAM')))
        offset = 0x1000
        fat = struct.pack('>II', 0xCAFEBABE, 2)
        fat += struct.pack('>iiIII', 12, 9, offset + len(thin), 4, 14)  # armv7 (bogus offset)
        fat += struct.pack('>iiIII', app_info.CPU_TYPE_ARM64, 0, offset, len(thin), 14)
        data = fat.ljust(offset, b'\0') + thin
        info = app_info.inspect_macho(io.BytesIO(data))
        self.assertEqual(info['encrypted'], False)
        self.assertEqual(info['team_id'], 'TEAM')
        self.assertEqual(info['archs'], ['armv7', 'arm64'])
        self.assertEqual(app_info.arch_bits(info['archs']), 0)

    def test_architectures(self):
        self.assertEqual(app_info.arch_name(app_info.CPU_TYPE_ARM64, -0x7FFFFFFE), 'arm64e')  # capability bit set
        self.assertEqual(app_info.arch_bits(['armv7', 'armv7s']), 32)
        self.assertEqual(app_info.arch_bits(['arm64', 'arm64e']), 64)
        self.assertEqual(app_info.arch_bits(['arm64_32']), 32)

    def test_default_names_are_windows_safe(self):
        name = app_info.format_ipa_name(app_info.DEFAULT_DECRYPTED_NAME, 'A:B/C?', 'com.x', '1.0')
        self.assertEqual(name, 'A_B_C__com.x_1.0_decrypted')
        self.assertEqual(app_info.format_ipa_name(app_info.DEFAULT_DECRYPTED_NAME, 'App', 'com.x', ''),
                         'App_com.x_unknown_decrypted')

    def test_name_templates(self):
        name = app_info.format_ipa_name('{bundle}-{version} ({build}) {type}', 'A/B', 'com.x', '1.0', '7', 'encrypted')
        self.assertEqual(name, 'com.x-1.0 (7) encrypted')
        self.assertEqual(app_info.format_ipa_name(app_info.DEFAULT_ORIGINAL_NAME, 'A/B', 'com.x', '1.0', kind='original'),
                         'A_B_com.x_1.0_original')
        for template, key in (('{foo}', 'name_unknown'), ('{name', 'name_braces'), ('  ', 'name_empty'),
                              ('{name.upper}', 'name_unknown'), ('{name:d}', 'name_braces'),
                              ('{name!x}', 'name_braces'), ('{name:{bundle}}', 'name_braces')):
            with self.assertRaises(app_info.NameTemplateError) as caught:
                app_info.check_name_template(template)
            self.assertEqual(caught.exception.args[0], key, template)


class DumpDirTests(unittest.TestCase):
    def test_status(self):
        import ipa_extractor
        with tempfile.TemporaryDirectory() as path:
            self.assertEqual(ipa_extractor.dump_dir_status(''), 'empty')
            self.assertEqual(ipa_extractor.dump_dir_status(os.path.join(path, 'missing')), 'missing')
            for name in ('dump.py', 'dump.js'):
                open(os.path.join(path, name), 'w').close()
            self.assertEqual(ipa_extractor.dump_dir_status(path), 'no_bridge')
            os.makedirs(os.path.join(path, 'node_modules', 'frida-objc-bridge'))
            self.assertEqual(ipa_extractor.dump_dir_status(path), 'ok')


class FridaVersionTests(unittest.TestCase):
    def test_pick_prefers_exact_then_newest_of_same_major(self):
        import frida_versions
        versions = ['17.24.3', '17.5.1', '16.6.6', '16.1.0']
        self.assertEqual(frida_versions.pick('17.24.3', versions), '17.24.3')
        self.assertEqual(frida_versions.pick('17.30.0', versions), '17.24.3')
        self.assertEqual(frida_versions.pick('16.7.0', versions), '16.6.6')
        self.assertIsNone(frida_versions.pick('15.2.2', versions))
        self.assertIsNone(frida_versions.pick(None, versions))

    def test_only_complete_installs_are_listed(self):
        import frida_versions
        with tempfile.TemporaryDirectory() as root:
            for name in ('16.6.6', '17.24.3', '17.5.1', '17.9.9.partial', 'notes'):
                os.makedirs(os.path.join(root, name))
            for name in ('16.6.6', '17.24.3', '17.5.1'):
                open(os.path.join(root, name, frida_versions.COMPLETE), 'w').close()
            os.makedirs(os.path.join(root, '18.0.0'))  # pip never finished
            self.assertEqual(frida_versions.installed(root), ['17.24.3', '17.5.1', '16.6.6'])
            frida_versions.remove('17.5.1', root)
            self.assertEqual(frida_versions.installed(root), ['17.24.3', '16.6.6'])

    def test_finish_install_replaces_previous_copy(self):
        import frida_versions
        with tempfile.TemporaryDirectory() as root:
            frida_versions.prepare_install('17.24.3', root)
            open(os.path.join(frida_versions.staging('17.24.3', root), 'new'), 'w').close()
            os.makedirs(os.path.join(root, '17.24.3'))
            open(os.path.join(root, '17.24.3', 'old'), 'w').close()
            frida_versions.finish_install('17.24.3', root)
            self.assertEqual(sorted(os.listdir(os.path.join(root, '17.24.3'))), [frida_versions.COMPLETE, 'new'])
            self.assertFalse(os.path.exists(frida_versions.staging('17.24.3', root)))

    def test_env_puts_version_folder_first(self):
        import frida_versions
        env = frida_versions.env('17.24.3', {'PYTHONPATH': 'elsewhere'}, root='versions')
        self.assertEqual(env['PYTHONPATH'].split(os.pathsep),
                         [os.path.join('versions', '17.24.3'), 'elsewhere'])
        self.assertEqual(frida_versions.env('16.6.6', {}, root='v')['PYTHONPATH'], os.path.join('v', '16.6.6'))

    def test_gui_does_not_import_frida(self):
        code = 'import sys, ipa_extractor; print("frida" in sys.modules)'
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        self.assertEqual(output.strip(), 'False')


def thin_macho(cpu, subtype, cryptid, is64=True):
    """Minimal Mach-O with one LC_ENCRYPTION_INFO(_64) and some code after the load commands."""
    if is64:
        command = struct.pack('<IIIIII', 0x2C, 24, 0x4000, 0x1000, cryptid, 0)
        header = struct.pack('<IiiIIIII', 0xFEEDFACF, cpu, subtype, 2, 1, len(command), 0, 0)
    else:
        command = struct.pack('<IIIII', 0x21, 20, 0x4000, 0x1000, cryptid)
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


class VerifyTests(unittest.TestCase):
    ARM64 = (app_info.CPU_TYPE_ARM64, 0)
    ARMV7 = (app_info.CPU_TYPE_ARM, 9)

    def ipa(self, files):
        import zipfile
        handle = tempfile.NamedTemporaryFile(suffix='.ipa', delete=False)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        with zipfile.ZipFile(handle.name, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('Payload/X.app/Info.plist', b'<plist/>' * 10)
            archive.writestr('Payload/X.app/icon.png', b'\x89PNG' + b'\0' * 100)
            archive.writestr('Payload/X.app/Java.class', struct.pack('>II', 0xCAFEBABE, 0x34) + b'\0' * 40)
            for name, data in files.items():
                archive.writestr('Payload/X.app/' + name, data)
        return handle.name

    def verify(self, files):
        import ipa_verify
        return ipa_verify.verify_ipa(self.ipa(files))

    def test_fully_decrypted(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0),
                              'Frameworks/F.framework/F': thin_macho(*self.ARM64, 0)})
        self.assertEqual(result.status, ipa_verify.DECRYPTED)
        self.assertEqual(len(result.files), 2)  # the PNG, plist and Java class file are not Mach-O

    def test_encrypted_extension_is_partial(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0),
                              'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1)})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertEqual([ipa_verify.describe(f) for f in result.encrypted], ['PlugIns/E.appex/E (arm64)'])

    def test_every_fat_slice_is_checked(self):
        import ipa_verify
        only_32bit = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                               self.ARM64 + (thin_macho(*self.ARM64, 0),))
        self.assertEqual(self.verify({'X': only_32bit}).status, ipa_verify.PARTIAL_32BIT)
        arm64_encrypted = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 0, is64=False),),
                                    self.ARM64 + (thin_macho(*self.ARM64, 1),))
        result = self.verify({'X': arm64_encrypted})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertEqual(result.encrypted[0].encrypted_archs, ['arm64'])

    def test_32bit_only_binary_is_not_partial_64bit(self):
        import ipa_verify
        # Without a decrypted arm64 slice beside it, nothing in the file runs on 64-bit devices.
        result = self.verify({'X': thin_macho(*self.ARMV7, 1, is64=False)})
        self.assertEqual(result.status, ipa_verify.PARTIAL)

    def test_truncated_macho_counts_as_not_verified(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0)[:40]})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertTrue(result.files[0].error)


class ErrorClassificationTests(unittest.TestCase):
    def test_known_errors(self):
        import ipa_extractor
        cases = {
            'frida.NotSupportedError: unable to launch iOS app via FBS: '
            'The operation couldn’t be completed. Application failed preflight checks': 'preflight',
            'frida.TransportError: timeout was reached': 'timeout',
            'frida.TransportError: the connection is closed': 'closed',
            'frida.InvalidOperationError: session is gone': 'session',
            'frida.NotSupportedError: unexpected error while resuming process: (os/kern) failure': 'resume',
            'frida.ServerNotRunningError: unable to connect to remote frida-server': 'server',
            "FileNotFoundError: [Errno 2] No such file or directory: 'Payload'": 'path',
            'something else': None,
        }
        for message, kind in cases.items():
            self.assertEqual(ipa_extractor.classify_error(message), kind, message)


class WorkerTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'Windows only')
    @unittest.skipUnless(importlib.util.find_spec('scp'), 'scp is installed by Install Frida dependencies')
    def test_long_paths_keep_scp_directory_target(self):
        code = ('import dump_worker, tempfile, scp\n'
                'dump_worker.use_long_paths()\n'
                'seen = []\n'
                'scp.SCPClient.__bases__[0].get = lambda self, r, l="", *a, **k: seen.append(l)\n'
                'client = scp.SCPClient.__new__(scp.SCPClient)\n'
                'client.get("x", tempfile.gettempdir() + "\\\\Payload/")\n'
                'print(tempfile.gettempdir().startswith(dump_worker.EXTENDED_PREFIX), seen[0].endswith("Payload"))\n')
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        self.assertEqual(output.split(), ['True', 'True'])

    def test_reports_progress_as_json_lines(self):
        code = ('import dump_worker, sys, types\n'
                'bar = dump_worker.ProgressBar(total=10)\n'
                'bar.set_description_str("App resources")\n'
                'bar.update(10)\n'
                'bar.close()\n'
                'dump_worker.ProgressBar.write("hello")\n')
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        events = [json.loads(line[2:]) for line in output.splitlines() if line.startswith('@@')]
        self.assertEqual(events[-2]['n'], 10)
        self.assertTrue(events[-2]['closed'])
        self.assertEqual(events[-1], {'type': 'log', 'text': 'hello'})


class LocaleTests(unittest.TestCase):
    def test_every_language_matches_english(self):
        import string
        import i18n
        locales = i18n.load_locales()
        english = locales[i18n.FALLBACK]

        def fields(text):
            return {field for _, field, _, _ in string.Formatter().parse(text) if field}

        for code, strings in locales.items():
            self.assertIn('_name', strings, code)
            self.assertEqual(set(strings) - set(english), set(), code)  # no stray keys
            for key, text in strings.items():
                if not key.startswith('_'):
                    self.assertEqual(fields(text), fields(english[key]), '{} {}'.format(code, key))

    def test_language_matching(self):
        import i18n
        locales = i18n.load_locales()
        self.assertEqual(i18n.resolve(locales, 'xx'), i18n.FALLBACK)
        self.assertEqual(i18n.match_language(locales, 'zh-Hant-HK'), 'zh-TW')
        self.assertEqual(i18n.match_language(locales, 'zh-Hans-CN'), 'zh-CN')
        self.assertEqual(i18n.match_language(locales, 'ja-JP'), 'ja')
        self.assertEqual(i18n.match_language({'pt-BR': {}, 'en': {}}, 'pt-PT'), 'pt-BR')
        self.assertIsNone(i18n.match_language({'en': {}}, 'pt-PT'))


class DisplayNameTests(unittest.TestCase):
    def test_parse_strings(self):
        import device_apps
        text = '/* comment */\n"CFBundleDisplayName" = "A \\"B\\"";\nCFBundleName = "\\U00e9";\n'
        self.assertEqual(device_apps.parse_strings(text.encode()),
                         {'CFBundleDisplayName': 'A "B"', 'CFBundleName': '\u00e9'})
        self.assertEqual(device_apps.parse_strings('"CFBundleName" = "\u540d";'.encode('utf-16')),
                         {'CFBundleName': '\u540d'})
        self.assertEqual(device_apps.parse_strings(b'\xff\xfe\x00\xd8'), {})  # broken UTF-16

    def test_lproj_candidates(self):
        import device_apps
        self.assertEqual(device_apps.lproj_candidates('zh-Hant-TW')[:3], ['zh-Hant-TW', 'zh-Hant', 'zh_TW'])
        self.assertIn('Japanese', device_apps.lproj_candidates('ja-JP'))


class FakeSSH:
    """Just enough of paramiko's SSHClient, Transport and Channel for ipa_extract."""

    def __init__(self, tar_data):
        self.stream = io.BytesIO(tar_data)
        self.channel = self

    def get_transport(self):
        return self

    def open_session(self, timeout=None):
        return self

    def exec_command(self, command, timeout=None):
        if 'tar ' in command:
            return None, self, io.BytesIO()
        return None

    def settimeout(self, timeout):
        pass

    def set_combine_stderr(self, combine):
        pass

    def makefile(self, mode):
        return io.BytesIO(b'iTunesMetadata.plist\n12\tX.app\n')  # ls and du output

    def read(self, size=-1):
        return self.stream.read(size)

    def recv_exit_status(self):
        return 0

    def close(self):
        pass


class ExtractTests(unittest.TestCase):
    @staticmethod
    def tar(extra=None):
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            for name, data in (('X.app/Info.plist', b'plist'), ('X.app/X', b'exe'), ('iTunesMetadata.plist', b'meta')):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo('X.app/Current')
            link.type, link.linkname = tarfile.SYMTYPE, 'X'
            tar.addfile(link)
            if extra is not None:
                tar.addfile(extra)
        return buffer.getvalue()

    def test_streams_bundle_into_ipa(self):
        import ipa_extract
        import zipfile
        with tempfile.TemporaryDirectory() as folder:
            dest = os.path.join(folder, 'x.ipa')
            ipa_extract.extract_ipa(FakeSSH(self.tar()), '/var/containers/Bundle/Application/U/X.app', dest)
            with zipfile.ZipFile(dest) as ipa:
                self.assertEqual(ipa.read('Payload/X.app/X'), b'exe')
                self.assertEqual(ipa.read('iTunesMetadata.plist'), b'meta')
                self.assertEqual(ipa.read('Payload/X.app/Current'), b'X')  # symlink target
                self.assertEqual(ipa.getinfo('Payload/X.app/X').external_attr >> 16 & 0o777, 0o755)
            self.assertEqual(os.listdir(folder), ['x.ipa'])

    def test_hard_links_are_not_dropped_silently(self):
        import ipa_extract
        import tarfile
        link = tarfile.TarInfo('X.app/Copy')
        link.type, link.linkname = tarfile.LNKTYPE, 'X.app/X'
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError):
                ipa_extract.extract_ipa(FakeSSH(self.tar(link)), '/c/U/X.app', os.path.join(folder, 'x.ipa'))
            self.assertEqual(os.listdir(folder), [])  # no partial IPA left behind


if __name__ == '__main__':
    unittest.main()
