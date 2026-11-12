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
try:
    import tkinter
except ImportError:
    tkinter = None
needs_window = unittest.skipIf(tkinter is None, 'tkinter is not installed (the window needs it, the command line does not)')


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
        import engine
        with tempfile.TemporaryDirectory() as path:
            self.assertEqual(engine.dump_dir_status(''), 'empty')
            self.assertEqual(engine.dump_dir_status(os.path.join(path, 'missing')), 'missing')
            for name in ('dump.py', 'dump.js'):
                open(os.path.join(path, name), 'w').close()
            self.assertEqual(engine.dump_dir_status(path), 'no_bridge')
            os.makedirs(os.path.join(path, 'node_modules', 'frida-objc-bridge'))
            self.assertEqual(engine.dump_dir_status(path), 'ok')


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

    @needs_window
    def test_gui_does_not_import_frida(self):
        code = 'import sys, ipa_extractor; print("frida" in sys.modules)'
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        self.assertEqual(output.strip(), 'False')


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


class VerifyTests(IpaMixin, unittest.TestCase):

    def test_fully_decrypted(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0),
                              'Frameworks/F.framework/F': thin_macho(*self.ARM64, 0)})
        self.assertEqual(result.status, ipa_verify.DECRYPTED)
        self.assertEqual(len(result.files), 2)  # the PNG, plist and Java class file are not Mach-O

    def test_partial_type_lists_decrypted_archs(self):
        import ipa_verify
        fat = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 0, is64=False),),
                        self.ARM64 + (thin_macho(*self.ARM64, 1),))
        result = self.verify({'X': fat})
        self.assertEqual(result.type, 'partial-decrypted-armv7')
        self.assertIn('partial-decrypted-armv6-armv7', ipa_verify.all_types())
        self.assertEqual(ipa_verify.partial_type([]), ipa_verify.PARTIAL)

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

    def test_reasons(self):
        import ipa_verify
        fat_32 = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                           self.ARM64 + (thin_macho(*self.ARM64, 0),))
        result = self.verify({'X': thin_macho(*self.ARM64, 1),
                              'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                              'Watch/W.app/PlugIns/WE.appex/WE': thin_macho(*self.ARM64, 1),
                              'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                              'Frameworks/libz.dylib': thin_macho(*self.ARM64, 1),
                              'Frameworks/G.framework/G': fat_32,
                              'Data/plugin.bin': thin_macho(*self.ARM64, 1),
                              'Broken': thin_macho(*self.ARM64, 0)[:40]})
        reasons = {ipa_verify.short_name(f.name): ipa_verify.reason(f) for f in result.encrypted}
        self.assertEqual(reasons, {'X': 'main', 'PlugIns/E.appex/E': 'appex',
                                   'Watch/W.app/PlugIns/WE.appex/WE': 'watch',
                                   'Frameworks/F.framework/F': 'framework', 'Frameworks/libz.dylib': 'framework',
                                   'Frameworks/G.framework/G': 'slice32', 'Data/plugin.bin': 'other',
                                   'Broken': 'unreadable'})

    def test_truncated_macho_counts_as_not_verified(self):
        import ipa_verify
        result = self.verify({'X': thin_macho(*self.ARM64, 0)[:40]})
        self.assertEqual(result.status, ipa_verify.PARTIAL)
        self.assertTrue(result.files[0].error)


class RepairTests(IpaMixin, unittest.TestCase):
    def test_patches_decrypted_slices_into_ipa(self):
        import ipa_repair
        import ipa_verify
        import zipfile
        fat = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                        self.ARM64 + (thin_macho(*self.ARM64, 1),))
        path = self.ipa({'X': thin_macho(*self.ARM64, 0), 'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                         'PlugIns/F.appex/F': fat})
        with zipfile.ZipFile(path) as archive:
            before = {i.filename: (archive.read(i), i.external_attr, i.date_time) for i in archive.infolist()}
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/var/containers/Bundle/Application/U/X.app')
        self.assertEqual([j.device_path for j in jobs], ['/var/containers/Bundle/Application/U/X.app/PlugIns/E.appex/E',
                                                         '/var/containers/Bundle/Application/U/X.app/PlugIns/F.appex/F'])
        with tempfile.TemporaryDirectory() as work:
            for job in jobs:
                for index, slice_ in enumerate(job.slices):
                    if job.id == '1' and slice_.arch == 'armv7':
                        continue  # this slice failed on the device
                    with open(os.path.join(work, '{}_{}.bin'.format(job.id, index)), 'wb') as handle:
                        handle.write(b'\x1f\x20\x03\xd5' * (slice_.cryptsize // 4))  # nop
                    job.done.add(index)
            self.assertEqual(ipa_repair.apply(path, jobs, work), 2)
        result = ipa_verify.verify_ipa(path)
        self.assertEqual(result.status, ipa_verify.PARTIAL_32BIT)  # only F's armv7 slice is left
        with zipfile.ZipFile(path) as archive:
            after = {i.filename: (archive.read(i), i.external_attr, i.date_time) for i in archive.infolist()}
        self.assertEqual(list(after), list(before))
        for name in ('Payload/X.app/X', 'Payload/X.app/Info.plist', 'Payload/X.app/icon.png'):
            self.assertEqual(after[name], before[name])
        patched = after['Payload/X.app/PlugIns/E.appex/E'][0]
        self.assertEqual(len(patched), len(before['Payload/X.app/PlugIns/E.appex/E'][0]))
        self.assertEqual(patched[0x100:0x104], b'\x1f\x20\x03\xd5')

    def test_plan_knows_executables_and_extension_ids(self):
        import ipa_repair
        import ipa_verify
        import plistlib
        plist = lambda executable, identifier: plistlib.dumps(
            {'CFBundleExecutable': executable, 'CFBundleIdentifier': identifier})
        path = self.ipa({'X': thin_macho(*self.ARM64, 1),
                         'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                         'PlugIns/E.appex/Info.plist': plist('E', 'com.example.app.share'),
                         'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                         'Watch/W.app/W': thin_macho(*self.ARM64, 1),
                         'Data/plugin.bin': thin_macho(*self.ARM64, 1),
                         'Info.plist': plist('X', 'com.example.app')})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/var/containers/Bundle/Application/U/X.app', path)
        found = {ipa_verify.short_name(j.member): (j.kind, j.extension) for j in jobs}
        self.assertEqual(found, {'X': ('main', None), 'PlugIns/E.appex/E': ('appex', 'com.example.app.share'),
                                 'Frameworks/F.framework/F': ('framework', None), 'Watch/W.app/W': ('watch', None),
                                 'Data/plugin.bin': ('other', None)})
        self.assertEqual(jobs[1].to_json()['suffix'], '/X.app/PlugIns/E.appex/E')

    def test_size_mismatch_is_not_repaired(self):
        import ipa_repair
        import ipa_verify
        path = self.ipa({'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1)})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/app/X.app')

        class FakeSFTP:
            def stat(self, path):
                return type('Stat', (), {'st_size': 1})()

        ipa_repair.check_sizes(FakeSFTP(), jobs, path)
        self.assertEqual(jobs[0].error[0], 'mismatch')
        self.assertEqual(ipa_repair.apply(path, jobs, '.'), 0)


class ThemeTests(unittest.TestCase):
    def test_unknown_themes_fall_back_to_the_system_theme(self):
        import engine
        for name in ('system', 'light', 'dark', 'black'):
            self.assertEqual(engine.theme_setting(name), name)
        for bad in ('', 'pink', None, 3):
            self.assertEqual(engine.theme_setting(bad), 'system')
        self.assertEqual(engine.DEFAULTS['theme'], 'system')

    def test_the_system_theme_is_looked_up_and_defaults_to_light(self):
        import engine
        from unittest import mock
        for name in ('light', 'dark', 'black'):
            with mock.patch.object(engine, 'system_theme', side_effect=AssertionError):
                self.assertEqual(engine.resolve_theme(name), name)      # a fixed theme never asks the system
        with mock.patch.object(engine, 'system_theme', return_value='dark'):
            self.assertEqual(engine.resolve_theme('system'), 'dark')
            self.assertEqual(engine.resolve_theme('pink'), 'dark')      # unknown values mean "system"
        with mock.patch.object(engine, 'IS_WINDOWS', False), mock.patch.object(engine, 'IS_MACOS', False), \
                mock.patch.object(engine.shutil, 'which', return_value=None):
            self.assertEqual(engine.system_theme(), 'light')            # no way to tell
        with mock.patch.object(engine, 'IS_WINDOWS', False), mock.patch.object(engine, 'IS_MACOS', True), \
                mock.patch.object(engine.shutil, 'which', return_value='/usr/bin/defaults'), \
                mock.patch.object(engine.subprocess, 'run') as run:
            run.return_value.returncode, run.return_value.stdout = 0, 'Dark\n'
            self.assertEqual(engine.system_theme(), 'dark')
            run.return_value.returncode = 1                             # no AppleInterfaceStyle: light
            self.assertEqual(engine.system_theme(), 'light')

    @needs_window
    def test_every_theme_defines_every_colour_and_black_is_black(self):
        import ipa_extractor
        keys = set(ipa_extractor.PALETTES['light'])
        for name, palette in ipa_extractor.PALETTES.items():
            self.assertEqual(set(palette), keys, name)
            for value in palette.values():
                self.assertRegex(value, r'^#[0-9a-f]{6}$')
        self.assertEqual(ipa_extractor.PALETTES['black']['bg'], '#000000')
        self.assertEqual(ipa_extractor.PALETTES['black']['field'], '#000000')

    def test_every_language_names_the_themes(self):
        import i18n
        for code, strings in i18n.load_locales().items():
            for key in ('theme', 'theme_system', 'theme_light', 'theme_dark', 'theme_black'):
                self.assertTrue(strings.get(key), (code, key))
            self.assertEqual(len({strings['theme_system'], strings['theme_light'], strings['theme_dark'], strings['theme_black']}), 4, code)


class DecryptMethodTests(unittest.TestCase):
    def test_method_follows_ios_version(self):
        import engine
        self.assertEqual(engine.decrypt_method('iPhone OS 12.4'), 'mremap')
        self.assertEqual(engine.decrypt_method('iPhone OS 15.8.3'), 'mremap')
        self.assertEqual(engine.decrypt_method('iPhone OS 16.1.2'), 'memory')
        self.assertEqual(engine.decrypt_method('iPhone OS 17.0'), 'memory')
        self.assertEqual(engine.decrypt_method(None), 'mremap')

    def test_versions(self):
        import ipa_repair
        self.assertEqual(ipa_repair.version_tuple('iPhone OS 16.1.2'), (16, 1, 2))
        self.assertGreater(ipa_repair.version_tuple('17.0'), ipa_repair.version_tuple('iPhone OS 16.1.2'))
        self.assertLess(ipa_repair.version_tuple('16.1'), ipa_repair.version_tuple('16.1.2'))
        self.assertEqual(ipa_repair.version_tuple(''), ())

    def test_per_slice_copies_only_on_old_ios(self):
        import engine
        copies = lambda ios, method='mremap': engine.per_slice_copies(dict(ios=ios, method=method))
        self.assertTrue(copies('iOS 8.1.1'))
        self.assertFalse(copies('iPhone OS 12.4'))
        self.assertFalse(copies(''))
        self.assertFalse(copies('iOS 8.1.1', 'memory'))

    def test_repair_failures(self):
        import engine
        self.assertEqual(engine.repair_failure('unsupported:watch'), ('repair_unsupported_watch', ''))
        self.assertEqual(engine.repair_failure('mremap_encrypted failed: Cannot allocate memory (errno 12)')[0],
                         'repair_nomem')
        self.assertEqual(engine.repair_failure('TransportError: timeout')[0], 'repair_failed')


class GatedLaunchTests(unittest.TestCase):
    def test_frida_launchd_pids(self):
        import engine
        listing = ('PID\tStatus\tLabel\n19362\t-9\tre.frida.server\n-\t0\tre.frida.helper\n'
                   '88\t0\tcom.apple.backboardd\n')
        self.assertEqual(engine.frida_launchd_pids(listing), [19362])

    def test_gated_launches(self):
        import engine
        ps = ('  20058 T    xpcproxy com.apple.siriinferenced\n'
              '  20071 T    xpcproxy com.adguard.AdguardExtension.SafariWebExtension\n'
              '  20072 Ss   xpcproxy com.adguard.AdguardExtension.Tunnel\n'
              '  20080 T    /private/var/containers/Bundle/Application/X/Adguard.app/Adguard\n')
        self.assertEqual(engine.gated_launches(ps, 'com.adguard.AdguardExtension'), ([20071], [20058]))
        self.assertEqual(engine.gated_launches(ps), ([], [20058, 20071]))

    def test_gated_launches_match_the_app_only(self):
        import engine
        ps = ('  1 T    xpcproxy UIKitApplication:com.foo[8a3c][rb-legacy]\n'  # the app itself
              '  2 T    xpcproxy com.foo.Share(6F2B)\n'
              '  3 T    xpcproxy com.foobar.Widget\n'                         # another app
              '  4 T    xpcproxy UIKitApplication:com.foobar[11aa]\n')
        self.assertEqual(engine.gated_launches(ps, 'com.foo'), ([1, 2], [3, 4]))

    @needs_window
    def test_release_gated_resumes_frida_server_and_services(self):
        import ipa_extractor
        from unittest import mock
        outputs = {'launchctl list': (0, '-\t0\tcom.apple.x\n812\t-9\tre.frida.server\n'),
                   'ps -A -o pid=,stat=,args=': (0, ' 5 T xpcproxy com.foo.Ext\n 6 T xpcproxy com.apple.healthd\n')}
        gui = mock.Mock()
        gui._as_root.side_effect = lambda options, command: outputs.get(command, (0, ''))
        gui._resume_frida_server = lambda options: ipa_extractor.DumpGUI._resume_frida_server(gui, options)
        ipa_extractor.DumpGUI._release_gated(gui, {}, 'com.foo')
        commands = [call.args[1] for call in gui._as_root.call_args_list]
        self.assertEqual([c for c in commands if c.startswith('kill')], ['kill -CONT 812', 'kill -9 5', 'kill -CONT 6'])

    @needs_window
    def test_release_gated_survives_ssh_errors(self):
        import ipa_extractor
        from unittest import mock
        gui = mock.Mock()
        gui._as_root.side_effect = OSError('channel closed')
        ipa_extractor.DumpGUI._resume_frida_server(gui, {})
        ipa_extractor.DumpGUI._release_gated(gui, {}, 'com.foo')  # neither raises


class DumpMethodTests(unittest.TestCase):
    def test_setting_falls_back_to_direct(self):
        import engine
        self.assertEqual(engine.DEFAULTS['dump_method'], engine.METHOD_NATIVE)
        for value in engine.DUMP_METHODS:
            self.assertEqual(engine.dump_method_setting(value), value)
        for value in ('direct', 'dump', '', None):  # values of development builds, or none at all
            self.assertEqual(engine.dump_method_setting(value), engine.METHOD_NATIVE)
        # Method names say what they need: Frida for the frida_ ones, the helper programs for the native one.
        self.assertEqual(sorted(engine.DUMP_METHODS), ['frida_direct', 'frida_ios_dump', 'native'])

    def test_frida_method_to_return_to(self):
        import engine
        # the saved one, else the active method when it is a Frida one, else the direct mode
        self.assertEqual(engine.frida_method_setting(engine.METHOD_FRIDA_IOS_DUMP, engine.METHOD_NATIVE), engine.METHOD_FRIDA_IOS_DUMP)
        self.assertEqual(engine.frida_method_setting('', engine.METHOD_FRIDA_IOS_DUMP), engine.METHOD_FRIDA_IOS_DUMP)
        self.assertEqual(engine.frida_method_setting(None, engine.METHOD_NATIVE), engine.METHOD_FRIDA_DIRECT)
        self.assertEqual(engine.frida_method_setting(engine.METHOD_NATIVE, engine.METHOD_NATIVE), engine.METHOD_FRIDA_DIRECT)

    @needs_window
    def test_native_method_needs_no_frida_and_no_frida_ios_dump(self):
        import engine
        import ipa_extractor
        from unittest import mock
        for method, direct, native, frida in ((engine.METHOD_FRIDA_DIRECT, True, False, True),
                                              (engine.METHOD_FRIDA_IOS_DUMP, False, False, True),
                                              (engine.METHOD_NATIVE, True, True, False)):
            gui = mock.Mock()
            gui.var_dump_method.get.return_value = method
            self.assertEqual(ipa_extractor.DumpGUI.direct_method(gui), direct, method)
            self.assertEqual(ipa_extractor.DumpGUI.native_method(gui), native, method)
            gui.native_method = lambda g=gui: ipa_extractor.DumpGUI.native_method(g)
            self.assertEqual(ipa_extractor.DumpGUI.needs_frida(gui), frida, method)


class RepairJobTests(IpaMixin, unittest.TestCase):
    def job(self, slices=2):
        import ipa_repair
        import ipa_verify
        return ipa_repair.Job('0', 'Payload/X.app/PlugIns/E.appex/E', '/app/X.app/PlugIns/E.appex/E',
                              [ipa_verify.Slice('arm64', True, *self.ARM64, 0, 0x4000, 0x100, 1, 0)] * slices,
                              kind='appex', extension='com.x.e', min_os='16.0')

    def test_connection_lost_and_reset(self):
        import ipa_repair
        job = self.job()
        job.done.add(0)
        self.assertFalse(job.connection_lost())
        self.assertTrue(job.untried())
        job.slice_errors[1] = 'unsupported:slice'
        self.assertFalse(job.connection_lost())
        self.assertFalse(job.untried())
        for error in ('TransportError: the connection is closed', ipa_repair.STALLED.format(90),
                      'TransportError: timeout was reached',
                      'TransportError: error receiving data: Connection reset by peer',
                      'TransportError: error receiving data: An established connection was aborted',
                      'lost the connection to frida-server'):
            job.slice_errors[1] = error
            self.assertTrue(job.connection_lost(), error)
        job.slice_errors = {}
        job.error = ('frida', 'ServerNotRunningError: unable to connect to remote frida-server')
        self.assertTrue(job.connection_lost())
        job.reset()
        self.assertEqual((job.error, job.slice_errors, job.done), (None, {}, {0}))  # decrypted slices stay
        self.assertTrue(job.untried())

    def test_to_json_tells_the_worker_what_to_launch(self):
        data = self.job(1).to_json()
        self.assertEqual((data['kind'], data['extension'], data['suffix']),
                         ('appex', 'com.x.e', '/X.app/PlugIns/E.appex/E'))
        self.assertEqual(data['slices'][0]['cryptsize'], 0x100)

    def test_framework_with_info_plist_is_a_framework(self):
        import ipa_repair
        # A framework's Info.plist names its executable as well; that must not make it 'other'.
        executables = {'': 'X', 'Frameworks/F.framework': 'F', 'PlugIns/E.appex': 'E', 'Apps/N.app': 'N'}
        self.assertEqual(ipa_repair.kind('Frameworks/F.framework/F', executables), 'framework')
        self.assertEqual(ipa_repair.kind('Frameworks/libz.dylib', executables), 'framework')
        self.assertEqual(ipa_repair.kind('PlugIns/E.appex/Frameworks/G.framework/G', executables), 'framework')
        self.assertEqual(ipa_repair.kind('X', executables), 'main')
        self.assertEqual(ipa_repair.kind('PlugIns/E.appex/E', executables), 'appex')
        self.assertEqual(ipa_repair.kind('Apps/N.app/N', executables), 'other')
        self.assertEqual(ipa_repair.kind('Watch/W.app/W', executables), 'watch')

    def test_plan_reads_minimum_os_versions(self):
        import ipa_repair
        import ipa_verify
        import plistlib
        plist = lambda executable, identifier, minimum: plistlib.dumps(
            {'CFBundleExecutable': executable, 'CFBundleIdentifier': identifier, 'MinimumOSVersion': minimum})
        path = self.ipa({'X': thin_macho(*self.ARM64, 1), 'Info.plist': plist('X', 'com.x', '15.0'),
                         'PlugIns/G.appex/G': thin_macho(*self.ARM64, 1),
                         'PlugIns/G.appex/Info.plist': plist('G', 'com.x.g', '17.0'),
                         'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                         'Frameworks/F.framework/Info.plist': plist('F', 'com.x.f', '12.0')})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/app/X.app', path)
        found = {ipa_verify.short_name(j.member): (j.kind, j.min_os) for j in jobs}
        self.assertEqual(found, {'X': ('main', '15.0'), 'PlugIns/G.appex/G': ('appex', '17.0'),
                                 'Frameworks/F.framework/F': ('framework', '12.0')})
        self.assertGreater(ipa_repair.version_tuple('17.0'), ipa_repair.version_tuple('iPhone OS 16.1.2'))


class RepairWorkerHelperTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('repair_worker', ROOT / 'repair_worker.py')
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)  # frida itself is only imported by Worker()

    def test_clean_error(self):
        clean = self.worker.clean
        self.assertEqual(clean('Error: mremap_encrypted failed (errno 1)\n    at decrypt (agent.js:10)'),
                         'mremap_encrypted failed (errno 1)')
        self.assertEqual(clean('TransportError: the connection is closed'), 'TransportError: the connection is closed')
        self.assertEqual(clean(''), '')

    def test_belongs_to(self):
        belongs_to = self.worker.belongs_to
        self.assertTrue(belongs_to('com.foo', 'com.foo'))
        self.assertTrue(belongs_to('com.foo.Share', 'com.foo'))
        self.assertFalse(belongs_to('com.foobar', 'com.foo'))
        self.assertFalse(belongs_to('com.apple.Preferences', 'com.foo'))
        self.assertFalse(belongs_to(None, 'com.foo'))
        self.assertFalse(belongs_to('com.foo', ''))

    def test_same_cpu_ignores_capability_bits(self):
        same_cpu = self.worker.same_cpu
        item = {'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 0}
        self.assertTrue(same_cpu({'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 0x80000000}, item))
        self.assertFalse(same_cpu({'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 2}, item))  # arm64e
        self.assertFalse(same_cpu({'cpu': app_info.CPU_TYPE_ARM, 'subtype': 0}, item))

    def test_extension_hosts_learn_from_each_lookup(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)  # no frida: the lookups are faked
        worker.hosts, worker.app_running = {}, True
        worker.host_order = list(self.worker.EXTENSION_HOSTS)
        self.assertEqual(worker.host_order[-1], 'app')  # asked last: a running app tends to hang
        asked = []

        def catch(host, job):
            asked.append(host)
            if host == 'AuthenticationServicesAgent':
                raise RuntimeError('TransportError: timeout was reached')
            return 42 if host == 'spawn:com.apple.Preferences' else None

        worker.catch_extension = catch
        worker.device = mock.Mock()
        worker.read_image = mock.Mock()
        with mock.patch.object(self.worker, 'load_agent'), mock.patch.object(self.worker, 'emit'):
            worker.extension({'id': '0', 'slices': [{}], 'extension': 'com.x.a'})
            self.assertEqual(asked, ['SpringBoard', 'AuthenticationServicesAgent', 'spawn:com.apple.Preferences'])
            asked.clear()
            worker.extension({'id': '1', 'slices': [{}], 'extension': 'com.x.b'})
        self.assertEqual(asked, ['spawn:com.apple.Preferences'])  # the host that worked first, the hung one dropped
        self.assertEqual(worker.host_order, ['spawn:com.apple.Preferences', 'SpringBoard', 'app'])

    def test_frameworks_let_the_app_start_once_then_load_each(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)
        worker.app_running, worker.app_pid = False, 7
        worker.device = mock.Mock()
        api = mock.Mock()
        api.hook_app_main.return_value = True
        api.load_image.side_effect = [RuntimeError('dyld busy'), '0x1000', '0x2000']  # first try too early
        worker.app = lambda: api
        worker.read_image = mock.Mock()
        jobs = [{'id': str(i), 'path': '/a/X.app/Frameworks/F%d.framework/F%d' % (i, i), 'slices': [{}]} for i in range(2)]
        events = []
        with mock.patch.object(self.worker, 'emit', side_effect=lambda kind, **data: events.append(kind)), \
                mock.patch.object(self.worker.time, 'sleep'):
            worker.frameworks(jobs)
        api.hook_app_main.assert_called_once()
        worker.device.resume.assert_called_once_with(7)  # before any framework is loaded
        self.assertIn('running_app', events)               # the GUI logs that the app's code runs
        self.assertEqual(api.load_image.call_count, 3)
        self.assertEqual(worker.read_image.call_count, 2)

    def test_frameworks_never_resume_an_app_whose_ui_cannot_be_stopped(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)
        worker.app_running, worker.app_pid = False, 7
        worker.device = mock.Mock()
        api = mock.Mock()
        api.hook_app_main.return_value = False
        worker.app = lambda: api
        failed = []
        worker.fail_all = lambda job, error: failed.append((job['id'], error))
        with mock.patch.object(self.worker, 'emit'):
            worker.frameworks([{'id': '0', 'path': '/a/F', 'slices': [{}]}])
        worker.device.resume.assert_not_called()
        self.assertEqual(failed, [('0', 'RuntimeError: UIApplicationMain not found in the app')])

    def test_alive_is_throttled(self):
        from unittest import mock
        out = io.StringIO()
        with mock.patch.object(self.worker.sys, 'stdout', out), \
                mock.patch.object(self.worker.time, 'monotonic', side_effect=[100.0, 100.0, 105.0, 111.0, 111.0]):
            self.worker._last_emit[0] = 0.0
            self.worker.alive()   # 100: long silence -> emits (and records 100)
            self.worker.alive()   # 105: too soon
            self.worker.alive()   # 111: due again
        events = [json.loads(line[2:])['type'] for line in out.getvalue().splitlines()]
        self.assertEqual(events, ['alive', 'alive'])


class RunningPidTests(unittest.TestCase):
    def test_extensions_are_not_the_app(self):
        import device_apps
        from unittest import mock
        app = '/private/var/containers/Bundle/Application/U/Adguard.app'
        tunnel = '10496 /private/var/containers/Bundle/Application/U/Adguard.app/PlugIns/Tunnel.appex/Tunnel\n'
        with mock.patch.object(device_apps.remote, 'run', return_value=(0, tunnel)):
            self.assertEqual(device_apps.running_pid(None, app), 0)  # only the VPN extension runs
        with mock.patch.object(device_apps.remote, 'run',
                               return_value=(0, tunnel + '10500 /var/containers/Bundle/Application/U/Adguard.app/Adguard\n')):
            self.assertEqual(device_apps.running_pid(None, app), 10500)


class SuspendedPidsTests(unittest.TestCase):
    def test_finds_stopped_processes_of_the_bundle(self):
        import device_apps
        from unittest import mock
        ps = ('  10 T    /private/var/containers/Bundle/Application/U/X.app/X\n'
              '  11 T    /var/containers/Bundle/Application/U/X.app/PlugIns/E.appex/E\n'
              '  12 Ss   /private/var/containers/Bundle/Application/U/X.app/PlugIns/F.appex/F\n'
              '  13 T    /private/var/containers/Bundle/Application/U/X.appx/Y\n'
              '  14 T    xpcproxy\n')
        with mock.patch.object(device_apps.remote, 'run', return_value=(0, ps)):
            self.assertEqual(device_apps.suspended_pids(None, '/private/var/containers/Bundle/Application/U/X.app/'),
                             [10, 11])


class ErrorClassificationTests(unittest.TestCase):
    def test_known_errors(self):
        import engine
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
            self.assertEqual(engine.classify_error(message), kind, message)


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
        self.commands = getattr(self, 'commands', []) + [command]
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

    def test_direct_method_leaves_out_purchase_metadata(self):
        import ipa_extract
        import zipfile
        for metadata in (True, False):
            client = FakeSSH(self.tar())
            with tempfile.TemporaryDirectory() as folder:
                dest = os.path.join(folder, 'x.ipa')
                ipa_extract.extract_ipa(client, '/var/containers/Bundle/Application/U/X.app', dest,
                                        metadata=metadata)
                with zipfile.ZipFile(dest) as ipa:
                    self.assertEqual(ipa.read('Payload/X.app/X'), b'exe')
            # The device lists iTunesMetadata.plist (see FakeSSH.makefile); only tar decides what is copied.
            tar = next(command for command in client.commands if 'tar ' in command)
            self.assertEqual('iTunesMetadata.plist' in tar, metadata, tar)

    def test_hard_links_are_not_dropped_silently(self):
        import ipa_extract
        import tarfile
        link = tarfile.TarInfo('X.app/Copy')
        link.type, link.linkname = tarfile.LNKTYPE, 'X.app/X'
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError):
                ipa_extract.extract_ipa(FakeSSH(self.tar(link)), '/c/U/X.app', os.path.join(folder, 'x.ipa'))
            self.assertEqual(os.listdir(folder), [])  # no partial IPA left behind

@needs_window
class WrapTextTests(unittest.TestCase):
    class Font:
        def measure(self, text):
            return 10 * len(text)

    def wrap(self, text, width):
        import ipa_extractor
        return ipa_extractor.wrap_text(text, width, self.Font()).split('\n')

    def test_words_of_spaced_scripts_are_never_split(self):
        for text in ('Расшифрованные приложения читаются', 'Entschlüsselung ausführbarer Dateien', 'Giải mã ứng dụng đã cài',
                     'Şifre çözme işlemi tamamlandı', '복호화 모드를 선택하세요'):
            words = set(text.split())
            for line in self.wrap(text, 140):
                for word in line.split():
                    self.assertIn(word, words, line)

    def test_a_long_word_stays_on_a_line_of_its_own(self):
        self.assertEqual(self.wrap('aa Расшифровывать bb', 100), ['aa', 'Расшифровывать', 'bb'])

    def test_unspaced_scripts_break_between_characters(self):
        self.assertEqual(self.wrap('これは長い日本語の文です', 50), ['これは長い', '日本語の文', 'です'])
        self.assertEqual(self.wrap('這是一段很長的中文說明', 50), ['這是一段很', '長的中文說', '明'])
        thai = 'การตั้งค่านี้ใช้กับ'
        self.assertTrue(all(len(line) <= 5 for line in self.wrap(thai, 50)))

    def test_paths_and_identifiers_stay_whole(self):
        path = r'C:\Users\me\frida-ios-dump'
        self.assertEqual(self.wrap('open ' + path + ' now', 150), ['open', path, 'now'])


if __name__ == '__main__':
    unittest.main()
