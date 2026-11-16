# -*- coding: utf-8 -*-
"""Reading Mach-O files and the names made from an app (app_info.py)."""

import io
import struct
import unittest

import app_info
from tests.support import code_directory, macho, superblob


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


if __name__ == '__main__':
    unittest.main()
