# -*- coding: utf-8 -*-
"""Helpers of the window that need no window: themes and text wrapping."""

import unittest

from tests.support import needs_window


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
