# -*- coding: utf-8 -*-
"""Helpers of the window that need no window: themes."""

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
        from gui import theme
        keys = set(theme.PALETTES['light'])
        for name, palette in theme.PALETTES.items():
            self.assertEqual(set(palette), keys, name)
            for value in palette.values():
                self.assertRegex(value, r'^#[0-9a-f]{6}$')
        self.assertEqual(theme.PALETTES['black']['bg'], '#000000')
        self.assertEqual(theme.PALETTES['black']['side'], '#000000')

    def test_every_language_names_the_themes(self):
        import i18n
        for code, strings in i18n.load_locales().items():
            for key in ('theme', 'theme_system', 'theme_light', 'theme_dark', 'theme_black'):
                self.assertTrue(strings.get(key), (code, key))
            self.assertEqual(len({strings['theme_system'], strings['theme_light'], strings['theme_dark'], strings['theme_black']}), 4, code)


if __name__ == '__main__':
    unittest.main()
