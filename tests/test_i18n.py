# -*- coding: utf-8 -*-
"""The translations: every language has every message (i18n.py, locales/)."""

import unittest


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


class LanguageTests(unittest.TestCase):
    def test_every_language_names_the_connection_choices(self):
        import i18n
        for code, strings in i18n.load_locales().items():
            for key in ('connection', 'conn_ssh', 'conn_usb', 'usb_device', 'usb_refresh', 'tab_connection',
                        'connection_help', 'log_ready_usb', 'usb_none', 'conn_ssh_tip', 'conn_usb_tip'):
                self.assertTrue(strings.get(key), (code, key))
            self.assertNotEqual(strings['conn_ssh'], strings['conn_usb'], code)


if __name__ == '__main__':
    unittest.main()
