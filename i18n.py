# -*- coding: utf-8 -*-
"""UI languages: one JSON file per language in locales/, named by its language tag (zh-TW.json, en.json).

Adding a language means adding a file; keys missing from it fall back to English. Values are
str.format templates (literal braces doubled). "_name" is shown in the language list and
"_fonts" lists preferred UI fonts, first installed one wins.
"""

import json
import locale
import os
import subprocess
import sys

LOCALE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'locales')
FALLBACK = 'en'
AUTO = 'auto'
# Chinese is chosen by script, which region tags only imply.
TRADITIONAL_CHINESE = ('hant', 'tw', 'hk', 'mo')


def load_locales(directory=LOCALE_DIR):
    locales = {}
    for file in sorted(os.listdir(directory)):
        if file.endswith('.json'):
            with open(os.path.join(directory, file), encoding='utf-8') as handle:
                locales[file[:-5]] = json.load(handle)
    return locales


def system_language_tags():
    """The user's preferred UI languages as tags such as 'zh-TW' or 'en-US', most preferred first."""
    tags = []
    if sys.platform == 'win32':
        import ctypes
        # The display language first; the regional format (e.g. English UI with Chinese dates) second.
        language_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        tags.append(locale.windows_locale.get(language_id, ''))
        buffer = ctypes.create_unicode_buffer(85)
        if ctypes.windll.kernel32.GetUserDefaultLocaleName(buffer, len(buffer)):
            tags.append(buffer.value)
    elif sys.platform == 'darwin':
        try:
            output = subprocess.run(['defaults', 'read', '-g', 'AppleLanguages'], capture_output=True,
                                    text=True, timeout=5).stdout
            tags += [part.strip(' "\n,()') for part in output.split('\n')]
        except (OSError, subprocess.SubprocessError):
            pass
    for name in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG'):
        tags += os.environ.get(name, '').split(':')
    return [tag.split('.')[0].replace('_', '-') for tag in tags if tag and tag.split('.')[0] not in ('C', 'POSIX')]


def match_language(locales, tag):
    """Best locale code for a tag like 'zh-Hant-TW' or 'ja-JP', or None."""
    parts = tag.lower().split('-')
    by_lower = {code.lower(): code for code in locales}
    if parts[0] == 'zh':
        wanted = 'zh-tw' if any(p in TRADITIONAL_CHINESE for p in parts[1:]) else 'zh-cn'
        return by_lower.get(wanted)
    same_language = [code for code in locales if code.lower().split('-')[0] == parts[0]]
    # Otherwise any variant of the language, e.g. pt-BR for a pt-PT system.
    return by_lower.get(tag.lower()) or by_lower.get(parts[0]) or (same_language or [None])[0]


def system_language(locales):
    for tag in system_language_tags():
        code = match_language(locales, tag)
        if code:
            return code
    return FALLBACK


def resolve(locales, code):
    if code == AUTO:
        return system_language(locales)
    return code if code in locales else FALLBACK
