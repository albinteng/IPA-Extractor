#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""List installed apps over SSH/SFTP alone, so extracting IPAs does not need Frida.

Names follow what the Home screen shows (the localized display name), matching
the names Frida reports, so IPA file names do not depend on how the list was loaded.
"""

import plistlib
import posixpath
import re
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor

import remote

APP_ROOTS = ('/private/var/containers/Bundle/Application', '/Applications', '/var/jb/Applications')
DATA_ROOT = '/private/var/mobile/Containers/Data/Application'
# SFTP requests are sequential per channel; several channels hide the round trips.
# sshd allows 10 sessions per connection by default; the GUI needs a few of its own.
WORKERS = 4
GLOBAL_PREFERENCES = '/private/var/mobile/Library/Preferences/.GlobalPreferences.plist'
# Legacy lproj names still used by old bundles.
LEGACY_LPROJ = {'en': 'English', 'ja': 'Japanese', 'fr': 'French', 'de': 'German',
                'es': 'Spanish', 'it': 'Italian', 'nl': 'Dutch'}
# Chinese scripts versus the region-style names older bundles use.
CHINESE = {'zh-Hant': ('zh-Hant', 'zh_TW', 'zh-TW', 'zh_HK', 'zh-HK'),
           'zh-Hans': ('zh-Hans', 'zh_CN', 'zh-CN', 'zh')}


def _read(sftp, path):
    with sftp.open(path, 'rb') as handle:
        return handle.read()


def _plist(sftp, path):
    try:
        return plistlib.loads(_read(sftp, path))
    except Exception:
        return None


def parse_strings(data):
    """Parse an InfoPlist.strings file: binary/XML plist, or "key" = "value"; text."""
    try:
        result = plistlib.loads(data)
        return result if isinstance(result, dict) else {}
    except Exception:
        pass
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        text = data.decode('utf-16', 'replace')
    else:
        text = data.decode('utf-8-sig', 'replace')
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    result = {}
    pattern = r'"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;|(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*;'
    for match in re.finditer(pattern, text):
        key = match.group(1) if match.group(1) is not None else match.group(3)
        value = match.group(2) if match.group(2) is not None else match.group(4)
        result[_unescape(key)] = _unescape(value)
    return result


def _unescape(text):
    # .strings files write Unicode escapes as \U00e9 as well as é.
    return re.sub(r'\\([uU][0-9a-fA-F]{4}|.)',
                  lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 5
                  else {'n': '\n', 't': '\t'}.get(m.group(1), m.group(1)), text)


def preferred_languages(sftp):
    prefs = _plist(sftp, GLOBAL_PREFERENCES) or {}
    return list(prefs.get('AppleLanguages') or ['en'])


def lproj_candidates(language):
    """Folder names to try for one preferred language, most specific first."""
    parts = language.replace('_', '-').split('-')
    names = [language]
    if parts[0] == 'zh':
        script = 'zh-Hans'
        if 'Hant' in parts or any(p in ('TW', 'HK', 'MO') for p in parts):
            script = 'zh-Hant'
        names += CHINESE[script]
    elif len(parts) > 1:
        names += ['{}_{}'.format(parts[0], parts[-1]), '{}-{}'.format(parts[0], parts[-1]), parts[0]]
    names.append(LEGACY_LPROJ.get(parts[0], parts[0]))
    return list(dict.fromkeys(names))


def display_name(sftp, app_path, info, entries, languages):
    lprojs = {e[:-6] for e in entries if e.endswith('.lproj')}
    order = [c for language in languages for c in lproj_candidates(language)]
    development = info.get('CFBundleDevelopmentRegion')
    if development:
        # The development region counts as a localization even without its own .lproj.
        lprojs.update(lproj_candidates(development))
        order += lproj_candidates(development)
    for name in dict.fromkeys(order):
        if name not in lprojs:
            continue
        # The first localization the app has is chosen even if it does not rename the app.
        try:
            strings = parse_strings(_read(sftp, '{}/{}.lproj/InfoPlist.strings'.format(app_path, name)))
        except Exception:  # missing or unreadable: fall back to Info.plist
            strings = {}
        label = strings.get('CFBundleDisplayName') or strings.get('CFBundleName')
        if label:
            return label
        break
    return (info.get('CFBundleDisplayName') or info.get('CFBundleName') or
            info.get('CFBundleExecutable') or posixpath.basename(app_path)[:-4])


def _running(client):
    result = []
    for line in remote.run(client, 'ps -A -o pid=,comm=')[1].splitlines():
        pid, _, command = line.strip().partition(' ')
        if pid.isdigit():
            result.append((int(pid), command.strip()))
    return result


def _bundle_prefixes(app_path):
    app_path = app_path.rstrip('/')
    return app_path + '/', app_path.replace('/private/var/', '/var/', 1) + '/'


def running_pid(client, app_path):
    """PID of the app whose bundle is at app_path, or 0 when it is not running.
    Only the app's own executable counts, not its extensions (PlugIns/X.appex/X), which the system
    keeps running on its own (a VPN tunnel, for one)."""
    for pid, command in _running(client):
        for prefix in _bundle_prefixes(app_path):
            if command.startswith(prefix) and '/' not in command[len(prefix):]:
                return pid
    return 0


def suspended_pids(client, app_path):
    """PIDs of stopped processes (state T) running code from the app's bundle, its extensions included."""
    prefixes = _bundle_prefixes(app_path)
    result = []
    for line in remote.run(client, 'ps -A -o pid=,stat=,comm=')[1].splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].startswith('T') and parts[2].startswith(prefixes):
            result.append(int(parts[0]))
    return result


class _SFTPPool:
    """A fixed set of worker threads, each with its own SFTP channel."""

    def __init__(self, client):
        self.client = client
        self.local = threading.local()
        self.channels = []
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(WORKERS)

    def get(self):
        sftp = getattr(self.local, 'sftp', None)
        if sftp is None:
            sftp = self.local.sftp = self.client.open_sftp()
            with self.lock:
                self.channels.append(sftp)
        return sftp

    def map(self, func, items):
        return list(self.executor.map(lambda item: func(self.get(), item), items))

    def close(self):
        self.executor.shutdown()
        for sftp in self.channels:
            sftp.close()


def _container_owner(sftp, path):
    meta = _plist(sftp, path + '/.com.apple.mobile_container_manager.metadata.plist')
    return (meta or {}).get('MCMMetadataIdentifier'), path


def _read_bundle(sftp, path, languages):
    try:
        entries = sftp.listdir(path)
    except OSError:
        return None
    info = _plist(sftp, path + '/Info.plist') if 'Info.plist' in entries else None
    if not info or not info.get('CFBundleIdentifier'):
        return None
    # SpringBoard-hidden bundles (plugins, services) are not listed by Frida either.
    if 'hidden' in (info.get('SBAppTags') or []) or info.get('LSApplicationLaunchProhibited'):
        return None
    # Offloaded apps keep only a placeholder bundle: Info.plist and icons, no executable.
    offloaded = info.get('CFBundleExecutable') not in entries
    return dict(name=display_name(sftp, path, info, entries, languages), bundle=info['CFBundleIdentifier'],
                version=str(info.get('CFBundleShortVersionString', '')),
                build=str(info.get('CFBundleVersion', '')), path=path, offloaded=offloaded)


def list_apps(client):
    """Return {bundle: dict(name, bundle, version, build, path, offloaded, data, pid)}."""
    _, output = remote.run(
        client, 'for d in {}; do ls -d "$d"/*.app "$d"/*/*.app; done 2>/dev/null; echo @@; ls -d {}/*/ 2>/dev/null'.format(
            ' '.join(shlex.quote(root) for root in APP_ROOTS), DATA_ROOT), timeout=30)
    bundles, _, data = output.partition('@@')
    paths = [line.strip() for line in bundles.splitlines() if line.strip()]
    data_paths = [line.strip().rstrip('/') for line in data.splitlines() if line.strip()]
    processes = _running(client)
    pool = _SFTPPool(client)
    try:
        languages = pool.map(lambda sftp, _: preferred_languages(sftp), [None])[0]
        containers = dict(pool.map(_container_owner, data_paths))
        apps = {}
        for app in pool.map(lambda sftp, path: _read_bundle(sftp, path, languages), paths):
            if app is None or app['bundle'] in apps:
                continue
            prefix = app['path'] + '/'
            app['pid'] = next((p for p, command in processes if command.startswith(prefix)), 0)
            app['data'] = containers.get(app['bundle'], '')
            apps[app['bundle']] = app
        return apps
    finally:
        pool.close()
