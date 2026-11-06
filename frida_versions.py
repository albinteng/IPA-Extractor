# -*- coding: utf-8 -*-
"""Several frida versions side by side, one folder each, so one window can serve devices
whose frida-server major versions differ.

A process can load only one frida, so the GUI never imports it: everything that talks to
Frida runs in a child process whose PYTHONPATH points at the chosen version's folder.
"""

import io
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import urllib.request
import zipfile

script_dir = os.path.dirname(os.path.realpath(__file__))
VERSION_RE = re.compile(r'\d+\.\d+\.\d+')
LEGACY_BELOW = 14  # frida 14 is the first with abi3 wheels; older ones ship eggs for Python 2.7 and 3.8 only
LEGACY_PYTHON = '3.8.10'
LEGACY_PYTHON_URL = 'https://www.python.org/ftp/python/{0}/python-{0}-embed-amd64.zip'.format(LEGACY_PYTHON)
PYPI_URL = 'https://pypi.org/pypi/frida/{}/json'
COMPLETE = '.complete'  # written after pip succeeds, so a half-finished install is never used


def _writable(folder):
    try:
        os.makedirs(folder, exist_ok=True)
        with tempfile.TemporaryFile(dir=folder):
            return True
    except OSError:
        return False


def default_root():
    """Beside the tool like settings.json; the home folder when the tool's folder is read-only."""
    portable = os.path.join(script_dir, 'frida_versions')
    if _writable(portable):
        return portable
    return os.path.join(os.path.expanduser('~'), '.ipa_extractor', 'frida_versions')


ROOT = default_root()


def version_key(version):
    return tuple(int(part) for part in version.split('.'))


def major(version):
    return (version or '').split('.')[0]


def folder(version, root=None):
    return os.path.join(root or ROOT, version)


def installed(root=None):
    """Installed versions, newest first."""
    root = root or ROOT
    try:
        names = os.listdir(root)
    except OSError:
        return []
    versions = [name for name in names if VERSION_RE.fullmatch(name)
                and os.path.isfile(os.path.join(root, name, COMPLETE))]
    return sorted(versions, key=version_key, reverse=True)


def pick(device_version, versions):
    """The installed version to use with device_version: the same one, else the newest of its major."""
    if not device_version:
        return None
    if device_version in versions:
        return device_version
    same_major = [v for v in versions if major(v) == major(device_version)]
    return max(same_major, key=version_key) if same_major else None


def env(version, base=None, root=None):
    """Environment for a child process that must import this frida version."""
    result = dict(os.environ if base is None else base)
    paths = [folder(version, root)] + [p for p in result.get('PYTHONPATH', '').split(os.pathsep) if p]
    result['PYTHONPATH'] = os.pathsep.join(paths)
    return result


def python(version, root=None):
    """Interpreter for a child process using this frida version.

    A version whose Python bindings exist only for an older Python (frida 12 for 3.8) brings its own
    interpreter in <version>/python; every other version runs with the tool's own Python.
    """
    for name in ('python.exe', os.path.join('bin', 'python3')):
        path = os.path.join(folder(version, root), 'python', name)
        if os.path.isfile(path):
            return path
    return sys.executable


def staging(version, root=None):
    return folder(version, root) + '.partial'


def is_legacy(version):
    """Whether this frida has no wheel for current Pythons and needs its own Python 3.8."""
    return int(major(version) or 0) < LEGACY_BELOW


def legacy_supported():
    """The embeddable Python 3.8 and the frida eggs used here exist for Windows x64 only."""
    return sys.platform == 'win32' and platform.machine().lower() in ('amd64', 'x86_64')


def egg_name(version):
    return 'frida-{}-py3.8-win-amd64.egg'.format(version)


def legacy_versions(releases):
    """Legacy versions among PyPI's `releases` that have an egg for this computer."""
    if not legacy_supported():
        return []
    return [v for v, files in releases.items() if re.fullmatch(r'\d+\.\d+\.\d+', v) and is_legacy(v)
            and any(f['filename'] == egg_name(v) and not f.get('yanked') for f in files)]


def install_legacy(version, log, root=None):
    """Install an old frida into its staging folder: its Python 3.8 egg beside an embeddable Python 3.8.

    log(text) reports progress. Raises on failure; finish_install() then moves it into place.
    """
    def download(url):
        log('Downloading ' + url)
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read()

    if not legacy_supported():
        raise RuntimeError('frida {} needs Python 3.8, which this tool sets up on Windows x64 only'.format(version))
    path = staging(version, root)
    with urllib.request.urlopen(PYPI_URL.format(version), timeout=30) as response:
        files = json.load(response)['urls']
    egg = next((f for f in files if f['filename'] == egg_name(version)), None)
    if egg is None:
        raise RuntimeError('no {} on PyPI'.format(egg_name(version)))
    with zipfile.ZipFile(io.BytesIO(download(egg['url']))) as archive:
        archive.extractall(path, [n for n in archive.namelist() if not n.startswith('EGG-INFO/')])
    python = os.path.join(path, 'python')
    with zipfile.ZipFile(io.BytesIO(download(LEGACY_PYTHON_URL))) as archive:
        archive.extractall(python)
    # An embeddable Python ignores PYTHONPATH; its ._pth lists where to import from ('..' is the frida folder).
    with open(os.path.join(python, 'python38._pth'), 'w') as handle:
        handle.write('\n'.join(['python38.zip', '.', '..', 'import site', '']))


def install_command(version, root=None):
    """pip command that installs frida==version into its staging folder (see finish_install)."""
    if is_legacy(version):
        return ['download', egg_name(version), 'and', 'Python', LEGACY_PYTHON, '(embeddable)']
    # --target cannot be combined with --user; the folder needs no administrator rights anyway.
    return [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check', '--no-warn-script-location',
            '--target', staging(version, root), 'frida=={}'.format(version)]


def prepare_install(version, root=None):
    path = staging(version, root)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)


def finish_install(version, root=None):
    """Move the staging folder into place once pip has succeeded."""
    path, target = staging(version, root), folder(version, root)
    with open(os.path.join(path, COMPLETE), 'w'):
        pass
    remove(version, root)
    os.replace(path, target)


def remove(version, root=None):
    """Delete an installed version. Raises OSError when a running process still holds its files."""
    path = folder(version, root)
    if os.path.isdir(path):
        # Drop the marker first so a folder that cannot be fully deleted is no longer offered.
        try:
            os.remove(os.path.join(path, COMPLETE))
        except FileNotFoundError:
            pass
        shutil.rmtree(path)
