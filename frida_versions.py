# -*- coding: utf-8 -*-
"""Several frida versions side by side, one folder each, so one window can serve devices
whose frida-server major versions differ.

A process can load only one frida, so the GUI never imports it: everything that talks to
Frida runs in a child process whose PYTHONPATH points at the chosen version's folder.
"""

import os
import re
import shutil
import sys
import tempfile

script_dir = os.path.dirname(os.path.realpath(__file__))
VERSION_RE = re.compile(r'\d+\.\d+\.\d+')
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


def staging(version, root=None):
    return folder(version, root) + '.partial'


def install_command(version, root=None):
    """pip command that installs frida==version into its staging folder (see finish_install)."""
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
