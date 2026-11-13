#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the release program with Nuitka: python build.py [--output DIR]

Needs `pip install nuitka paramiko cryptography scp` (plus sv-ttk on Linux) in the Python that runs it, a C compiler,
and on Linux patchelf. The result is a folder (a .app on macOS) that runs without Python; the release workflow
(.github/workflows/release.yml) zips it for each platform. Frida is not part of it: the program downloads the
version a device needs (see frida_versions.py).
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = 'IPA Extractor'

# What dump.py of frida-ios-dump imports and the program itself would not: it runs inside the program
# (workers.py), and a compiled program contains only the modules it can see being imported.
DUMP_PY_IMPORTS = ('traceback', 'queue', 'stat', 'posixpath', 'math', 'concurrent.futures', 'urllib.parse', 'socket',
                   'zipfile', 'argparse', 'tempfile', 'shutil', 'threading', 'scp', 'paramiko')


def command(output):
    sys.path.insert(0, HERE)
    import engine
    version = engine.__version__
    args = [sys.executable, '-m', 'nuitka', '--standalone', '--assume-yes-for-downloads',
            '--enable-plugin=tk-inter', '--output-dir=' + output, '--output-filename=IPA-Extractor',
            '--product-name=' + NAME, '--file-version=' + '.'.join((version.split('.') + ['0'] * 4)[:4]),
            '--company-name=IPA Extractor', '--file-description=' + NAME,
            '--include-data-dir=locales=locales', '--include-data-dir=helpers/bin=helpers/bin',
            '--include-data-dir=assets=assets', '--include-data-files=device_models.json=device_models.json',
            '--include-data-files=repair_agent.js=repair_agent.js', '--nofollow-import-to=frida,frida_tools']
    args += ['--include-module=' + name for name in DUMP_PY_IMPORTS]
    if sys.platform == 'win32':
        # attach: the command line prints into the console it was started from; started by a double click, no console.
        args += ['--windows-console-mode=attach', '--windows-icon-from-ico=assets/icon.ico']
    if sys.platform == 'darwin':
        args += ['--macos-create-app-bundle', '--macos-app-name=' + NAME, '--macos-app-version=' + version]
        if os.path.isfile(os.path.join(HERE, 'assets', 'icon.icns')):
            args.append('--macos-app-icon=assets/icon.icns')
    else:
        args.append('--onefile')                        # one file (a .app is already one item)
    if sys.platform.startswith('linux'):
        args.append('--include-package-data=sv_ttk')   # the Tk theme of the window on Linux
    return args + ['ipa_extractor.py']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default=os.path.join(HERE, 'build'))
    args = parser.parse_args()
    return subprocess.call(command(os.path.abspath(args.output)), cwd=HERE)


if __name__ == '__main__':
    sys.exit(main())
