# -*- coding: utf-8 -*-
"""Where the tool's own files are, and where it keeps what it writes.

From source, both are the tool's folder: settings, output and the frida versions sit beside the scripts, so the
folder is portable. A program built with Nuitka (the release downloads) has no Python and no scripts: its own files
(locales, helpers, assets) are in its folder, and what it writes goes beside the program as well, except on macOS,
where a downloaded .app is run from a read-only copy and must stay unmodified: settings go to Application Support
and the output to Documents.
"""

import os
import shutil
import sys
import tempfile

FROZEN = '__compiled__' in globals()      # set by Nuitka in every module it compiles
APP_DIR = os.path.dirname(os.path.realpath(__file__))
if FROZEN and os.environ.get('NUITKA_ONEFILE_PARENT'):
    # A single-file build unpacks itself into a temporary folder (where __file__ is); what it writes belongs beside the
    # file that was started. containing_dir is that folder (a folder build is not unpacked: its __file__ is right).
    APP_DIR = os.path.realpath(getattr(__compiled__, 'containing_dir', APP_DIR))
HOME_DIR = os.path.join(os.path.expanduser('~'), '.ipa_extractor')


def writable(folder):
    try:
        os.makedirs(folder, exist_ok=True)
        with tempfile.TemporaryFile(dir=folder):
            return True
    except OSError:
        return False


def program_path():
    """The file of the released program that is running, also when it was started by its bare name from PATH."""
    start = sys.argv[0]
    if os.path.dirname(start):
        return os.path.abspath(start)
    return os.path.abspath(shutil.which(start) or os.path.join(APP_DIR, start))


def data_dir():
    """Settings and the installed frida versions."""
    if not FROZEN:
        return APP_DIR
    if sys.platform == 'darwin':
        return os.path.join(os.path.expanduser('~'), 'Library', 'Application Support', 'IPA Extractor')   # made when used
    return APP_DIR if writable(APP_DIR) else HOME_DIR


def output_base():
    """Where the default output folders and the frida-ios-dump checkout go."""
    if FROZEN and sys.platform == 'darwin':
        return os.path.join(os.path.expanduser('~'), 'Documents', 'IPA Extractor')
    return data_dir()


DATA_DIR = data_dir()
OUTPUT_BASE = output_base()
