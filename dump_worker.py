#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run frida-ios-dump's dump.py unchanged, reporting tqdm progress as JSON lines for the GUI.

Usage: dump_worker.py [dump.py arguments...]
FRIDA_IOS_DUMP_DIR selects the frida-ios-dump checkout (default: ../frida-ios-dump).
The SSH password may be supplied in FRIDA_DUMP_SSH_PASSWORD instead of -P so
that it does not appear in the process list.
"""

import itertools
import json
import os
import runpy
import sys
import threading
import time
import types

script_dir = os.path.dirname(os.path.realpath(__file__))
# The frida-ios-dump checkout to run; dump.py finds dump.js and node_modules beside itself.
# The GUI always sets FRIDA_IOS_DUMP_DIR; the fallback is for running this script by hand.
DUMP_DIR = os.environ.get('FRIDA_IOS_DUMP_DIR') or os.path.join(os.path.dirname(script_dir), 'frida-ios-dump')
DUMP_PY = os.path.join(DUMP_DIR, 'dump.py')
PREFIX = '@@'

_lock = threading.Lock()


def emit(kind, **data):
    data['type'] = kind
    with _lock:
        sys.stdout.write(PREFIX + json.dumps(data, ensure_ascii=False) + '\n')
        sys.stdout.flush()


class ProgressBar:
    """Minimal tqdm stand-in: dump.py only uses these members."""
    _ids = itertools.count(1)

    def __init__(self, *args, total=None, desc=None, mininterval=0.2, **kwargs):
        self.id = next(self._ids)
        self.n = 0
        self.total = total
        self.desc = desc or ''
        self.mininterval = mininterval
        self._last = 0.0

    def _emit(self, force=False, closed=False):
        now = time.monotonic()
        if not force and now - self._last < self.mininterval:
            return
        self._last = now
        emit('progress', id=self.id, desc=str(self.desc), n=self.n,
             total=self.total, closed=closed)

    def update(self, n=1):
        self.n += n
        self._emit()

    def set_description_str(self, desc=None, refresh=True):
        self.desc = desc or ''
        self._emit(force=refresh)

    set_description = set_description_str

    def refresh(self):
        self._emit(force=True)

    def close(self):
        self._emit(force=True, closed=True)

    @staticmethod
    def write(text, file=None, end='\n', nolock=False):
        emit('log', text=str(text))


EXTENDED_PREFIX = '\\\\?\\'


def use_long_paths():
    """Stage downloads under an extended-length temp path so deep bundles may exceed MAX_PATH."""
    import tempfile
    import scp

    temp = os.path.abspath(tempfile.gettempdir())
    if not temp.startswith(EXTENDED_PREFIX) and not temp.startswith('\\\\'):
        tempfile.tempdir = EXTENDED_PREFIX + temp

    # Windows skips separator normalization for extended-length paths, but dump.py joins
    # POSIX bundle paths such as 'Frameworks/X.framework/X'. '/' can never be part of a
    # Windows file name, so converting it is always correct.
    join = os.path.join

    def long_path_join(path, *paths):
        result = join(path, *paths)
        if isinstance(result, str) and result.startswith(EXTENDED_PREFIX):
            result = result.replace('/', '\\')
        return result

    os.path.join = long_path_join

    class LongPathSCPClient(scp.SCPClient):
        def get(self, remote_path, local_path='', *args, **kwargs):
            # dump.py passes 'Payload/'; '/' is literal in extended-length paths, so scp
            # would not see a directory and would write the file over it instead.
            if isinstance(local_path, str) and local_path.startswith(EXTENDED_PREFIX):
                local_path = local_path.rstrip('/\\')
            return super().get(remote_path, local_path, *args, **kwargs)

    scp.SCPClient = LongPathSCPClient


def main():
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    if sys.platform == 'win32':
        use_long_paths()
    fake_tqdm = types.ModuleType('tqdm')
    fake_tqdm.tqdm = ProgressBar
    sys.modules['tqdm'] = fake_tqdm
    argv = sys.argv[1:]
    password = os.environ.pop('FRIDA_DUMP_SSH_PASSWORD', None)
    if password is not None:
        argv += ['-P', password]
    sys.argv = [DUMP_PY] + argv
    runpy.run_path(DUMP_PY, run_name='__main__')


if __name__ == '__main__':
    main()
