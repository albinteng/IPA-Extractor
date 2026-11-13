# -*- coding: utf-8 -*-
"""Worker mode of the released program: `ipa_extractor --worker NAME ARGS...` runs one of the helper scripts.

From source, Frida runs in a child process of the tool's Python with the chosen version's folder on PYTHONPATH. The
released program has no Python to start, so it starts itself: this does what `python -u NAME.py ARGS` would do. The
frida folder is added to the import path here, since a compiled program does not read PYTHONPATH.
"""

import os
import sys

import dump_worker
import frida_probe
import repair_worker

WORKERS = {'dump_worker': dump_worker.main, 'frida_probe': frida_probe.main, 'repair_worker': repair_worker.main}


def run(name, argv):
    if name not in WORKERS:
        print('unknown worker: ' + name, file=sys.stderr)
        return 2
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    for folder in reversed([p for p in os.environ.get('PYTHONPATH', '').split(os.pathsep) if p]):
        sys.path.insert(0, folder)
    sys.argv = [name + '.py'] + list(argv)
    return WORKERS[name]() or 0
