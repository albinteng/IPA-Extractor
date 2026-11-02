#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check a remote frida-server from a child process, so the GUI never loads frida itself.

Usage: frida_probe.py HOST:PORT [--wait SECONDS]
Prints one JSON line: {"ok": true, "frida": "<loaded frida version>", "os": "<device OS>"}
or {"ok": false, "frida": ..., "error": "..."}. --wait keeps retrying until frida-server answers
(used right after it was killed and launchd is respawning it).
"""

import argparse
import json
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('address')
    parser.add_argument('--wait', type=float, default=0)
    args = parser.parse_args()
    try:
        import frida
    except Exception as error:
        print(json.dumps({'ok': False, 'frida': None, 'error': 'cannot import frida: {}'.format(error)}))
        return 1
    manager = frida.get_device_manager()
    deadline = time.monotonic() + args.wait
    while True:
        try:
            try:
                manager.remove_remote_device(args.address)
            except Exception:
                pass
            device = manager.add_remote_device(args.address)
            parameters = device.query_system_parameters()
            os_info = parameters.get('os') or {}
            print(json.dumps({'ok': True, 'frida': frida.__version__,
                              'os': '{} {}'.format(os_info.get('name', ''), os_info.get('version', '')).strip()}))
            return 0
        except Exception as error:
            if time.monotonic() >= deadline:
                print(json.dumps({'ok': False, 'frida': frida.__version__, 'error': str(error)}))
                return 1
            time.sleep(2)


if __name__ == '__main__':
    sys.exit(main())
