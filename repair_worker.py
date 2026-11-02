#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decrypt FairPlay-encrypted files of an installed app on the device, from inside the app's process.

Runs as a child process with the frida version that matches the device (see frida_versions.py),
so the GUI never loads frida itself.

Usage: repair_worker.py HOST:PORT JOBS.json OUTDIR (--pid PID | --bundle BUNDLE_ID)

JOBS.json: [{"id": "0", "path": "/path/on/device/X.appex/X",
             "slices": [{"offset": .., "cryptoff": .., "cryptsize": .., "cryptid": .., "cpu": .., "subtype": ..}]}]
For every slice that decrypts, OUTDIR/<id>_<slice index>.bin holds the decrypted range.
Prints JSON lines prefixed with @@: {"type": "attached", "pid": ..}, {"type": "slice", "id": .., "index": ..,
"ok": true} or {"ok": false, "error": ..}, and {"type": "error", "error": ..} when nothing can be done.
"""

import argparse
import json
import os
import sys

AGENT = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'repair_agent.js')
CHUNK = 4 * 1024 * 1024
PREFIX = '@@'


def emit(kind, **data):
    data['type'] = kind
    sys.stdout.write(PREFIX + json.dumps(data, ensure_ascii=False) + '\n')
    sys.stdout.flush()


def attach(device, pid, bundle):
    """Attach to the app: the running pid if it is still alive, otherwise launch it again."""
    if pid:
        try:
            return device.attach(pid), pid
        except Exception as error:  # it exited or crashed after it was dumped
            emit('log', text='attach to {} failed ({}); launching the app again'.format(pid, error))
    if not bundle:
        raise RuntimeError('the app is not running and no bundle ID was given')
    # Left suspended: the kernel finds the keys from the files themselves, so none of the app's
    # code has to run, and apps that crash on launch can still be repaired. The caller kills it.
    pid = device.spawn([bundle])
    return device.attach(pid), pid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('address')
    parser.add_argument('jobs')
    parser.add_argument('outdir')
    parser.add_argument('--pid', type=int, default=0)
    parser.add_argument('--bundle', default='')
    args = parser.parse_args()
    with open(args.jobs, encoding='utf-8') as handle:
        jobs = json.load(handle)
    try:
        import frida
        device = frida.get_device_manager().add_remote_device(args.address)
        session, pid = attach(device, args.pid, args.bundle)
        emit('attached', pid=pid, frida=frida.__version__)
        with open(AGENT, encoding='utf-8') as handle:
            script = session.create_script(handle.read())
        script.load()
        api = getattr(script, 'exports_sync', None) or script.exports
    except Exception as error:
        emit('error', error='{}: {}'.format(type(error).__name__, error))
        return 1
    for job in jobs:
        for index, item in enumerate(job['slices']):
            target = os.path.join(args.outdir, '{}_{}.bin'.format(job['id'], index))
            try:
                handle_id = api.decrypt(job['path'], item['offset'], item['cryptoff'], item['cryptsize'],
                                        item['cryptid'], item['cpu'], item['subtype'])
                try:
                    with open(target, 'wb') as out:
                        for start in range(0, item['cryptsize'], CHUNK):
                            out.write(api.read(handle_id, start, min(CHUNK, item['cryptsize'] - start)))
                finally:
                    api.release(handle_id)
                emit('slice', id=job['id'], index=index, ok=True)
            except Exception as error:
                try:
                    os.remove(target)
                except OSError:
                    pass
                emit('slice', id=job['id'], index=index, ok=False, error=str(error))
    try:
        script.unload()
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    sys.exit(main())
