#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Get decrypted copies of FairPlay-encrypted files of an installed app, without running its code.

Runs as a child process with the frida version that matches the device (see frida_versions.py),
so the GUI never loads frida itself.

Usage: repair_worker.py HOST:PORT JOBS.json OUTDIR --method mremap|memory --bundle ID [--pid PID]
                        [--no-launch]

  mremap  iOS 15 and earlier: mremap_encrypted in frida-server's own process.
  memory  iOS 16 and later: the system loads the code and it is read from memory. The main
          executable comes from the app spawned suspended; app extensions are started through
          NSExtension from a system process and stopped by spawn gating before they run.
          Frameworks come last: the app is let start without its UI (its initializers run) and
          each one is loaded into it.
          --pid reuses the running app, which then also looks extensions up; --no-launch says the
          app must not run (finishing a direct decryption rather than a dump).

JOBS.json: [{"id": "0", "path": "/path/on/device/X.app/PlugIns/E.appex/E", "suffix": "/X.app/PlugIns/E.appex/E",
             "kind": "main|appex|framework|watch|other", "extension": "bundle ID of the appex or null",
             "slices": [{"offset", "cryptoff", "cryptsize", "cryptid", "cpu", "subtype"}]}]
For every slice that is decrypted, OUTDIR/<id>_<slice index>.bin holds the decrypted range.
Prints JSON lines prefixed with @@: {"type": "slice", "id", "index", "ok", "error"},
{"type": "spawned", "pid"} for processes it left to be closed, {"type": "running_app"} when the
app is let run its initializers (for frameworks), {"type": "log", "text"},
{"type": "alive"} while a long step makes progress, and {"type": "error", "error"} when nothing
can be done. Errors starting with "unsupported:" name a
file or slice the method cannot handle (watch, other, slice, extension).
"""

import argparse
import json
import os
import sys
import threading
import time

AGENT = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'repair_agent.js')
CHUNK = 4 * 1024 * 1024
PREFIX = '@@'
# Processes that look extensions up for the system; each sees only some kinds of extension.
# Settings (started fresh, then closed) sees Safari content blockers and web extensions. The app
# itself comes last: asked while it runs, it often does not answer until Frida times out.
EXTENSION_HOSTS = ('SpringBoard', 'AuthenticationServicesAgent', 'spawn:com.apple.Preferences', 'app')
GATE_TIMEOUT = 15
LOAD_ATTEMPTS = 5  # a framework that does not load at once is tried again, a second apart
ALIVE_EVERY = 10  # seconds between "alive" events, so the GUI can tell slow from stuck
_last_emit = [0.0]


def emit(kind, **data):
    data['type'] = kind
    sys.stdout.write(PREFIX + json.dumps(data, ensure_ascii=False) + '\n')
    sys.stdout.flush()
    _last_emit[0] = time.monotonic()


def alive():
    """Tell the GUI the worker is still getting somewhere (it kills a worker that stays silent)."""
    if time.monotonic() - _last_emit[0] >= ALIVE_EVERY:
        emit('alive')


def load_agent(session):
    with open(AGENT, encoding='utf-8') as handle:
        script = session.create_script(handle.read())
    script.load()
    return getattr(script, 'exports_sync', None) or script.exports


def clean(error):
    """First line of an error, without the 'Error: ' a JavaScript exception starts with."""
    text = error.splitlines()[0] if error else ''
    return text[len('Error: '):] if text.startswith('Error: ') else text


def describe(error):
    return '{}: {}'.format(type(error).__name__, error)


def belongs_to(identifier, bundle):
    """Whether a spawn's identifier is the app with this bundle ID or one of its extensions."""
    return bool(bundle) and (identifier == bundle or (identifier or '').startswith(bundle + '.'))


def write_range(target, size, read):
    with open(target, 'wb') as out:
        for start in range(0, size, CHUNK):
            out.write(read(start, min(CHUNK, size - start)))
            alive()


def same_cpu(image, item):
    return (image['cpu'] & 0xFFFFFFFF) == (item['cpu'] & 0xFFFFFFFF) and \
        (image['subtype'] & 0xFFFFFF) == (item['subtype'] & 0xFFFFFF)


class Worker:
    def __init__(self, args):
        import frida
        self.frida = frida
        self.args = args
        self.device = frida.get_device_manager().add_remote_device(args.address)
        # A crashed frida-server would leave every call hanging; the caller then closes what was reported.
        self.device.on('lost', lambda *a: (emit('error', error='lost the connection to frida-server'), os._exit(3)))
        self.app_pid = args.pid or 0
        self.app_running = bool(args.pid) and not args.no_launch  # only a running app looks extensions up
        self.app_api = None
        self.hosts = {}        # host -> agent, injected once
        # The running app hosts lookups only when it was already running (finishing a dump).
        self.host_order = [h for h in EXTENSION_HOSTS if h != 'app' or self.app_running]

    def result(self, job, index, error=None, target=None):
        if error:
            if target:
                try:
                    os.remove(target)
                except OSError:
                    pass
            emit('slice', id=job['id'], index=index, ok=False, error=clean(error))
        else:
            emit('slice', id=job['id'], index=index, ok=True)

    def fail_all(self, job, error):
        for index in range(len(job['slices'])):
            self.result(job, index, error)

    def target(self, job, index):
        return os.path.join(self.args.outdir, '{}_{}.bin'.format(job['id'], index))

    # ---------------------------------------------------------------- mremap
    def run_mremap(self, jobs):
        try:
            api = load_agent(self.device.attach(0))  # frida-server itself: no app has to run
        except Exception as error:
            # Not the app instead: it runs in a sandbox that cannot open the copies made for it, and starting
            # apps is what this method avoids. The caller restarts frida-server and tries again.
            message = 'frida-server did not respond ({})'.format(clean(str(error)))
            for job in jobs:
                self.fail_all(job, message)
            return
        for job in jobs:
            # 64-bit slices first: the original path of a file serves one cputype only (the first to ask), and
            # the 64-bit one is what a 64-bit device runs.
            for index, item in sorted(enumerate(job['slices']), key=lambda pair: not pair[1]['cpu'] & 0x01000000):
                target = self.target(job, index)
                try:
                    path = item.get('path', job['path'])
                    try:
                        used = api
                        try:
                            handle = used.decrypt(path, item['offset'], item['cryptoff'], item['cryptsize'],
                                                  item['cryptid'], item['cpu'], item['subtype'])
                        except Exception as error:
                            # Some files (some app extensions) cannot be decrypted from a private copy (errno 12)
                            # though they can from where they are installed.
                            if 'errno 12' not in str(error) or path == job['path']:
                                raise
                            handle = used.decrypt(job['path'], item['offset'], item['cryptoff'], item['cryptsize'],
                                                  item['cryptid'], item['cpu'], item['subtype'])
                    except Exception as error:
                        # A 32-bit slice not aligned to the 64-bit page size (16 KB) can only be mapped by a
                        # 32-bit process: the app itself (spawned suspended, none of its code runs).
                        if 'errno 22' not in str(error) or item['cpu'] & 0x01000000:
                            raise
                        used = self.app()
                        handle = used.decrypt(job['path'], item['offset'], item['cryptoff'], item['cryptsize'],
                                              item['cryptid'], item['cpu'], item['subtype'])
                    try:
                        write_range(target, item['cryptsize'], lambda start, size: used.read(handle, start, size))
                    finally:
                        used.release(handle)
                    self.result(job, index)
                except Exception as error:
                    self.result(job, index, str(error), target)

    def app(self):
        """Agent in the app: the running one, else spawned and left suspended (none of its code runs)."""
        if self.app_api is None:
            session = None
            if self.app_pid:
                try:
                    session = self.device.attach(self.app_pid)
                except Exception as error:  # it exited after it was dumped
                    emit('log', text='attach to {} failed ({}); spawning the app'.format(self.app_pid, error))
                    self.app_running = False
            if session is None:
                self.app_pid = self.device.spawn([self.args.bundle])
                emit('spawned', pid=self.app_pid)
                session = self.device.attach(self.app_pid)
            self.app_api = load_agent(session)
        return self.app_api

    # ---------------------------------------------------------------- memory
    def read_image(self, api, job):
        """Copy the loaded slice of job's image out of a process; the other slices are not loaded."""
        image = api.image_base(job['suffix'])
        for index, item in enumerate(job['slices']):
            target = self.target(job, index)
            if image is None:
                self.result(job, index, 'image not loaded in the process')
            elif not same_cpu(image, item):
                self.result(job, index, 'unsupported:slice')
            else:
                try:
                    write_range(target, item['cryptsize'],
                                lambda start, size: api.read_at(image['base'], item['cryptoff'] + start, size))
                    self.result(job, index)
                except Exception as error:
                    self.result(job, index, str(error), target)

    def run_memory(self, jobs):
        frameworks = []
        for job in jobs:
            if job['kind'] == 'main':
                try:
                    self.read_image(self.app(), job)
                except Exception as error:
                    self.fail_all(job, describe(error))
            elif job['kind'] == 'appex' and job.get('extension'):
                self.extension(job)
            elif job['kind'] == 'framework':
                frameworks.append(job)  # last: the app has to run for them
            else:
                self.fail_all(job, 'unsupported:' + job['kind'])
        if frameworks:
            self.frameworks(frameworks)

    def frameworks(self, jobs):
        """Frameworks are decrypted only when loaded, which needs the app past dyld's setup. An app
        that is not running already is let start with UIApplicationMain replaced: it never shows its
        UI, but its initializers run (so this comes after everything that needs no code to run)."""
        try:
            api = self.app()
            if not self.app_running:
                if not api.hook_app_main():
                    raise RuntimeError('UIApplicationMain not found in the app')
                emit('running_app')
                self.device.resume(self.app_pid)
                self.app_running = True
        except Exception as error:
            for job in jobs:
                self.fail_all(job, describe(error))
            return
        for job in jobs:
            alive()
            try:
                for attempt in range(LOAD_ATTEMPTS):
                    try:
                        api.load_image(job['path'])
                        break
                    except Exception:
                        if attempt == LOAD_ATTEMPTS - 1:
                            raise
                        time.sleep(1)  # dyld may still be setting the app up
                self.read_image(api, job)
            except Exception as error:
                self.fail_all(job, describe(error))

    def host(self, name):
        """Agent in an extension host, injected once."""
        if name not in self.hosts:
            if name == 'app':
                session = self.device.attach(self.app_pid)
            elif name.startswith('spawn:'):
                pid = self.device.spawn([name[6:]])
                emit('spawned', pid=pid)
                session = self.device.attach(pid)
                self.device.resume(pid)
                time.sleep(3)  # it looks extensions up once it has started
            else:
                session = self.device.attach(name)
            self.hosts[name] = load_agent(session)
        return self.hosts[name]

    @staticmethod
    def detach(session):
        """Let go of a process; the caller kills every pid reported as spawned, over SSH, because
        killing a gated process through Frida has crashed frida-server 17 (SIGSEGV) on iOS 16."""
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass

    def extension(self, job):
        last_error = 'unsupported:extension'
        for host in list(self.host_order):
            pid = None
            alive()
            for attempt in (1, 2):  # a host occasionally drops the connection; try it once more
                try:
                    pid = self.catch_extension(host, job)
                    break
                except Exception as error:
                    self.hosts.pop(host, None)
                    last_error = describe(error)
                    if 'timeout' in last_error.lower():
                        # A host that hung once hangs again: leave it out for the other extensions.
                        self.host_order.remove(host)
                        break
            if pid is None:
                continue
            # An app's extensions are mostly of a kind the same host knows: ask it first next time.
            self.host_order.remove(host)
            self.host_order.insert(0, host)
            session = None
            try:
                session = self.device.attach(pid)
                self.read_image(load_agent(session), job)
            except Exception as error:
                self.fail_all(job, describe(error))
            finally:
                self.detach(session)
            return
        self.fail_all(job, last_error)

    def catch_extension(self, host, job):
        """Start job's extension from host with spawn gating on; its pid, still suspended, or None."""
        api = self.host(host)
        caught = {}
        kept = set()
        gated = threading.Event()
        answered = threading.Event()

        def on_spawn(spawn):
            if spawn.identifier == job['extension'] and 'pid' not in caught:
                caught['pid'] = spawn.pid
                emit('spawned', pid=spawn.pid)  # closed by the caller too, should this worker die
                gated.set()
            elif belongs_to(spawn.identifier, self.args.bundle):
                emit('spawned', pid=spawn.pid)  # more of the app: left suspended so none of it runs
                kept.add(spawn.pid)
            else:
                try:
                    self.device.resume(spawn.pid)  # anything else the system starts meanwhile
                except Exception:
                    pass

        def launch():
            try:
                caught['found'] = api.launch_extension(job['extension'])['found']
            except Exception as error:
                caught['error'] = error
            answered.set()

        self.device.on('spawn-added', on_spawn)
        self.device.enable_spawn_gating()
        try:
            threading.Thread(target=launch, daemon=True).start()
            deadline = time.monotonic() + GATE_TIMEOUT
            # Until the extension is caught, the host says it does not know it, or time runs out.
            while not gated.is_set() and time.monotonic() < deadline:
                if answered.is_set() and not caught.get('found'):
                    break
                gated.wait(0.1)
        finally:
            self.device.disable_spawn_gating()
            self.device.off('spawn-added', on_spawn)
            for spawn in self.device.enumerate_pending_spawn():
                if spawn.pid != caught.get('pid') and spawn.pid not in kept \
                        and not belongs_to(spawn.identifier, self.args.bundle):
                    try:
                        self.device.resume(spawn.pid)
                    except Exception:
                        pass
        if 'error' in caught and 'pid' not in caught:
            raise caught['error']
        return caught.get('pid')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('address')
    parser.add_argument('jobs')
    parser.add_argument('outdir')
    parser.add_argument('--method', choices=('mremap', 'memory'), default='mremap')
    parser.add_argument('--bundle', default='')
    parser.add_argument('--pid', type=int, default=0)
    parser.add_argument('--no-launch', action='store_true')
    args = parser.parse_args()
    with open(args.jobs, encoding='utf-8') as handle:
        jobs = json.load(handle)
    try:
        worker = Worker(args)
        if args.method == 'mremap':
            worker.run_mremap(jobs)
        else:
            worker.run_memory(jobs)
    except Exception as error:
        emit('error', error=describe(error))
        return 1
    return 0


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    sys.exit(main())
