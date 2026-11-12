#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The part of IPA Extractor that needs no window: settings, the SSH connection, and DumpEngine, which copies and
decrypts apps. The window (ipa_extractor.py) and the command line (ipa_cli.py) both build on it; it never imports tkinter."""

__version__ = '4.0'
APP_NAME = 'IPA Extractor'

import contextlib
import importlib.util
import json
import os
import platform
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

try:
    import paramiko
except ImportError:  # the window offers to install it; the command line says how
    paramiko = None

import app_info
import device_apps
import frida_versions
import ipa_extract
import ipa_repair
import ipa_verify
import i18n
import native_decrypt
import remote
import usbmux

script_dir = os.path.dirname(os.path.realpath(__file__))
WORKER = os.path.join(script_dir, 'dump_worker.py')
REPAIR_WORKER = os.path.join(script_dir, 'repair_worker.py')
REPAIR_STALL = 90     # seconds without output after which repair_worker.py counts as hung
REPAIR_RETRIES = 3    # times frida-server is restarted for one app's files, while each try gets further
MEMORY_FROM_IOS = 16  # mremap_encrypted is refused from iOS 16 on; the system loads the code instead
PROBE = os.path.join(script_dir, 'frida_probe.py')
PROBE_TIMEOUT = 30
ASSETS = os.path.join(script_dir, 'assets')
DEFAULT_DUMP_DIR = os.path.join(os.path.dirname(script_dir), 'frida-ios-dump')
IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
FRIDA_IOS_DUMP_URL = 'https://github.com/AloneMonkey/frida-ios-dump'
FRIDA_SERVER_PATHS = ('/usr/sbin/frida-server', '/var/jb/usr/sbin/frida-server')

THEME_SYSTEM, THEME_LIGHT, THEME_DARK, THEME_BLACK = 'system', 'light', 'dark', 'black'
THEMES = (THEME_SYSTEM, THEME_LIGHT, THEME_DARK, THEME_BLACK)


def theme_setting(value):
    """A theme name from a settings file or a variable; anything unknown is the default, the system's."""
    return value if value in THEMES else THEME_SYSTEM


def system_theme():
    """THEME_DARK when the system is set to dark, otherwise THEME_LIGHT (also when it cannot be told)."""
    def run(*command):
        try:
            if shutil.which(command[0]) is None:
                return ''
            done = subprocess.run(command, capture_output=True, text=True, timeout=3, creationflags=NO_WINDOW)
            return done.stdout.lower() if done.returncode == 0 else ''
        except (OSError, subprocess.SubprocessError):
            return ''
    dark = False
    try:
        if IS_WINDOWS:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as key:
                dark = winreg.QueryValueEx(key, 'AppsUseLightTheme')[0] == 0
        elif IS_MACOS:
            dark = 'dark' in run('defaults', 'read', '-g', 'AppleInterfaceStyle')
        else:
            dark = ('dark' in run('gsettings', 'get', 'org.gnome.desktop.interface', 'color-scheme')
                    or 'dark' in run('gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme')
                    or 'dark' in run('kreadconfig6', '--group', 'General', '--key', 'ColorScheme')
                    or 'dark' in run('kreadconfig5', '--group', 'General', '--key', 'ColorScheme'))
    except (OSError, ImportError, ValueError):
        dark = False
    return THEME_DARK if dark else THEME_LIGHT


def resolve_theme(value):
    """The theme to draw: a theme setting, with the system's choice looked up for THEME_SYSTEM."""
    value = theme_setting(value)
    return system_theme() if value == THEME_SYSTEM else value


# How the tool reaches the device: SSH over the network, or SSH carried through the USB cable (usbmux.py).
CONNECTION_SSH, CONNECTION_USB = 'ssh', 'usb'
CONNECTIONS = (CONNECTION_SSH, CONNECTION_USB)


def connection_setting(value):
    """A connection name from a settings file or a variable; anything unknown is the default, SSH."""
    return value if value in CONNECTIONS else CONNECTION_SSH


DEFAULT_FONT_SIZE = 13 if IS_MACOS else 10

# Settings files keep only values that differ from these, so new defaults reach existing users.
# Ways to make a decrypted IPA (the dump_method setting). The first two need frida-server.
METHOD_FRIDA_DIRECT = 'frida_direct'        # R4: decrypt the installed files, the app never runs
METHOD_FRIDA_IOS_DUMP = 'frida_ios_dump'    # run the app and dump it with frida-ios-dump
METHOD_NATIVE = 'native'                    # the same as R4 with helper programs on the device, no Frida
DUMP_METHODS = (METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP, METHOD_NATIVE)

DEFAULTS = dict(
    host='', port=22, user='', frida_port=27042,
    user_only=True, non_apple=False, encrypted_only=False,
    outdir=os.path.join(script_dir, 'output'), extract_dir=os.path.join(script_dir, 'output_encrypted'),
    separate_dirs=False, name_decrypted=app_info.DEFAULT_DECRYPTED_NAME, name_original=app_info.DEFAULT_ORIGINAL_NAME,
    dump_dir=DEFAULT_DUMP_DIR, close_after=True, restart_frida=True, repair=True, dump_method=METHOD_NATIVE,
    frida_method=METHOD_FRIDA_DIRECT, native_helper=native_decrypt.AUTO,
    lang=i18n.AUTO, font='', font_size=DEFAULT_FONT_SIZE, theme=THEME_SYSTEM, connection=CONNECTION_SSH, usb_device='',
)


def _writable(folder):
    try:
        with tempfile.TemporaryFile(dir=folder):
            return True
    except OSError:
        return False


# Portable: settings stay beside the tool and move with its folder. The home folder is the
# fallback when the tool's folder is read-only (e.g. under Program Files).
CONFIG_PATH = (os.path.join(script_dir, 'settings.json') if _writable(script_dir)
               else os.path.join(os.path.expanduser('~'), '.ipa_extractor.json'))
PYPI_FRIDA_URL = 'https://pypi.org/pypi/frida/json'
PROGRESS_INTERVAL = 0.2      # seconds between progress updates while streaming an IPA
# frida-server needs a few seconds to be respawned by launchd after it is killed.
RESTART_GRACE, RESTART_TIMEOUT, RESTART_POLL = 3, 45, 2
BASE_PACKAGES = ['paramiko>=3', 'cryptography'] + (['sv-ttk'] if sys.platform.startswith('linux') else [])
ERROR_PATTERNS = (
    ('preflight', 'failed preflight checks'),
    ('timeout', 'timeout was reached'),
    ('closed', 'connection is closed'),
    ('session', 'session is gone'),
    ('server', 'unable to connect to remote frida-server'),
    # Seen when the device was locked or the screen was off while Frida spawned the app.
    ('resume', 'error while resuming process'),
    ('path', 'filenotfounderror'),
)
# Errors after which frida-server itself may be wedged; restarting it usually recovers.
RESTART_ERRORS = ('timeout', 'closed', 'server')
RETRY_ERRORS = RESTART_ERRORS + ('session', 'resume')
MAX_CONSECUTIVE_FRIDA_ERRORS = 3
# dump.py's own agent timeout is 120 s, so silence beyond this means the worker is hung.
STALL_TIMEOUT = 150
# {type} of a decrypted IPA follows its verification result.
DUMP_KINDS = ipa_verify.all_types()


def pip_install(packages):
    """pip command line; outside a virtual environment packages go to the user's site-packages,
    which needs no administrator rights even when Python is installed for all users."""
    user = [] if sys.prefix != sys.base_prefix else ['--user']
    return [sys.executable, '-m', 'pip', 'install', '--upgrade'] + user + packages


def load_config():
    try:
        with open(CONFIG_PATH, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


class SSHTunnel:
    """Local TCP port forwarded to a port on the device through an SSH transport."""

    def __init__(self, transport, remote_port):
        self.transport = transport
        self.remote_port = remote_port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(16)
        self.local_port = self.server.getsockname()[1]
        self.closed = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed.is_set():
            try:
                client, peer = self.server.accept()
            except OSError:
                break
            try:
                channel = self.transport.open_channel(
                    'direct-tcpip', ('127.0.0.1', self.remote_port), peer, timeout=10)
            except Exception:
                client.close()
                continue
            threading.Thread(target=self._pipe, args=(client, channel), daemon=True).start()

    def _pipe(self, sock, channel):
        """Copy both ways with one thread per direction. select() on a paramiko channel makes paramiko
        build a socket pair per channel on Windows, which is where the SSH socket itself was seen failing."""
        sock.settimeout(1)
        channel.settimeout(1)

        def copy(read, write):
            try:
                while not self.closed.is_set():
                    try:
                        data = read(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    write(data)
            except Exception:
                pass
            finally:
                for end in (sock, channel):
                    try:
                        end.close()
                    except Exception:
                        pass

        threading.Thread(target=copy, args=(channel.recv, sock.sendall), daemon=True).start()
        copy(sock.recv, channel.sendall)

    def close(self):
        self.closed.set()
        for stop in (lambda: self.server.shutdown(socket.SHUT_RDWR), self.server.close):
            try:
                stop()  # shutdown wakes a thread blocked in accept() on Linux; close alone does not
            except OSError:
                pass


def probe_frida(version, address, wait=0, deep=False):
    """Ask frida_probe.py, running with frida `version`, whether frida-server at address answers.

    deep also makes it run a script inside frida-server, which is what decrypting needs.
    Returns (ok, detail): detail is the device OS on success, the error otherwise.
    """
    command = [frida_versions.python(version), '-u', PROBE, address] + (['--wait', str(wait)] if wait else []) \
        + (['--deep'] if deep else [])
    try:
        process = subprocess.run(command, env=frida_versions.env(version), stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, encoding='utf-8', errors='replace',
                                 timeout=PROBE_TIMEOUT + wait, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return False, 'frida.TransportError: timeout was reached'
    except OSError as error:
        return False, str(error)
    lines = [line for line in process.stdout.splitlines() if line.startswith('{')]
    try:
        result = json.loads(lines[-1])
    except (IndexError, ValueError):
        return False, (process.stdout + process.stderr).strip()[-500:] or 'exit code {}'.format(process.returncode)
    if result.get('frida') and result['frida'] != version:
        # The version folder is broken and another frida on sys.path was imported instead.
        return False, 'loaded frida {} instead of {}'.format(result['frida'], version)
    return bool(result.get('ok')), result.get('os') if result.get('ok') else result.get('error', '')


def dump_dir_status(path):
    """'empty', 'missing' (no dump.py/dump.js), 'no_bridge' (npm install not run) or 'ok'."""
    if not path:
        return 'empty'
    if not all(os.path.isfile(os.path.join(path, f)) for f in ('dump.py', 'dump.js')):
        return 'missing'
    # dump.py refuses to compile its agent without this package.
    if not os.path.isdir(os.path.join(path, 'node_modules', 'frida-objc-bridge')):
        return 'no_bridge'
    return 'ok'


def wheel_platform_pattern():
    """Regex matching wheel platform tags that install on this computer."""
    machine = platform.machine().lower()
    arm = machine in ('arm64', 'aarch64')
    if IS_WINDOWS:
        return r'win_arm64' if arm else r'win_amd64'
    if IS_MACOS:
        return r'macosx_\w+_(universal2|{})'.format('arm64' if arm else 'x86_64')
    # manylinux1_x86_64, manylinux_2_17_aarch64, ...
    return r'linux\w*_{}'.format('aarch64' if arm else 'x86_64')


def frida_releases():
    """Stable frida versions on PyPI, newest first, limited to ones with a wheel for this Python."""
    import urllib.request
    with urllib.request.urlopen(PYPI_FRIDA_URL, timeout=20) as response:
        releases = json.load(response)['releases']
    python_tag = 'cp{}{}'.format(*sys.version_info[:2])
    platform_tag = re.compile(wheel_platform_pattern())

    def installable(files):
        wheels = [f['filename'] for f in files if f.get('packagetype') == 'bdist_wheel' and not f.get('yanked')]
        return any(platform_tag.search(w) and ('abi3' in w or python_tag in w) for w in wheels)

    versions = [v for v, files in releases.items() if re.fullmatch(r'\d+\.\d+\.\d+', v) and installable(files)]
    versions += frida_versions.legacy_versions(releases)
    return sorted(versions, key=lambda v: tuple(int(n) for n in v.split('.')), reverse=True)


def frida_server_status(client):
    """Return (frida-server version or None, whether it is running) on the device."""
    # iOS 8 has no ps: launchctl then tells whether the frida-server job has a PID.
    _, found = remote.run(client, 'for p in {}; do [ -x "$p" ] && "$p" --version && break; done; '
                                  '{{ ps -A -o comm= 2>/dev/null | grep frida-server; '
                                  "launchctl list 2>/dev/null | grep -E '^[0-9]+[[:space:]].*frida'; }} "
                                  '| grep -c .'.format(' '.join(FRIDA_SERVER_PATHS)))
    lines = [line.strip() for line in found.splitlines() if line.strip()]
    version = lines[0] if len(lines) > 1 and re.match(r'^\d+\.\d+', lines[0]) else None
    running = bool(lines) and lines[-1].isdigit() and int(lines[-1]) > 0
    return version, running


major = frida_versions.major


def ios_major(device_os):
    """12 for 'iPhone OS 12.4', None when unknown."""
    match = re.search(r'(\d+)(?:\.\d+)*\s*$', device_os or '')
    return int(match.group(1)) if match else None


def decrypt_method(device_os):
    """How repair_worker.py decrypts on this device: mremap (iOS 15 and earlier) or memory."""
    major_version = ios_major(device_os)
    return 'memory' if major_version is not None and major_version >= MEMORY_FROM_IOS else 'mremap'


def per_slice_copies(options):
    """Whether each slice of a fat file needs a copy of its own: only iOS 8 and 9 were seen to set up decryption
    for just the first cputype that asks (later systems keep working from the installed file)."""
    major_version = ios_major(options.get('ios'))
    return options['method'] == 'mremap' and major_version is not None and major_version < 10


def dump_method_setting(value):
    """The saved decryption method, or the default when it is missing or unknown."""
    return value if value in DUMP_METHODS else DEFAULTS['dump_method']


def frida_method_setting(value, method):
    """The Frida mode to return to when the user switches from the native helpers to Frida: the saved one, else the
    active method if it is one, else the direct mode."""
    frida = (METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP)
    return value if value in frida else method if method in frida else METHOD_FRIDA_DIRECT


def frida_launchd_pids(launchctl_list):
    """PIDs of the frida-server launchd jobs in `launchctl list` output (PID, status, label)."""
    pids = []
    for line in launchctl_list.splitlines():
        parts = line.split()
        if len(parts) >= 3 and 'frida' in parts[2] and parts[0].isdigit():
            pids.append(int(parts[0]))
    return pids


def gated_launches(ps_output, bundle=None):
    """Launches left suspended by Frida's spawn gating, from `ps -A -o pid=,stat=,args=` output.

    Returns (pids to kill: launches of bundle or its extensions, pids to resume: everything else).
    """
    kill, resume = [], []
    # The app's launch shows as UIKitApplication:<bundle>[...], an extension's as <bundle>.<name>...;
    # com.foo must not match com.foobar.
    own = re.compile(r'(?:^|:){}(?:$|[.\[(])'.format(re.escape(bundle))) if bundle else None
    for line in ps_output.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].startswith('T'):
            continue
        args = parts[2].split()
        if os.path.basename(args[0]) != 'xpcproxy':
            continue
        if own and any(own.search(arg) for arg in args[1:]):
            kill.append(int(parts[0]))
        else:
            resume.append(int(parts[0]))
    return kill, resume


def repair_failure(error, job=None):
    """(reason key, error) for a file repair_worker.py could not decrypt."""
    if error.startswith('unsupported:'):
        # iOS 16 and later: only what the system loads on this device can be read (see repair_worker.py).
        return 'repair_unsupported_' + error.split(':', 1)[1], ''
    if job is not None and '(errno 1)' in error:
        # A 32-bit slice older than another slice of the same file that was decrypted: the device runs the
        # newer one (an arm64 device prefers armv7s over armv7 over armv6) and the kernel refuses the older.
        done = [job.slices[i] for i in job.done]
        for index in job.slice_errors:
            slice_ = job.slices[index]
            if slice_.cpu == 12 and any(other.is_64bit or other.subtype > slice_.subtype for other in done):
                return 'repair_oldslice', error
    if '(errno 12)' in error:
        return 'repair_nomem', error
    # errno 1 with nothing else to explain it: the kernel has no key for the file, typically because the app
    # was not installed with this device's Apple ID (e.g. from an already decrypted or re-signed IPA).
    if '(errno 1)' in error:
        return 'repair_nokey', error
    return 'repair_failed', error


def is_user_app(path):
    return '/containers/bundle/application/' in (path or '').lower()


def is_apple_app(bundle):
    return bundle.lower().startswith('com.apple.')


def natural_key(text):
    """Sort key that orders numbers by value, so version 9.1 comes before 10.2."""
    return [int(part) if part.isdigit() else part for part in re.split(r'(\d+)', str(text).lower())]


def classify_error(message):
    message = message.lower()
    return next((kind for kind, needle in ERROR_PATTERNS if needle in message), None)


def download_frida_ios_dump(target, log):
    """Clone frida-ios-dump with git, or fall back to GitHub's zip archive."""
    if shutil.which('git'):
        process = subprocess.run(['git', 'clone', '--depth', '1', FRIDA_IOS_DUMP_URL + '.git', target],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                 encoding='utf-8', errors='replace', creationflags=NO_WINDOW)
        for line in process.stdout.splitlines():
            if line.strip():
                log(line.strip())
        if process.returncode == 0:
            return
        if os.path.isdir(target) and not os.listdir(target):
            os.rmdir(target)
    import io
    import urllib.request
    import zipfile
    url = FRIDA_IOS_DUMP_URL + '/archive/refs/heads/master.zip'
    log(url)
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    staging = target.rstrip('\\/') + '.download'
    archive.extractall(staging)
    top = os.path.join(staging, archive.namelist()[0].split('/')[0])
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    if os.path.isdir(target):
        os.rmdir(target)
    shutil.move(top, target)
    shutil.rmtree(staging, ignore_errors=True)


class Text:
    """A translatable message: key plus format arguments, rendered on demand."""

    def __init__(self, key, **params):
        self.key = key
        self.params = params


class Indented:
    """A message shown indented under the one before it."""

    def __init__(self, text):
        self.text = text


# Letters of the scripts whose words are not separated by spaces: Thai, Japanese kana and Chinese characters.
# Everything else (accented Latin, Cyrillic, Greek, Hangul, ...) is written in words.
def open_ssh(host, port, user, password, log):
    """A connected paramiko client; raises the error that ended the attempts.

    A device on Wi-Fi sometimes accepts the connection but sends no SSH banner, so one failure is retried;
    old devices that offer only ssh-rsa host keys get them enabled. log(Text) reports both.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    retried = False
    while True:
        try:
            client.connect(host, port, user, password, timeout=10, banner_timeout=15,
                           auth_timeout=15, look_for_keys=False, allow_agent=False)
            client.get_transport().set_keepalive(10)
            return client
        except paramiko.AuthenticationException:  # a wrong password will not get better
            client.close()
            raise
        except Exception as error:
            # Wait for the failed transport's thread: it must not outlive the connection that replaces it.
            failed = client.get_transport()
            client.close()
            if failed is not None:
                failed.join(5)
            # Old devices (iOS 8-era OpenSSH) offer only ssh-rsa host keys, which paramiko dropped.
            legacy = (isinstance(error, paramiko.SSHException) and 'host key' in str(error)
                      and remote.enable_legacy_host_key())
            if legacy:
                log(Text('log_ssh_legacy'))
            else:
                if retried:
                    raise
                retried = True
                log(Text('log_ssh_retry', error=error))
                time.sleep(2)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


def error_text(error):
    """A usbmux error as a translatable Text (its parts too); any other error as it is."""
    if isinstance(error, usbmux.UsbmuxError):
        return Text(error.key, **{name: error_text(value) for name, value in error.params.items()})
    return error


def open_device(connection, host, port, user, password, log, usb_device=''):
    """(client, address, tunnel): an SSH client for the device, over the network or through USB.

    address is the (host, port) SSH really connects to (the local end of the tunnel for USB), for programs that
    open their own SSH connection; close the tunnel (None for the network) after the client.
    """
    tunnel = None
    if connection_setting(connection) == CONNECTION_USB:
        tunnel = usbmux.UsbTunnel(usb_device, port)
        address = ('127.0.0.1', tunnel.local_port)
    else:
        address = (host, port)
    try:
        return open_ssh(address[0], address[1], user, password, log), address, tunnel
    except BaseException as error:
        reason = getattr(tunnel, 'last_error', None)
        if tunnel is not None:
            tunnel.close()
        if isinstance(reason, usbmux.UsbmuxError) and not isinstance(error, usbmux.UsbmuxError):
            raise reason from error     # not "no SSH banner", but why the device could not be reached
        raise


class DumpEngine:
    """What extracting and decrypting needs, without any window: the batch workers that copy an app off the device
    and decrypt it. The GUI and the command line both build on it.

    A subclass provides: ssh, apps, cancel_requested, current_process, tunnel, generation, frida_version,
    t() and render() for messages, and the callbacks post(func, *args) (the thread the output belongs to),
    log(text), set_status(bundle, text, tag), _set_overall(value, text), _set_verify(...) and _batch_finished(...).
    """

    def ssh_alive(self):
        """True while the SSH session a running batch depends on is usable."""
        client = self.ssh
        transport = client.get_transport() if client is not None else None
        return transport is not None and transport.is_active()

    def _abort_lost(self, jobs, index):
        """Mark the jobs from index on as skipped after SSH was lost; the batch stops."""
        self.post(self.log, Text('log_batch_ssh_lost', n=len(jobs) - index))
        for bundle, _ in jobs[index:]:
            self.post(self.set_status, bundle, Text('st_skipped_lost'), 'failed')

    def _extract_worker(self, jobs, outdir):
        succeeded = 0
        try:
            for index, (bundle, name) in enumerate(jobs):
                if not self.ssh_alive():
                    self._abort_lost(jobs, index)
                    break
                if self._extract_one(index, len(jobs), bundle, name, outdir):
                    succeeded += 1
        except Exception as error:  # keep the UI usable whatever happens
            self.post(self.log, Text('log_batch_error', error=error))
        finally:
            self.post(self._batch_finished, 'extract', outdir, succeeded, len(jobs), False)

    def _extract_one(self, index, total, bundle, name, outdir):
        """Extract one original IPA; True on success."""
        if self.cancel_requested.is_set():
            self.post(self.set_status, bundle, Text('st_cancelled'), 'failed')
            return False
        last = [0.0]

        def progress(done, size):
            now = time.monotonic()
            if now - last[0] < PROGRESS_INTERVAL:
                return
            last[0] = now
            fraction = done / size if size else 0
            self.post(self.set_status, bundle, Text('st_extracting', pct='{:.0f}'.format(fraction * 100)),
                      'running')
            self.post(self._set_overall, (index + fraction) / total * 100,
                      '{}/{}  {}'.format(index + 1, total, bundle))

        path = os.path.join(outdir, name + '.ipa')
        progress(0, 0)
        try:
            ipa_extract.extract_ipa(self.ssh, self.apps[bundle]['path'], path, progress,
                                    self.cancel_requested.is_set)
        except ipa_extract.Cancelled:
            self.post(self.set_status, bundle, Text('st_cancelled'), 'failed')
            return False
        except Exception as error:
            self.post(self.set_status, bundle, Text('st_failed', msg=error), 'failed')
            self.post(self.log, Text('log_failed', bundle=bundle, msg=error))
            return False
        self.post(self.set_status, bundle, Text('st_extracted'), 'done')
        self.post(self.log, Text('log_done', bundle=bundle, path=path))
        return True

    def _dump_worker(self, jobs, options):
        counts = dict(succeeded=0, partial=0, paused=False)
        try:
            self._dump_jobs(jobs, options, counts)
        except Exception as error:  # keep the UI usable whatever happens
            self.post(self.log, Text('log_batch_error', error=error))
        finally:
            self.post(self._batch_finished, 'dump', options['outdir'], counts['succeeded'], len(jobs),
                      counts['paused'], counts['partial'])

    def _dump_jobs(self, jobs, options, counts):
        total = len(jobs)
        consecutive_frida_errors = 0
        paused = False
        for index, (bundle, name) in enumerate(jobs):
            if self.cancel_requested.is_set():
                self.post(self.set_status, bundle, Text('st_cancelled'), 'failed')
                continue
            if paused:
                self.post(self.set_status, bundle, Text('st_skipped'), 'failed')
                continue
            if not self.ssh_alive():
                self._abort_lost(jobs, index)
                break
            for attempt in (1, 2):
                if options['direct']:
                    # Only SSH is involved: a copy that broke off (Wi-Fi, a stalled channel) is tried once more.
                    ok, message = self._copy_bundle(index, total, bundle, name, options)
                    kind = None
                    if ok or self.cancel_requested.is_set() or attempt == 2 or not self.ssh_alive():
                        break
                    self.post(self.log, Text('log_failed', bundle=bundle, msg=message))
                    self.post(self.log, Text('log_retry', bundle=bundle))
                    continue
                ok, message = self._dump_one(index, total, bundle, name, options)
                kind = None if ok else classify_error(message)
                if (ok or self.cancel_requested.is_set() or attempt == 2 or kind not in RETRY_ERRORS
                        or not self.ssh_alive()):
                    break
                if (kind in RESTART_ERRORS and options['restart_frida']
                        and not self._restart_frida_server(options, bundle)):
                    break
                self.post(self.log, Text('log_retry', bundle=bundle))
            if ok:
                consecutive_frida_errors = 0
                pid = options.pop('pid', None)
                ok = self._finish_dump(bundle, os.path.join(options['outdir'], name + '.ipa'), options, counts, pid)
                # The app dump.py ran is closed when asked; one the repair spawned never ran, so always.
                if pid is not None and options['close_after']:
                    self._close_app(bundle, pid)
                self._close_spawned(bundle, options)
                # Should frida-server have crashed while it held one, nothing reported it: never leave
                # the app or its extensions suspended (they would resume the next time frida-server dies).
                try:
                    for stopped in device_apps.suspended_pids(self.ssh, self.apps[bundle]['path']):
                        self._close_app(bundle, stopped)
                except Exception:
                    pass
                if ok:
                    counts['succeeded'] += 1
            elif self.cancel_requested.is_set():
                self.post(self.set_status, bundle, Text('st_cancelled'), 'failed')
            else:
                self.post(self.set_status, bundle,
                          Text('st_failed', msg=Text('err_' + kind) if kind else message), 'failed')
                self.post(self.log, Text('log_failed', bundle=bundle, msg=message))
                # One app that blocks Frida is normal; several in a row means the device is stuck,
                # and continuing would only fail every remaining app.
                consecutive_frida_errors = consecutive_frida_errors + 1 if kind in RESTART_ERRORS else 0
                if consecutive_frida_errors >= MAX_CONSECUTIVE_FRIDA_ERRORS:
                    paused = counts['paused'] = True

    def _finish_dump(self, bundle, path, options, counts, pid=None):
        """Verify a freshly decrypted IPA (R1), decrypt what is still encrypted on the device (R2),
        name it after the result and report it (R3).

        Runs on the dump thread; pid is the app dump.py launched, still running. False when the
        IPA turned out to be unusable.
        """
        failures = {}  # member -> (reason, error) for files the repair could not fix
        try:
            result = ipa_verify.verify_ipa(path)
            if result.encrypted and options['repair'] and not self.cancel_requested.is_set():
                failures = self._repair(bundle, path, result, options, pid)
                if not self.ssh_alive():
                    self.post(self.log, Text('log_conn_lost_partial', bundle=bundle))
                result = ipa_verify.verify_ipa(path)
            status = result.status
        except Exception as error:  # not a readable zip: dump.py wrote a broken IPA
            self.post(self.set_status, bundle, Text('st_failed', msg=Text('verify_error', error=error)), 'failed')
            self.post(self.log, Text('log_verify_failed', bundle=bundle, error=error))
            return False
        if status == ipa_verify.NO_MACHO:
            self.post(self.set_status, bundle, Text('st_failed', msg=Text('verify_no_macho')), 'failed')
            self.post(self.log, Text('log_failed', bundle=bundle, msg=Text('verify_no_macho')))
            return False
        final = os.path.join(options['outdir'], options['names'][bundle][result.type] + '.ipa')
        if final != path:
            try:
                os.replace(path, final)
                path = final
            except OSError as error:
                self.post(self.log, Text('log_rename_failed', path=final, error=error))
        # The user agreed to replace these; an older result under another name would be stale.
        for other in options['names'][bundle].values():
            stale = os.path.join(options['outdir'], other + '.ipa')
            if stale != path and os.path.exists(stale):
                try:
                    os.remove(stale)
                    self.post(self.log, Text('log_removed_stale', bundle=bundle, path=stale))
                except OSError as error:
                    self.post(self.log, Text('log_remove_failed', path=stale, error=error))
        files = [dict(file=ipa_verify.short_name(f.name), archs=', '.join(f.encrypted_archs) or '?',
                      reason=failures.get(f.name, (ipa_verify.reason(f), ''))[0],
                      error=f.error or failures.get(f.name, ('', ''))[1]) for f in result.encrypted]
        self.post(self._set_verify, bundle, status, len(result.files), files, result.type)
        self.post(self.log, Text('log_done', bundle=bundle, path=path))
        if status == ipa_verify.DECRYPTED:
            self.post(self.set_status, bundle, Text('st_done'), 'done')
            self.post(self.log, Text('log_verify_ok', bundle=bundle, n=len(result.files)))
            return True
        counts['partial'] += 1
        if status == ipa_verify.PARTIAL_32BIT:
            self.post(self.set_status, bundle, Text('st_done_partial32'), 'done')
        else:
            self.post(self.set_status, bundle, Text('st_partial', n=len(files)), 'partial')
        self.post(self.log, Text('log_verify_partial', bundle=bundle, n=len(files),
                                 total=len(result.files), status=status))
        for file in files:
            self.post(self.log, Indented(Text('log_verify_file', file=file['file'], archs=file['archs'],
                                              reason=self.reason_text(file))))
        return True

    def _repair(self, bundle, path, result, options, pid):
        """Decrypt the IPA's still-encrypted files on the device and patch them in (R2).

        Returns {member: (reason key, error)} for the files that stay encrypted.
        """
        jobs = ipa_repair.plan(result, self.apps[bundle]['path'], path)
        if not jobs:
            return {}
        if options['method'] == 'memory':
            # Reading memory needs the system to load the code, which it never does for a bundle
            # that requires a newer iOS than the device runs.
            device = ipa_repair.version_tuple(options['ios'])
            for job in jobs:
                if device and job.min_os and ipa_repair.version_tuple(job.min_os) > device:
                    job.error = ('unsupported_minos', job.min_os)
        self.post(self.set_status, bundle, Text('st_running', pct='100', stage=Text('stage_repair', n=len(jobs))),
                  'running')
        self.post(self.log, Text('log_repair_start', bundle=bundle, n=len(jobs)))
        try:
            sftp = self.ssh.open_sftp()
            try:
                ipa_repair.check_sizes(sftp, jobs, path)
            finally:
                sftp.close()
            with tempfile.TemporaryDirectory(prefix='ipa-repair-') as work:
                todo = [job for job in jobs if job.error is None]
                # Only the first cputype set up for a file works (iOS 8): each slice of a fat file gets its own copy.
                with self._private_copies(todo if per_slice_copies(options) else [], options):
                    if todo and options.get('native'):
                        self._run_native(bundle, todo, work, options)
                    elif todo:
                        self._run_repair_worker(bundle, todo, work, options, pid)
                    # frida-server sometimes crashes or stops responding: when asked, restart it (killing a
                    # crashed one is harmless) and try what it took down again, as long as that gets further.
                    for _ in range(0 if options.get('native') else REPAIR_RETRIES):
                        retry = [job for job in todo if not job.repaired and job.connection_lost()]
                        if not retry or not options['restart_frida'] or self.cancel_requested.is_set():
                            break
                        self.post(self.log, Text('log_repair_retry', bundle=bundle, n=len(retry)))
                        if not self._restart_frida_server(options, bundle):
                            break
                        # What the last try started would get in the way (the extension's host is spawned again).
                        self._close_spawned(bundle, options)
                        before = sum(len(job.done) for job in retry)
                        for job in retry:
                            job.reset()
                        self._run_repair_worker(bundle, retry, work, options, pid)
                        if sum(len(job.done) for job in retry) == before:
                            break
                    if (not options.get('native')
                            and any(job.connection_lost() for job in todo if not job.repaired)):
                        # frida-server died and was not restarted (or died again): whatever it held
                        # suspended must not stay so, frida-server's own relaunch included.
                        self._release_gated(options, bundle)
                    changed = ipa_repair.apply(path, jobs, work)
        except Exception as error:
            self.post(self.log, Text('log_repair_failed', bundle=bundle, error=error))
            return {job.member: ('repair_failed', str(error)) for job in jobs}
        failures = {}
        for job in jobs:
            if job.error:
                failures[job.member] = ('repair_' + job.error[0], job.error[1])
            elif not job.repaired:
                error = next(iter(job.slice_errors.values()), '')
                failures[job.member] = repair_failure(error, job)
        self.post(self.log, Text('log_repair_done', bundle=bundle, n=changed, total=len(jobs)))
        return failures

    @contextlib.contextmanager
    def _private_copies(self, jobs, options):
        """iOS 8 sets up decryption of a file for the first cputype that asks, and refuses the others until
        the file leaves the kernel's cache. For a file with several encrypted slices, give each slice a
        copy of its own (the executable and the SC_Info folder with its key) on the device."""
        # A folder name never used before: the kernel keeps what it knows about a path, so a new file under the
        # path of a deleted one (another app's copy) is not safe.
        root = '/var/tmp/ipa_extractor_{}_{}'.format(os.getpid(), uuid.uuid4().hex[:8])
        made = False
        try:
            for job in jobs:
                if len(job.slices) < 2:
                    continue
                source = posixpath.dirname(job.device_path)
                for index in range(len(job.slices)):
                    folder = '{}/{}_{}/X.app'.format(root, job.id, index)
                    status, output = remote.run(self.ssh, 'mkdir -p {d} && cp {f} {d}/ && '
                                                '{{ [ ! -d {s}/SC_Info ] || cp -R {s}/SC_Info {d}/; }}'.format(
                                                    d=shlex.quote(folder), f=shlex.quote(job.device_path),
                                                    s=shlex.quote(source)), timeout=300)
                    made = True
                    if status == 0:
                        job.slice_paths[index] = '{}/{}'.format(folder, posixpath.basename(job.device_path))
            yield
        finally:
            for job in jobs:
                job.slice_paths = {}
            if made:
                try:
                    remote.run(self.ssh, 'rm -rf ' + shlex.quote(root), timeout=60)
                except Exception:
                    pass

    def _run_native(self, bundle, jobs, work, options):
        """Decrypt the jobs' slices with the helper program chosen for the device; marks each job's decrypted slices."""
        device = native_decrypt.Device(self.ssh, options['user'], options['password'])
        helper = options['native']
        by_id = {job.id: job for job in jobs}

        def report(job, index, error):
            job = by_id[job.id]
            if error is None:
                job.done.add(index)
                if job.repaired:
                    self.post(self.log, Indented(Text('log_repaired', file=ipa_verify.short_name(job.member))))
            else:
                job.slice_errors[index] = error

        try:
            native_decrypt.run(device, helper, bundle, self.apps[bundle]['path'], jobs, work, report,
                               log=lambda text: self.post(self.log, '[{}] {}'.format(bundle, text)),
                               cancelled=self.cancel_requested.is_set)
        except native_decrypt.HelperError as error:
            self.post(self.helper_problem, str(error))
            for job in jobs:
                if job.untried():
                    job.error = ('helper', str(error))
        except Exception as error:
            for job in jobs:
                if job.untried():
                    job.error = ('helper', str(error) or type(error).__name__)

    def _run_repair_worker(self, bundle, jobs, work, options, pid):
        """Run repair_worker.py with the device's frida; marks each job's decrypted slices."""
        jobs_path = os.path.join(work, 'jobs.json')
        with open(jobs_path, 'w', encoding='utf-8') as handle:
            json.dump([job.to_json() for job in jobs], handle)
        command = [frida_versions.python(options['frida_version']), '-u', REPAIR_WORKER, options['frida'], jobs_path, work,
                   '--method', options['method'], '--bundle', bundle]
        if pid:
            command += ['--pid', str(pid)]
        if options['direct']:
            command.append('--no-launch')
        env = dict(frida_versions.env(options['frida_version']), PYTHONIOENCODING='utf-8')
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace',
                                   creationflags=NO_WINDOW)
        self.current_process = process  # Cancel terminates it
        by_id = {job.id: job for job in jobs}
        last_output = [time.monotonic()]

        stalled = threading.Event()

        def watchdog():
            # A crashed frida-server leaves the worker waiting forever.
            while process.poll() is None:
                if time.monotonic() - last_output[0] > REPAIR_STALL:
                    stalled.set()
                    process.kill()
                    return
                time.sleep(1)

        threading.Thread(target=watchdog, daemon=True).start()
        output = []
        try:
            for line in process.stdout:
                last_output[0] = time.monotonic()
                line = line.rstrip()
                if not line.startswith('@@'):
                    if line:
                        output.append(line)
                    continue
                try:
                    event = json.loads(line[2:])
                except ValueError:
                    continue
                if event['type'] == 'slice':
                    job = by_id[event['id']]
                    if event['ok']:
                        job.done.add(event['index'])
                        if job.repaired:
                            self.post(self.log, Indented(Text('log_repaired',
                                                              file=ipa_verify.short_name(job.member))))
                    else:
                        job.slice_errors[event['index']] = event['error']
                elif event['type'] == 'error':
                    for job in jobs:
                        if job.untried():  # the others already have their own result
                            job.error = ('frida', event['error'])
                elif event['type'] == 'spawned':
                    options.setdefault('repair_pids', []).append(event['pid'])  # left suspended; closed later
                elif event['type'] == 'running_app':
                    # iOS 16+ frameworks: unlike everything else, this lets the app's own code run.
                    self.post(self.log, Text('log_repair_run_app', bundle=bundle))
                elif event['type'] == 'log':
                    self.post(self.log, '[{}] {}'.format(bundle, event['text']))
            code = process.wait()
        finally:
            self.current_process = None
        if stalled.is_set() or code != 0:
            # Files the worker never got to: say why, unless it already did.
            reason = (ipa_repair.STALLED.format(REPAIR_STALL) if stalled.is_set()
                      else '\n'.join(output[-5:]) or self.t('exit_code', code=code))
            for job in jobs:
                if job.error is None and job.untried():
                    job.error = ('frida', reason)

    @staticmethod
    def reason_text(file):
        return Text('reason_' + file['reason'], error=file['error'])

    def _as_root(self, options, command):
        if options['user'] == 'root':
            return remote.run(self.ssh, command)
        # Rootless jailbreaks (Dopamine) log in as mobile; sudo asks for the same password.
        return remote.run(self.ssh, "sudo -S -p '' sh -c {}".format(shlex.quote(command)),
                          stdin=options['password'] + '\n')

    def _resume_frida_server(self, options):
        """Killed while it gated spawns, frida-server leaves its hook in launchd, which then holds
        launchd's own restart of frida-server suspended (a stopped xpcproxy): let that go."""
        try:
            for pid in frida_launchd_pids(self._as_root(options, 'launchctl list')[1]):
                self._as_root(options, 'kill -CONT {}'.format(pid))
        except Exception:
            pass

    def _release_gated(self, options, bundle):
        """Let go of the launches a dead frida-server held suspended: bundle's are killed, so none
        of the app's code runs, the others (system services, frida-server itself) resumed."""
        self._resume_frida_server(options)
        try:
            kill, resume = gated_launches(self._as_root(options, 'ps -A -o pid=,stat=,args=')[1], bundle)
            for pid in kill:
                self._as_root(options, 'kill -9 {}'.format(pid))
            for pid in resume:
                self._as_root(options, 'kill -CONT {}'.format(pid))
        except Exception:
            pass

    def _restart_frida_server(self, options, bundle=None):
        """Kill frida-server (launchd's KeepAlive respawns it) and reconnect. Runs on the dump thread."""
        if self.ssh is None or self.tunnel is None:
            return False
        self.post(self.log, Text('log_restarting'))
        address = '127.0.0.1:{}'.format(self.tunnel.local_port)
        try:
            self._as_root(options, 'killall -9 frida-server')
        except Exception as error:
            self.post(self.log, Text('log_restart_failed', error=error))
            return False
        deadline = time.monotonic() + RESTART_TIMEOUT
        error = None
        time.sleep(RESTART_GRACE)
        while time.monotonic() < deadline and not self.cancel_requested.is_set():
            ok, error = probe_frida(options['frida_version'], address, deep=True)
            if options['generation'] != self.generation:
                return False  # disconnected meanwhile; the tunnel is gone
            if ok:
                self.post(self.log, Text('log_restarted'))
                self._release_gated(options, bundle)
                return True
            if 'timeout' in str(error).lower():
                # It answers but runs nothing: a wedged process, not one still starting. Kill it again.
                try:
                    self._as_root(options, 'killall -9 frida-server')
                except Exception:
                    pass
                time.sleep(RESTART_GRACE)
            self._resume_frida_server(options)
            time.sleep(RESTART_POLL)
        self.post(self.log, Text('log_restart_failed', error=error))
        return False

    def _dump_one(self, index, total, bundle, name, options):
        def report(fraction, stage):
            fraction = max(0.0, min(1.0, fraction))
            self.post(self.set_status, bundle,
                      Text('st_running', pct='{:.0f}'.format(fraction * 100), stage=stage), 'running')
            self.post(self._set_overall, (index + fraction) / total * 100,
                      ('{}/{}  {}  '.format(index + 1, total, bundle), stage))

        report(0, Text('stage_connecting'))
        self._close_running_app(bundle)
        command = [frida_versions.python(options['frida_version']), '-u', WORKER, bundle, '-R', options['frida'],
                   '--ssh-transport', 'tcp', '-H', options['host'], '-p', options['port'],
                   '-u', options['user'], '-o', name, '-v']
        env = dict(frida_versions.env(options['frida_version']), FRIDA_DUMP_SSH_PASSWORD=options['password'],
                   PYTHONIOENCODING='utf-8', FRIDA_IOS_DUMP_DIR=options['dump_dir'])
        try:
            process = subprocess.Popen(command, cwd=options['outdir'], env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding='utf-8', errors='replace',
                                       creationflags=NO_WINDOW)
        except OSError as error:
            return False, str(error)
        self.current_process = process
        last_error = ''
        binaries = 0
        spawned = False
        spawned_pid = None
        last_output = [time.monotonic()]
        stalled = threading.Event()

        def watchdog():
            # A wedged frida-server makes dump.py wait forever without any error.
            while process.poll() is None:
                if time.monotonic() - last_output[0] > STALL_TIMEOUT:
                    stalled.set()
                    process.kill()
                    return
                time.sleep(1)

        threading.Thread(target=watchdog, daemon=True).start()
        for line in process.stdout:
            last_output[0] = time.monotonic()
            line = line.rstrip()
            if line.startswith('@@'):
                try:
                    event = json.loads(line[2:])
                except ValueError:
                    continue
                if event['type'] == 'log':
                    line = event['text']
                else:
                    total_bytes = event.get('total') or 0
                    part = event['n'] / total_bytes if total_bytes else 0
                    if event['desc'].startswith('App resources'):
                        report(0.25 + 0.70 * part, Text('stage_resources' if total_bytes else 'stage_scan'))
                    else:
                        report(0.10 + 0.15 * part, Text('stage_binary', file=event['desc']))
                    continue
            if not line:
                continue
            if line.startswith('[debug]'):
                if 'Spawning' in line:
                    spawned = True
                match = re.match(r'\[debug\] Attaching to PID (\d+)', line)
                if match and spawned:
                    spawned_pid = int(match.group(1))
                if 'Spawning' in line or 'Attaching' in line:
                    report(0.03, Text('stage_launch'))
                elif 'Frida agent loaded' in line:
                    report(0.06, Text('stage_injected'))
                elif 'Packaging IPA' in line:
                    report(0.96, Text('stage_package'))
                continue
            if line.startswith('start dump'):
                binaries += 1
                report(0.08, Text('stage_decrypt', n=binaries))
            if line.startswith('*** Caught exception') or 'Error' in line or 'Failed' in line:
                last_error = line.replace('*** Caught exception: ', '')
            self.post(self.log, '[{}] {}'.format(bundle, line))
        code = process.wait()
        self.current_process = None
        # dump.py leaves the app running; hundreds of them would exhaust device memory
        # and get the app being dumped killed by jetsam.
        if code == 0 and os.path.exists(os.path.join(options['outdir'], name + '.ipa')):
            report(1, Text('stage_finished'))
            # Still running: repairing still-encrypted files attaches to it, then it is closed.
            options['pid'] = spawned_pid
            return True, ''
        if spawned_pid is not None and options['close_after']:
            self._close_app(bundle, spawned_pid)
        if stalled.is_set():
            # Phrased like Frida's own error so it is classified as a timeout and retried.
            return False, 'frida.TransportError: timeout was reached (no response for {}s)'.format(STALL_TIMEOUT)
        return False, last_error or self.t('exit_code', code=code)

    def _copy_bundle(self, index, total, bundle, name, options):
        """Direct method (R4): copy the installed app as an IPA; its files are decrypted afterwards."""
        last = [0.0]

        def progress(done, size):
            now = time.monotonic()
            if now - last[0] < PROGRESS_INTERVAL:
                return
            last[0] = now
            fraction = done / size if size else 0
            self.post(self.set_status, bundle, Text('st_running', pct='{:.0f}'.format(fraction * 50),
                                                    stage=Text('stage_copy')), 'running')
            self.post(self._set_overall, (index + fraction / 2) / total * 100,
                      '{}/{}  {}'.format(index + 1, total, bundle))

        progress(0, 0)
        try:
            # Like frida-ios-dump IPAs: no iTunesMetadata.plist, which names the purchasing Apple ID.
            ipa_extract.extract_ipa(self.ssh, self.apps[bundle]['path'], os.path.join(options['outdir'], name + '.ipa'),
                                    progress, self.cancel_requested.is_set, metadata=False)
        except ipa_extract.Cancelled:
            return False, self.t('st_cancelled')
        except Exception as error:
            # socket.timeout and the like have no message of their own.
            return False, str(error) or type(error).__name__
        return True, ''

    def _close_running_app(self, bundle):
        """Close the app if it is running, so dump.py spawns it instead of attaching to it."""
        # Checked over SSH, which works even when frida-server is wedged.
        try:
            pid = device_apps.running_pid(self.ssh, self.apps[bundle]['path'])
        except Exception:
            return  # dump.py reports connection problems itself
        if pid:
            self.post(self.log, Text('log_relaunch', bundle=bundle, pid=pid))
            self._close_app(bundle, pid)
            time.sleep(1)

    def _close_spawned(self, bundle, options):
        """Close what repair_worker.py started and left suspended."""
        for pid in options.pop('repair_pids', []):
            self._close_app(bundle, pid)

    def _close_app(self, bundle, pid):
        # Apps run as mobile, so both root and mobile logins may kill them.
        try:
            status, output = remote.run(self.ssh, 'kill -9 {}'.format(pid))
        except Exception as error:
            status, output = None, str(error) or type(error).__name__
        if status == 0:
            self.post(self.log, Text('log_closed', bundle=bundle, pid=pid))
        elif 'no such process' not in output.lower():  # it may already have exited or crashed
            self.post(self.log, Text('log_close_failed', bundle=bundle, pid=pid,
                                     error=output.strip() or self.t('exit_code', code=status)))

    @staticmethod
    def _install_commands(version, dump_dir):
        """[(command, cwd)] that install frida `version` into its own folder, plus what dump.py needs.

        dump_dir None skips npm install (frida-objc-bridge is already in place).
        """
        commands = [(frida_versions.install_command(version), script_dir)]
        # dump.py also needs scp (from the tool's own Python); tqdm is replaced by dump_worker.py.
        if importlib.util.find_spec('scp') is None:
            commands.append((pip_install(['scp>=0.15']), script_dir))
        if dump_dir:
            # frida-objc-bridge is installed into the frida-ios-dump checkout that dump.py bundles from.
            commands.append((['npm', 'install'], dump_dir))
        return commands

    def _run_command(self, command, cwd):
        """Run one install command, logging its output; True on success."""
        self.post(self.log, '$ ' + ' '.join(command))
        try:
            process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                                       errors='replace', shell=IS_WINDOWS and command[0] == 'npm',
                                       creationflags=NO_WINDOW)
        except OSError as error:
            self.post(self.log, Text('log_exec_failed', error=error))
            if command[0] == 'npm':
                self.post(self.log, Text('log_need_node'))
            return False
        for line in process.stdout:
            if line.strip():
                self.post(self.log, '  ' + line.rstrip())
        code = process.wait()
        if code != 0:
            self.post(self.log, Text('log_cmd_failed', code=code))
            return False
        return True

    def install_frida(self, version, dump_dir):
        """Install frida `version` side by side with the others, logging as it goes; True on success."""
        try:
            if frida_versions.is_legacy(version):
                # No wheel for this Python: its own Python 3.8 and the frida egg (frida-ios-dump needs frida 16).
                frida_versions.prepare_install(version)
                try:
                    frida_versions.install_legacy(version, lambda text: self.post(self.log, text))
                    frida_versions.finish_install(version)
                    return True
                except Exception as error:
                    self.post(self.log, Text('log_exec_failed', error=error))
                    shutil.rmtree(frida_versions.staging(version), ignore_errors=True)
                    return False
            commands = self._install_commands(version, dump_dir)
            frida_versions.prepare_install(version)
            if self._run_command(*commands[0]):
                frida_versions.finish_install(version)
                return all(self._run_command(*command) for command in commands[1:])
            shutil.rmtree(frida_versions.staging(version), ignore_errors=True)
            return False
        except OSError as error:
            self.post(self.log, Text('log_exec_failed', error=error))
            return False
