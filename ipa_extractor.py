#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPA Extractor: Tkinter GUI that pulls original or decrypted IPAs off a jailbroken device over SSH."""

__version__ = '2.0'
APP_NAME = 'IPA Extractor'

import importlib.util
import json
import os
import platform
import queue
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont

try:
    import paramiko
except ImportError:  # main() offers to install it; pythonw would otherwise exit without a word
    paramiko = None

import app_info
import device_apps
import frida_versions
import ipa_extract
import ipa_repair
import ipa_verify
import i18n
import remote

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

CHECKED, UNCHECKED = '☑', '☐'
COLORS = dict(ok='#1a7f37', busy='#d4a72c', error='#cf222e', idle='#8c959f')
# Named Tk fonts the UI uses; all follow the font chosen in Settings.
UI_FONTS = ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont', 'TkCaptionFont',
            'TkSmallCaptionFont', 'TkIconFont', 'TkTooltipFont')
# Fonts sv-ttk's widgets use instead of the Tk named fonts.
SUN_VALLEY_FONTS = ('SunValleyBodyFont', 'SunValleyBodyStrongFont', 'SunValleyCaptionFont')
DEFAULT_FONT_SIZE = 13 if IS_MACOS else 10
# Settings files keep only values that differ from these, so new defaults reach existing users.
# Ways to make a decrypted IPA (the dump_method setting). Both need frida-server; the names leave room
# for methods that do not.
METHOD_FRIDA_DIRECT = 'frida_direct'        # R4: decrypt the installed files, the app never runs
METHOD_FRIDA_IOS_DUMP = 'frida_ios_dump'    # run the app and dump it with frida-ios-dump
DUMP_METHODS = (METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP)

DEFAULTS = dict(
    host='', port=22, user='', frida_port=27042,
    user_only=True, non_apple=False, encrypted_only=False,
    outdir=os.path.join(script_dir, 'output_decrypted'), extract_dir=os.path.join(script_dir, 'output_encrypted'),
    separate_dirs=True, name_decrypted=app_info.DEFAULT_DECRYPTED_NAME, name_original=app_info.DEFAULT_ORIGINAL_NAME,
    dump_dir=DEFAULT_DUMP_DIR, close_after=True, restart_frida=True, repair=True, dump_method=METHOD_FRIDA_DIRECT,
    lang=i18n.AUTO, font='', font_size=DEFAULT_FONT_SIZE,
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
COLUMNS = (
    ('check', 44),
    ('name', 180),
    ('bundle', 230),
    ('version', 100),
    ('encrypted', 75),
    ('team', 110),
    ('signer', 220),
    ('developer', 150),
    ('status', 200),
)
SHIFT_MASK = 0x0001          # Tk event.state bit for the Shift key
PROGRESS_LABEL_CHARS = 70    # the progress label has a fixed width
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
DUMP_KINDS = (ipa_verify.DECRYPTED, ipa_verify.PARTIAL_32BIT, ipa_verify.PARTIAL)


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
        try:
            while not self.closed.is_set():
                readable, _, _ = select.select([sock, channel], [], [], 1)
                if sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        break
                    channel.sendall(data)
                if channel in readable:
                    data = channel.recv(65536)
                    if not data:
                        break
                    sock.sendall(data)
        except Exception:
            pass
        finally:
            sock.close()
            channel.close()

    def close(self):
        self.closed.set()
        for stop in (lambda: self.server.shutdown(socket.SHUT_RDWR), self.server.close):
            try:
                stop()  # shutdown wakes a thread blocked in accept() on Linux; close alone does not
            except OSError:
                pass


def probe_frida(version, address, wait=0):
    """Ask frida_probe.py, running with frida `version`, whether frida-server at address answers.

    Returns (ok, detail): detail is the device OS on success, the error otherwise.
    """
    command = [sys.executable, '-u', PROBE, address] + (['--wait', str(wait)] if wait else [])
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
    return sorted(versions, key=lambda v: tuple(int(n) for n in v.split('.')), reverse=True)


def frida_server_status(client):
    """Return (frida-server version or None, whether it is running) on the device."""
    _, found = remote.run(client, 'for p in {}; do [ -x "$p" ] && "$p" --version && break; done; '
                                  'ps -A -o comm= | grep -c frida-server'.format(' '.join(FRIDA_SERVER_PATHS)))
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


def dump_method_setting(value):
    """The saved decryption method, or the default when it is missing or unknown."""
    return value if value in DUMP_METHODS else METHOD_FRIDA_DIRECT


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


def repair_failure(error):
    """(reason key, error) for a file repair_worker.py could not decrypt."""
    if error.startswith('unsupported:'):
        # iOS 16 and later: only what the system loads on this device can be read (see repair_worker.py).
        return 'repair_unsupported_' + error.split(':', 1)[1], ''
    # The kernel has no key for the file: typically the app was not installed with this device's
    # Apple ID (e.g. from an already decrypted or re-signed IPA).
    if '(errno 12)' in error or '(errno 1)' in error:
        return 'repair_nokey', error
    return 'repair_failed', error


def is_user_app(path):
    return '/containers/Bundle/Application/' in (path or '')


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


def wrap_text(text, width, font='TkDefaultFont'):
    """Insert line breaks so text fits width pixels.

    Tk only breaks lines at spaces, which Chinese and Japanese text rarely has, so this
    breaks between any two characters except inside runs of Latin letters and digits.
    """
    font = tkfont.nametofont(font) if isinstance(font, str) else font
    lines = []
    for paragraph in text.split('\n'):
        line = ''
        for token in re.findall(r'[\w.\-/\\:@{}()]+|\s+|.', paragraph, re.ASCII):
            if line.strip() and font.measure(line + token) > width:
                lines.append(line.rstrip())
                line = token.lstrip()
            else:
                line += token
        lines.append(line)
    return '\n'.join(lines)


class WrapLabel(ttk.Label):
    """Label whose text re-wraps to the width it is given (pack with fill='x' or grid with sticky='we')."""

    def __init__(self, parent, text='', **kwargs):
        super().__init__(parent, width=1, **kwargs)
        self.raw_text = text
        self.wrap_width = 0
        self.bind('<Configure>', self._rewrap)

    def set_text(self, text):
        self.raw_text = text
        self.configure(text=wrap_text(text, self.wrap_width - 4) if self.wrap_width > 1 else text)

    def _rewrap(self, event):
        if event.width != self.wrap_width:
            self.wrap_width = event.width
            self.configure(text=wrap_text(self.raw_text, event.width - 4))


class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.window = widget, text, None
        widget.bind('<Enter>', self.show)
        widget.bind('<Leave>', self.hide)

    def show(self, event=None):
        if self.window is not None:
            return
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry('+{}+{}'.format(x, y))
        tk.Label(self.window, text=wrap_text(self.text, 420), justify='left', background='#ffffe0',
                 relief='solid', borderwidth=1, padx=6, pady=4).pack()

    def hide(self, event=None):
        if self.window is not None:
            self.window.destroy()
            self.window = None


class DumpGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry('1320x840')
        self.minsize(1000, 620)
        self.events = queue.Queue()
        self.ssh = None
        self.tunnel = None
        self.frida_version = None  # local frida version in use once Frida is connected
        self.device_frida_version = None
        self.device_os = None
        self.apps = {}           # bundle -> dict(name, bundle, version, build, path, pid, info...)
        self.status = {}         # bundle -> (Text, tag)
        self.checked = set()
        self.check_anchor = None  # last checkbox clicked, for Shift-click ranges
        self.list_host = None     # device the app list belongs to
        self.sort_column = 'name'
        self.sort_reverse = False
        self.dumping = False     # a batch (decrypted or original IPAs) is running
        self.cancel_requested = threading.Event()
        self.current_process = None
        self.generation = 0      # invalidates background work from older connections
        c = dict(DEFAULTS, **load_config())
        self.locales = i18n.load_locales()
        self.lang_setting = c['lang'] if c['lang'] in self.locales else i18n.AUTO
        self.lang = i18n.resolve(self.locales, self.lang_setting)
        self.ssh_state = (Text('state_idle'), 'idle')
        self.frida_state = (Text('state_unused'), 'idle')
        self.overall = (0, None)
        self.var_host = tk.StringVar(value=c['host'])
        self.var_port = tk.StringVar(value=str(c['port']))
        self.var_user = tk.StringVar(value=c['user'])
        self.var_password = tk.StringVar(value=c.get('password', ''))
        self.var_frida_port = tk.StringVar(value=str(c['frida_port']))
        self.var_remember = tk.BooleanVar(value=bool(c.get('password')))
        self.var_search = tk.StringVar()
        self.var_user_only = tk.BooleanVar(value=c['user_only'])
        self.var_non_apple = tk.BooleanVar(value=c['non_apple'])
        self.var_encrypted_only = tk.BooleanVar(value=c['encrypted_only'])
        self.var_outdir = tk.StringVar(value=c['outdir'])
        self.var_extract_dir = tk.StringVar(value=c['extract_dir'])
        self.var_dump_dir = tk.StringVar(value=c['dump_dir'])
        self.var_close_after = tk.BooleanVar(value=c['close_after'])
        self.var_restart_frida = tk.BooleanVar(value=c['restart_frida'])
        self.var_repair = tk.BooleanVar(value=c['repair'])
        self.var_dump_method = tk.StringVar(value=dump_method_setting(c['dump_method']))
        self.var_name_decrypted = tk.StringVar(value=c['name_decrypted'])
        self.var_name_original = tk.StringVar(value=c['name_original'])
        self.var_separate_dirs = tk.BooleanVar(value=c['separate_dirs'])
        self.var_font = tk.StringVar(value=c['font'])  # '' follows the language
        self.var_font_size = tk.StringVar(value=str(c['font_size']))
        self.var_lang = tk.StringVar()
        self.var_search.trace_add('write', lambda *a: self.refresh_tree())
        self.style = ttk.Style(self)
        self.apply_theme()
        self.apply_icon()
        self.style.configure('TNotebook.Tab', padding=(18, 7))
        self.installed_fonts = sorted(f for f in tkfont.families(self) if not f.startswith('@'))
        # The platform's UI font (Segoe UI on Windows, the system font on macOS), before Settings change it.
        self.system_font = tkfont.nametofont('TkDefaultFont').actual('family')
        self.apply_fonts()
        self.fix_numpad_decimal()
        self.root_frame = None
        self.settings_window = None
        self.install_window = None
        self.ssh_connecting = False
        self.frida_connecting = False
        self.installing = False   # a frida version is being installed
        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self.on_close)
        self.after(100, self._drain_events)
        self.after(3000, self._watch_connection)
        self.log(Text('log_ready'))

    def t(self, key, **params):
        template = self.locales[self.lang].get(key) or self.locales[i18n.FALLBACK].get(key, key)
        return template.format(**params)

    def apply_icon(self):
        try:
            # Both apply to Settings and other dialogs too. On Windows use only the .ico (sharper at
            # 16 and 32 px): combined with iconphoto, the title bar falls back to a generic icon.
            if IS_WINDOWS:
                self.iconbitmap(default=os.path.join(ASSETS, 'icon.ico'))
            else:
                self.icon_image = tk.PhotoImage(file=os.path.join(ASSETS, 'icon.png'))
                self.iconphoto(True, self.icon_image)
        except tk.TclError:
            pass

    def fix_numpad_decimal(self):
        """Type the numpad '.' even when an IME turns it into a Delete key event.

        With a Chinese or Japanese IME active on Windows, the numpad decimal key arrives as
        keysym Delete carrying the character '.', and ttk entries would delete text instead.
        """
        for widget_class in ('TEntry', 'TSpinbox', 'TCombobox'):
            self.bind_class(widget_class, '<Delete>',
                            'if {"%A" eq "."} {ttk::entry::Insert %W %A} else {ttk::entry::Delete %W}')

    def apply_theme(self):
        """Native theme on Windows and macOS; on Linux, Sun Valley (sv-ttk) instead of Tk's dated default."""
        if IS_WINDOWS:
            self.style.theme_use('vista')
        elif not IS_MACOS:
            try:
                import sv_ttk
                sv_ttk.set_theme('light', self)
            except ImportError:
                self.style.theme_use('clam')
        # Classic Tk widgets (Text, Canvas) do not follow ttk themes. Sun Valley does not report its
        # colours through style lookups, so read its palette directly.
        try:
            background = self.tk.call('set', '::ttk::theme::sv_light::colors(-bg)')
        except tk.TclError:
            background = self.style.lookup('TFrame', 'background')
        self.theme_background = background or self.cget('background')
        self.configure(background=self.theme_background)

    def auto_font(self):
        """First installed font the language prefers (locale "_fonts"), else the platform's UI font."""
        installed = set(self.installed_fonts)
        for family in self.locales[self.lang].get('_fonts', []):
            if family in installed:
                return family
        return self.system_font

    def apply_fonts(self):
        family = self.var_font.get() or self.auto_font()
        try:
            size = min(16, max(8, int(self.var_font_size.get())))
        except ValueError:
            size = DEFAULT_FONT_SIZE
        for name in UI_FONTS + SUN_VALLEY_FONTS:
            if name in tkfont.names(self):
                tkfont.nametofont(name).configure(family=family, size=size)
        self.style.configure('Treeview', rowheight=tkfont.nametofont('TkDefaultFont').metrics('linespace') + 8)

    def render(self, text):
        if isinstance(text, Indented):
            return '    ' + self.render(text.text)
        if isinstance(text, Text):
            params = {k: self.render(v) for k, v in text.params.items()}
            return self.t(text.key, **params)
        return str(text)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        log_content = selection = ''
        if self.root_frame is not None:
            log_content = self.log_text.get('1.0', 'end-1c')
            selection = self.tree.selection()
            self.root_frame.destroy()
        self.title('{} {}'.format(APP_NAME, __version__))
        root = self.root_frame = ttk.Frame(self)
        root.pack(fill='both', expand=True)

        conn = ttk.LabelFrame(root, text=self.t('device'))
        conn.pack(fill='x', padx=8, pady=(8, 4))
        fields = (('host', self.var_host, 16), ('ssh_port', self.var_port, 6),
                  ('user', self.var_user, 8), ('password', self.var_password, 14))
        for column, (label, var, width) in enumerate(fields):
            ttk.Label(conn, text=self.t(label)).grid(row=0, column=column * 2, padx=(8, 2), pady=6)
            entry = ttk.Entry(conn, textvariable=var, width=width,
                              show='•' if var is self.var_password else '')
            entry.grid(row=0, column=column * 2 + 1, pady=6)
            entry.bind('<Return>', lambda e: self.connect())
        ttk.Checkbutton(conn, text=self.t('remember'), variable=self.var_remember).grid(row=0, column=8, padx=6)
        self.btn_connect = ttk.Button(conn, command=self.toggle_connection,
                                      text=self.t('disconnect' if self.ssh is not None else 'connect'),
                                      state='disabled' if self.ssh_connecting else 'normal')
        self.btn_connect.grid(row=0, column=9, padx=6)
        conn.columnconfigure(10, weight=1)
        ttk.Button(conn, text=self.t('settings'), command=self.open_settings).grid(row=0, column=11, padx=6)
        indicators = ttk.Frame(conn)
        indicators.grid(row=1, column=0, columnspan=12, padx=2, pady=(0, 6), sticky='w')
        self.ssh_dot, self.ssh_label = self._indicator(indicators, 'SSH')
        self.frida_dot, self.frida_label = self._indicator(indicators, 'Frida')

        dirs = ttk.Frame(root)
        dirs.pack(fill='x', padx=8, pady=(4, 0))
        folders = ((('outdir', self.var_outdir), ('extract_dir', self.var_extract_dir))
                   if self.var_separate_dirs.get() else (('outdir_single', self.var_outdir),))
        for row, (label, var) in enumerate(folders):
            ttk.Label(dirs, text=self.t(label)).grid(row=row, column=0, sticky='w', pady=2)
            ttk.Entry(dirs, textvariable=var).grid(row=row, column=1, sticky='we', padx=4)
            ttk.Button(dirs, text=self.t('browse'), command=lambda v=var: self.choose_dir(v)).grid(
                row=row, column=2, padx=2)
            ttk.Button(dirs, text=self.t('open_dir'), command=lambda v=var: self.open_dir(v.get())).grid(
                row=row, column=3, padx=2)
        dirs.columnconfigure(1, weight=1)
        ttk.Separator(root).pack(fill='x', padx=8, pady=(6, 2))

        tools = ttk.Frame(root)
        tools.pack(fill='x', padx=8, pady=4)
        ttk.Label(tools, text=self.t('search')).pack(side='left')
        ttk.Entry(tools, textvariable=self.var_search, width=22).pack(side='left', padx=4)
        ttk.Checkbutton(tools, text=self.t('user_only'), variable=self.var_user_only,
                        command=self.refresh_tree).pack(side='left', padx=4)
        ttk.Checkbutton(tools, text=self.t('non_apple'), variable=self.var_non_apple,
                        command=self.refresh_tree).pack(side='left', padx=4)
        ttk.Checkbutton(tools, text=self.t('encrypted_only'), variable=self.var_encrypted_only,
                        command=self.refresh_tree).pack(side='left', padx=4)
        ttk.Button(tools, text=self.t('refresh'), command=self.load_apps).pack(side='left', padx=6)
        self.lbl_count = ttk.Label(tools, text='')
        self.lbl_count.pack(side='left', padx=8)

        checks = ttk.Frame(root)
        checks.pack(fill='x', padx=8, pady=(0, 4))
        ttk.Button(checks, text=self.t('check_all'), command=self.check_all).pack(side='left', padx=(0, 2))
        ttk.Button(checks, text=self.t('check_none'), command=self.check_none).pack(side='left', padx=2)
        ttk.Button(checks, text=self.t('check_invert'), command=self.check_invert).pack(side='left', padx=2)
        ttk.Button(checks, text=self.t('check_failed'), command=self.check_failed).pack(side='left', padx=2)
        partial = ttk.Button(checks, text=self.t('check_partial'), command=self.check_partial)
        partial.pack(side='left', padx=2)
        Tooltip(partial, self.t('check_partial_tip'))
        unextracted = ttk.Button(checks, text=self.t('check_unextracted'), command=self.check_unextracted)
        unextracted.pack(side='left', padx=2)
        Tooltip(unextracted, self.t('check_unextracted_tip'))

        panes = ttk.PanedWindow(root, orient='vertical')
        panes.pack(fill='both', expand=True, padx=8, pady=4)

        table = ttk.Frame(panes)
        WrapLabel(table, text=self.t('hint'), foreground='#57606a', justify='left').pack(fill='x', pady=(0, 2))
        self.tree = ttk.Treeview(table, columns=[c[0] for c in COLUMNS], show='headings',
                                 selectmode='extended')
        for key, width in COLUMNS:
            title = UNCHECKED if key == 'check' else self.t('col_' + key)
            self.tree.heading(key, text=title,
                              command=self.toggle_visible if key == 'check' else lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=40, anchor='center' if key == 'check' else 'w',
                             stretch=key in ('name', 'signer', 'status'))
        scroll = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scroll.pack(side='right', fill='y')
        self.tree.tag_configure('checked', background='#ddf4ff')
        self.tree.tag_configure('done', foreground=COLORS['ok'])
        self.tree.tag_configure('failed', foreground=COLORS['error'])
        self.tree.tag_configure('partial', foreground='#bc4c00')
        self.tree.tag_configure('running', foreground='#0969da')
        self.tree.tag_configure('queued', foreground='#9a6700')
        self.tree.tag_configure('offloaded', foreground=COLORS['idle'])
        self.tree.bind('<<TreeviewSelect>>', lambda e: self.show_details())
        self.tree.bind('<Button-1>', self.on_tree_click)
        self.tree.bind('<Double-1>', self.on_tree_double_click)
        self.tree.bind('<space>', self.on_space)
        self.tree.bind('<Button-3>', self.on_tree_menu)
        if IS_MACOS:
            self.tree.bind('<Button-2>', self.on_tree_menu)
            self.tree.bind('<Control-Button-1>', self.on_tree_menu)
        panes.add(table, weight=4)

        lower = ttk.Frame(panes)
        self.details = tk.Text(lower, height=7, wrap='word', state='disabled', relief='flat',
                               background=self.theme_background, font=tkfont.nametofont('TkDefaultFont'))
        self.details.pack(fill='x')
        actions = ttk.Frame(lower)
        actions.pack(fill='x', pady=4)
        # Negative widths are minimums, so longer translations are not cut off.
        self.btn_extract = ttk.Button(actions, command=self.start_extract, width=-22)
        self.btn_extract.pack(side='left')
        Tooltip(self.btn_extract, self.t('extract_tip'))
        self.btn_dump = ttk.Button(actions, command=self.start_dump, width=-22)
        self.btn_dump.pack(side='left', padx=(6, 0))
        Tooltip(self.btn_dump, self.t('dump_tip'))
        self.btn_cancel = ttk.Button(actions, command=self.cancel_batch, text=self.t('cancel'),
                                     state='normal' if self.dumping else 'disabled')
        self.btn_cancel.pack(side='left', padx=6)
        self.progress = ttk.Progressbar(actions, maximum=100)
        self.progress.pack(side='left', fill='x', expand=True, padx=6)
        self.lbl_progress = ttk.Label(actions, text='', width=48)
        self.lbl_progress.pack(side='left')
        log_frame = ttk.Frame(lower)
        log_frame.pack(fill='both', expand=True)
        self.log_text = tk.Text(log_frame, height=10, wrap='none', font='TkTextFont')
        log_scroll = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side='left', fill='both', expand=True)
        log_scroll.pack(side='right', fill='y')
        if log_content:
            self.log_text.insert('end', log_content + '\n')
            self.log_text.see('end')
        self.log_text.configure(state='disabled')
        panes.add(lower, weight=2)

        self.set_ssh_state(*self.ssh_state)
        self.set_frida_state(*self.frida_state)
        self._set_overall(*self.overall)
        self.refresh_tree()
        selection = [b for b in selection if self.tree.exists(b)]
        if selection:
            self.tree.selection_set(selection)
            self.tree.see(selection[0])

    def open_settings(self, tab=0):
        if self.settings_window is not None and self.settings_window.winfo_exists():
            self.settings_tabs.select(tab)
            self.settings_window.lift()
            return
        self.var_font_size.set(str(tkfont.nametofont('TkDefaultFont').actual('size')))
        window = self.settings_window = tk.Toplevel(self)
        window.title('{} – Settings'.format(APP_NAME))
        window.transient(self)
        window.resizable(True, False)
        outer = ttk.Frame(window, padding=10)
        outer.pack(fill='both', expand=True)
        tabs = self.settings_tabs = ttk.Notebook(outer)
        tabs.pack(fill='both', expand=True)

        general = ttk.Frame(tabs, padding=12)
        tabs.add(general, text=self.t('tab_general'))
        ttk.Label(general, text=self.t('language')).grid(row=0, column=0, sticky='w', pady=4)
        self.language_choices = {self.t('lang_auto', language=self.locales[i18n.system_language(self.locales)]['_name']):
                                 i18n.AUTO}
        self.language_choices.update((locale['_name'], code) for code, locale in
                                     sorted(self.locales.items(), key=lambda item: item[1]['_name'].casefold()))
        self.var_lang.set(next(name for name, code in self.language_choices.items() if code == self.lang_setting))
        combo = ttk.Combobox(general, textvariable=self.var_lang, state='readonly', width=24,
                             values=list(self.language_choices))
        combo.grid(row=0, column=1, sticky='w', padx=6)
        combo.bind('<<ComboboxSelected>>', lambda e: self.change_language())
        # Fonts the languages recommend come first.
        auto = self.t('font_auto', family=self.auto_font())
        preferred = [f for locale in self.locales.values() for f in locale.get('_fonts', [])
                     if f in self.installed_fonts]
        families = list(dict.fromkeys(preferred + self.installed_fonts))
        font_name = tk.StringVar(value=self.var_font.get() or auto)

        def font_chosen(event=None):
            self.var_font.set('' if font_name.get() == auto else font_name.get())
            self.apply_fonts()
            self._save_config()

        ttk.Label(general, text=self.t('font')).grid(row=1, column=0, sticky='w', pady=4)
        fonts = ttk.Combobox(general, textvariable=font_name, values=[auto] + families, state='readonly', width=32)
        fonts.grid(row=1, column=1, sticky='w', padx=6)
        fonts.bind('<<ComboboxSelected>>', font_chosen)
        ttk.Label(general, text=self.t('font_size')).grid(row=2, column=0, sticky='w', pady=4)
        size = ttk.Spinbox(general, from_=8, to=16, textvariable=self.var_font_size, width=5, command=font_chosen)
        size.grid(row=2, column=1, sticky='w', padx=6)
        size.bind('<Return>', font_chosen)
        size.bind('<FocusOut>', font_chosen)

        extract = ttk.Frame(tabs, padding=12)
        tabs.add(extract, text=self.t('tab_extract'))
        names = ttk.LabelFrame(extract, text=self.t('name_group'), padding=8)
        names.pack(fill='x')
        row = 0
        for key, var, default, kind in (
                ('name_decrypted', self.var_name_decrypted, app_info.DEFAULT_DECRYPTED_NAME, 'decrypted'),
                ('name_original', self.var_name_original, app_info.DEFAULT_ORIGINAL_NAME, 'encrypted')):
            ttk.Label(names, text=self.t(key)).grid(row=row, column=0, sticky='w')
            entry = ttk.Entry(names, textvariable=var, width=50)
            entry.grid(row=row, column=1, sticky='we', padx=4)
            ttk.Button(names, text=self.t('name_reset'), command=lambda v=var, d=default: v.set(d)).grid(
                row=row, column=2)
            fields = ttk.Frame(names)
            fields.grid(row=row + 1, column=1, sticky='w', padx=4, pady=(2, 0))
            ttk.Label(fields, text=self.t('name_insert'), foreground='#57606a').pack(side='left')
            for field in app_info.NAME_FIELDS:
                ttk.Button(fields, text=self.t('field_' + field), width=-1,
                           command=lambda e=entry, f=field: self._insert_field(e, f)).pack(side='left', padx=1)
            preview = ttk.Label(names, foreground='#57606a')
            preview.grid(row=row + 2, column=1, sticky='w', padx=4, pady=(2, 8))
            update = lambda *a, v=var, l=preview, k=kind: self._update_name_preview(v, l, k)
            var.trace_add('write', update)
            update()
            row += 3
        names.columnconfigure(1, weight=1)
        WrapLabel(names, text=self.t('name_help'), foreground='#57606a', justify='left').grid(
            row=row, column=0, columnspan=3, sticky='we')
        ttk.Checkbutton(extract, text=self.t('separate_dirs'), variable=self.var_separate_dirs,
                        command=self._folders_changed).pack(anchor='w', pady=(10, 0))

        frida = ttk.Frame(tabs, padding=12)
        tabs.add(frida, text=self.t('tab_frida'))
        WrapLabel(frida, text=self.t('frida_help'), foreground='#57606a', justify='left').grid(
            row=0, column=0, columnspan=3, sticky='we', pady=(0, 8))
        # Decryption method first: the options below each method only apply to it.
        ttk.Label(frida, text=self.t('dump_method')).grid(row=1, column=0, columnspan=3, sticky='w')
        # R4 (the default): copy the app and decrypt its files without running it.
        direct_option = ttk.Radiobutton(frida, text=self.t('dump_method_frida_direct'), value=METHOD_FRIDA_DIRECT,
                                        variable=self.var_dump_method)
        direct_option.grid(row=2, column=0, columnspan=3, sticky='w', pady=(4, 0))
        Tooltip(direct_option, self.t('dump_method_frida_direct_tip'))
        dump_option = ttk.Radiobutton(frida, text=self.t('dump_method_frida_ios_dump'), value=METHOD_FRIDA_IOS_DUMP,
                                      variable=self.var_dump_method)
        dump_option.grid(row=3, column=0, columnspan=3, sticky='w', pady=(8, 0))
        Tooltip(dump_option, self.t('dump_method_frida_ios_dump_tip'))
        dump_box = ttk.Frame(frida)
        dump_box.grid(row=4, column=0, columnspan=3, sticky='we', padx=(24, 0))
        dump_label = ttk.Label(dump_box, text=self.t('dump_dir'))
        dump_label.grid(row=0, column=0, sticky='w')
        dump_entry = ttk.Entry(dump_box, textvariable=self.var_dump_dir, width=44)
        dump_entry.grid(row=0, column=1, sticky='we', padx=4)
        dump_browse = ttk.Button(dump_box, text=self.t('browse'), command=lambda: self.choose_dir(
            self.var_dump_dir, DEFAULT_DUMP_DIR, window))
        dump_browse.grid(row=0, column=2)
        dump_widgets = [dump_label, dump_entry, dump_browse]
        status_row = ttk.Frame(dump_box)
        status_row.grid(row=1, column=1, columnspan=2, sticky='w', padx=4)
        status = ttk.Label(status_row)
        status.pack(side='left')
        install_dump = ttk.Button(status_row, text=self.t('install_dump'), command=self.install_frida_ios_dump)
        # R2: decrypt what frida-ios-dump left encrypted, on the device.
        repair = ttk.Checkbutton(dump_box, text=self.t('repair'), variable=self.var_repair)
        repair.grid(row=2, column=0, columnspan=3, sticky='w', pady=(6, 0))
        Tooltip(repair, self.t('repair_tip'))
        # The direct method never lets an app run, and what it starts suspended is always closed.
        close_after = ttk.Checkbutton(dump_box, text=self.t('close_after'), variable=self.var_close_after)
        close_after.grid(row=3, column=0, columnspan=3, sticky='w', pady=(4, 0))
        dump_widgets += [status, install_dump, repair, close_after]
        dump_box.columnconfigure(1, weight=1)
        ttk.Separator(frida).grid(row=5, column=0, columnspan=3, sticky='we', pady=12)
        # Both methods talk to frida-server, which can crash or hang with either.
        ttk.Checkbutton(frida, text=self.t('restart_frida'), variable=self.var_restart_frida).grid(
            row=6, column=0, columnspan=3, sticky='w', pady=(0, 8))
        ttk.Label(frida, text=self.t('frida_port')).grid(row=7, column=0, sticky='w')
        ttk.Entry(frida, textvariable=self.var_frida_port, width=8).grid(row=7, column=1, sticky='w', padx=4)
        ttk.Button(frida, text=self.t('install'), command=self.install_dependencies).grid(
            row=8, column=0, columnspan=3, sticky='w', pady=(8, 0))

        def update_status(*args):
            state = dump_dir_status(self.var_dump_dir.get().strip())
            status.configure(text=self.t('dump_dir_' + state),
                             foreground=COLORS['ok'] if state == 'ok' else COLORS['error'])
            # A missing or unset folder can be fixed by downloading frida-ios-dump.
            if state in ('empty', 'missing'):
                install_dump.pack(side='left', padx=8)
            else:
                install_dump.pack_forget()

        def update_method(*args):
            # Options of frida-ios-dump are greyed out (and unused) with the direct method.
            enabled = not self.direct_method()
            for widget in dump_widgets:
                widget.state(['!disabled'] if enabled else ['disabled'])
            status.configure(foreground=status.cget('foreground') if enabled else COLORS['idle'])
            if enabled:
                update_status()

        self.var_dump_dir.trace_add('write', update_status)
        self.var_dump_method.trace_add('write', update_method)
        update_status()
        update_method()
        frida.columnconfigure(1, weight=1)
        tabs.select(tab)

        def close():
            for var in (self.var_name_decrypted, self.var_name_original, self.var_dump_dir, self.var_dump_method):
                for mode, callback in var.trace_info():
                    var.trace_remove(mode, callback)
            self._save_config()
            window.destroy()
            self.show_details()
            # A folder fixed in Settings takes effect without reconnecting.
            if (self.ssh is not None and self.frida_version is None and not self.frida_connecting
                    and (self.direct_method()
                         or dump_dir_status(self.var_dump_dir.get().strip()) == 'ok')):
                self.connect_frida()

        ttk.Button(outer, text=self.t('close'), command=close).pack(side='right', pady=(10, 0))
        window.protocol('WM_DELETE_WINDOW', close)
        self.settings_close = close

    def _folders_changed(self):
        self._save_config()
        self._build_ui()

    @staticmethod
    def _insert_field(entry, field):
        entry.insert('insert', '{' + field + '}')
        entry.focus_set()

    def _update_name_preview(self, var, label, kind):
        selection = self.tree.selection()
        app = self.apps.get(selection[0]) if selection else None
        app = app or dict(name='App', bundle='com.example.app', version='1.0', build='100')
        try:
            name = app_info.format_ipa_name(var.get(), app['name'], app['bundle'], app['version'],
                                            app['build'], kind)
            label.configure(text=self.t('name_preview', file=name + '.ipa'), foreground='#57606a')
        except app_info.NameTemplateError as error:
            label.configure(text=self.t('name_bad', error=self.name_error_text(error)), foreground=COLORS['error'])

    def name_error_text(self, error):
        key, params = error.args
        return self.t(key, **params)

    def _show_name_error(self, mode, error):
        messagebox.showerror(self.t('m_name_t'), self.t(
            'm_name', kind=self.t('name_decrypted' if mode == 'dump' else 'name_original'),
            error=self.name_error_text(error)))
        self.open_settings(tab=1)

    def output_dir(self, mode):
        """Folder that IPAs of a batch mode ('dump' or 'extract') are written to."""
        separate = mode == 'extract' and self.var_separate_dirs.get()
        return (self.var_extract_dir if separate else self.var_outdir).get().strip()

    def ipa_name(self, app, mode, kind=None):
        """IPA base name for app; raises NameTemplateError for a bad template.

        For decrypted IPAs kind is the verification result (ipa_verify's status), 'decrypted' by default.
        """
        if mode == 'dump':
            template, kind = self.var_name_decrypted.get(), kind or ipa_verify.DECRYPTED
        else:
            # Unknown counts as encrypted, the usual case for App Store apps.
            encrypted = app.get('info', {}).get('encrypted') is not False
            template, kind = self.var_name_original.get(), 'encrypted' if encrypted else 'original'
        return app_info.format_ipa_name(template, app['name'], app['bundle'], app['version'], app['build'], kind)

    def change_language(self):
        setting = self.language_choices[self.var_lang.get()]
        if setting != self.lang_setting:
            self.lang_setting = setting
            self.lang = i18n.resolve(self.locales, setting)
            self._save_config()
            reopen = self.settings_window is not None and self.settings_window.winfo_exists()
            if reopen:
                self.settings_close()
            self.apply_fonts()
            self._build_ui()
            if reopen:
                self.open_settings()

    def _indicator(self, parent, title):
        frame = ttk.Frame(parent)
        frame.pack(side='left', padx=(6, 18))
        dot = tk.Canvas(frame, width=14, height=14, highlightthickness=0, background=self.theme_background)
        dot.create_oval(2, 2, 12, 12, fill=COLORS['idle'], outline='', tags='dot')
        dot.pack(side='left')
        label = ttk.Label(frame)
        label.pack(side='left', padx=2)
        label.title = title
        return dot, label

    def _set_indicator(self, dot, label, text, color):
        dot.itemconfigure('dot', fill=COLORS[color])
        label.configure(text='{}: {}'.format(label.title, self.render(text)))

    def set_ssh_state(self, text, color):
        self.ssh_state = (text, color)
        self._set_indicator(self.ssh_dot, self.ssh_label, text, color)

    def set_frida_state(self, text, color):
        self.frida_state = (text, color)
        self._set_indicator(self.frida_dot, self.frida_label, text, color)

    def log(self, text):
        self.log_text.configure(state='normal')
        self.log_text.insert('end', time.strftime('[%H:%M:%S] ') + self.render(text) + '\n')
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    # ------------------------------------------------------- thread plumbing
    def post(self, func, *args):
        """Run func(*args) on the Tk thread."""
        self.events.put((func, args))

    def _drain_events(self):
        try:
            while True:
                func, args = self.events.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        self.after(50, self._drain_events)

    def run_background(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    # ----------------------------------------------------------- connection
    def _save_config(self):
        data = dict(host=self.var_host.get().strip(), port=self.var_port.get().strip(),
                    user=self.var_user.get().strip(), frida_port=self.var_frida_port.get().strip(),
                    outdir=self.var_outdir.get().strip(), extract_dir=self.var_extract_dir.get().strip(),
                    lang=self.lang_setting,
                    user_only=self.var_user_only.get(), non_apple=self.var_non_apple.get(),
                    encrypted_only=self.var_encrypted_only.get(),
                    dump_dir=self.var_dump_dir.get().strip(), close_after=self.var_close_after.get(),
                    restart_frida=self.var_restart_frida.get(), repair=self.var_repair.get(),
                    dump_method=self.var_dump_method.get(),
                    name_decrypted=self.var_name_decrypted.get(), name_original=self.var_name_original.get(),
                    separate_dirs=self.var_separate_dirs.get(), font=self.var_font.get(),
                    font_size=self.var_font_size.get())
        data = {key: value for key, value in data.items() if str(value) != str(DEFAULTS[key])}
        if self.var_remember.get():
            data['password'] = self.var_password.get()
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
        except OSError as error:
            self.log(Text('log_config_fail', error=error))

    def toggle_connection(self):
        if self.ssh is not None:
            if self.dumping:
                messagebox.showwarning(self.t('m_busy_t'), self.t('m_busy'))
                return
            self.disconnect('state_disconnected')
        else:
            self.connect()

    def connect(self):
        if self.ssh is not None or self.ssh_connecting:
            return
        try:
            port = int(self.var_port.get())
        except ValueError:
            messagebox.showerror(self.t('m_param_t'), self.t('m_ports'))
            return
        host = self.var_host.get().strip()
        if not host:
            messagebox.showerror(self.t('m_param_t'), self.t('m_host'))
            return
        if not self.var_user.get().strip():
            messagebox.showerror(self.t('m_param_t'), self.t('m_user'))
            return
        if host != self.list_host:
            # The list, checks and results belong to another device.
            self.apps, self.status = {}, {}
            self.checked.clear()
            self.refresh_tree()
            self.show_details()
        self.list_host = host
        self._save_config()
        self.generation += 1
        self.ssh_connecting = True
        self.btn_connect.configure(state='disabled')
        self.set_ssh_state(Text('state_connecting'), 'busy')
        self.run_background(self._connect_worker, self.generation, host, port,
                            self.var_user.get().strip(), self.var_password.get())

    def _connect_worker(self, generation, host, port, user, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.post(self.log, Text('log_ssh_connecting', user=user, host=host, port=port))
            client.connect(host, port, user, password, timeout=10, banner_timeout=15,
                           auth_timeout=15, look_for_keys=False, allow_agent=False)
            client.get_transport().set_keepalive(10)
        except Exception as error:
            client.close()
            self.post(self._connect_failed, generation, error)
            return
        self.post(self._ssh_connected, generation, client, host)

    def _connect_failed(self, generation, error):
        self.ssh_connecting = False
        if generation != self.generation:
            return
        self.log(Text('log_ssh_failed', error=error))
        self.set_ssh_state(Text('state_failed'), 'error')
        self.btn_connect.configure(state='normal', text=self.t('connect'))

    def _ssh_connected(self, generation, client, host):
        self.ssh_connecting = False
        if generation != self.generation:
            client.close()
            return
        self.ssh = client
        self.set_ssh_state(Text('state_connected', host=host), 'ok')
        self.btn_connect.configure(state='normal', text=self.t('disconnect'))
        self.log(Text('log_ssh_ok'))
        self.load_apps()
        if self.direct_method() or dump_dir_status(self.var_dump_dir.get().strip()) == 'ok':
            self.connect_frida()
        else:
            self.set_frida_state(Text('state_no_dump'), 'idle')
            self.log(Text('log_frida_skipped'))

    def connect_frida(self, then=None):
        """Connect Frida through the SSH tunnel; then() runs once it is ready.

        Without then (connecting together with SSH) failures are only logged.
        """
        try:
            frida_port = int(self.var_frida_port.get())
        except ValueError:
            messagebox.showerror(self.t('m_param_t'), self.t('m_ports'))
            return
        if self.frida_connecting:
            return
        self.frida_connecting = True
        self.set_frida_state(Text('state_checking'), 'busy')
        self.btn_dump.configure(state='disabled')
        self.log(Text('log_frida_connecting'))
        self.run_background(self._frida_worker, self.generation, self.ssh, frida_port, then)

    def _frida_worker(self, generation, client, frida_port, then):
        def fail(state, error):
            self.post(self._frida_failed, generation, state, error, then)

        try:
            device_version, running = frida_server_status(client)
        except Exception as error:
            return fail('state_failed', error)
        self.post(self._device_frida_found, generation, device_version)
        versions = frida_versions.installed()
        self.post(self.log, Text('log_frida_versions', device=device_version or Text('not_installed'),
                                 state=Text('running' if running else 'not_running'),
                                 local=', '.join(versions) or Text('not_installed')))
        if not device_version or not running:
            return fail('state_no_server', Text('log_no_server'))
        version = frida_versions.pick(device_version, versions)
        if version is None:
            self.post(self._frida_missing, generation, device_version, then)
            return
        if version != device_version:
            self.post(self.log, Text('log_minor', local=version, device=device_version))
        tunnel = None
        try:
            tunnel = SSHTunnel(client.get_transport(), frida_port)
            # Fail fast here rather than in the middle of a batch.
            ok, detail = probe_frida(version, '127.0.0.1:{}'.format(tunnel.local_port))
        except Exception as error:
            ok, detail = False, error
        if not ok:
            if tunnel is not None:
                tunnel.close()
            return fail('state_failed', Text('log_frida_failed', error=detail))
        self.post(self._frida_connected, generation, tunnel, version, detail, then)

    def _device_frida_found(self, generation, version):
        if generation == self.generation:
            self.device_frida_version = version

    def _frida_failed(self, generation, state, error, then):
        self.frida_connecting = False
        self._checks_changed()
        if generation != self.generation:
            return
        self.set_frida_state(Text(state), 'error')
        self.log(error)
        if then is not None:
            messagebox.showerror(self.t('m_frida_t'), self.t('m_frida', error=self.render(error)))

    def _frida_missing(self, generation, device_version, then):
        """No installed frida fits the device: offer to install the device's own version."""
        self.frida_connecting = False
        self._checks_changed()
        if generation != self.generation:
            return
        self.set_frida_state(Text('state_no_local', major=major(device_version)), 'error')
        self.log(Text('log_frida_missing', device=device_version, major=major(device_version)))
        if self.dumping or not messagebox.askyesno(self.t('m_frida_get_t'), self.t(
                'm_frida_get', device=device_version, major=major(device_version),
                command=' '.join(frida_versions.install_command(device_version)))):
            return
        self.set_frida_state(Text('state_installing', version=device_version), 'busy')
        self.installing = True
        self._checks_changed()
        self.run_background(self._install_worker, device_version, None, then)

    def _frida_connected(self, generation, tunnel, version, device_os, then):
        self.frida_connecting = False
        self._checks_changed()
        if generation != self.generation or self.ssh is None:
            tunnel.close()
            return
        self.tunnel = tunnel
        self.frida_version = version
        self.device_os = device_os  # e.g. 'iPhone OS 12.4'
        self.set_frida_state(Text('state_tunnel_version', port=tunnel.local_port, version=version), 'ok')
        self.log(Text('log_frida_ok', local=tunnel.local_port, remote=self.var_frida_port.get()))
        self.log(Text('log_frida_using', version=version))
        if then is not None:
            then()

    def _drop_frida(self):
        """Forget the Frida connection (SSH stays up), e.g. before switching frida versions."""
        if self.tunnel is not None:
            self.tunnel.close()
        self.tunnel = self.frida_version = None

    def disconnect(self, reason):
        self.generation += 1
        self._drop_frida()
        if self.ssh is not None:
            self.ssh.close()
        self.ssh = self.device_frida_version = self.device_os = None
        self.set_ssh_state(Text(reason), 'idle' if reason == 'state_disconnected' else 'error')
        self.set_frida_state(Text('state_unused'), 'idle')
        self.btn_connect.configure(state='normal', text=self.t('connect'))
        self.log(Text('log_disconnected', reason=Text(reason)))

    def _watch_connection(self):
        transport = self.ssh.get_transport() if self.ssh is not None else None
        if self.ssh is not None and (transport is None or not transport.is_active()):
            self.disconnect('state_dropped')
        self.after(3000, self._watch_connection)

    # ---------------------------------------------------------------- apps
    def load_apps(self):
        if self.ssh is None:
            messagebox.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        self.log(Text('log_loading'))
        self.run_background(self._load_apps_worker, self.generation, self.ssh)

    def _load_apps_worker(self, generation, client):
        # SSH alone is enough, so original IPAs can be extracted without Frida.
        try:
            apps = device_apps.list_apps(client)
        except Exception as error:
            self.post(self.log, Text('log_load_failed', error=error))
            return
        self.post(self._apps_loaded, generation, apps)
        # Signature details need several SFTP reads per app; fill them in progressively.
        order = sorted(apps.values(), key=lambda a: (not is_user_app(a['path']), a['name'].lower()))
        try:
            sftp = client.open_sftp()
        except Exception as error:
            self.post(self.log, Text('log_sftp_failed', error=error))
            return
        try:
            for app in order:
                if generation != self.generation:
                    return
                if not app['path'] or app.get('offloaded'):
                    continue
                try:
                    info = app_info.read_app_info(sftp, app['path'])
                except Exception as error:
                    info = dict(error=str(error))
                self.post(self._app_info_loaded, generation, app['bundle'], info)
        finally:
            sftp.close()
        self.post(self._app_info_done, generation)

    def _apps_loaded(self, generation, apps):
        if generation != self.generation:
            return
        for bundle, app in apps.items():
            previous = self.apps.get(bundle)
            if previous and previous.get('version') == app['version']:
                for key in ('info', 'verify'):
                    if key in previous:
                        app[key] = previous[key]
        self.apps = apps
        self.checked = {b for b in self.checked if b in apps and not apps[b].get('offloaded')}
        user_count = sum(1 for a in apps.values() if is_user_app(a['path']))
        self.log(Text('log_loaded', total=len(apps), user=user_count))
        self.refresh_tree()

    def _app_info_done(self, generation):
        if generation != self.generation:
            return
        self.log(Text('log_info_done'))
        if self.var_encrypted_only.get():
            self.refresh_tree()  # apps found to be unencrypted can now be hidden

    def _app_info_loaded(self, generation, bundle, info):
        if generation != self.generation or bundle not in self.apps:
            return
        self.apps[bundle]['info'] = info
        self._update_row(bundle)
        if bundle in self.tree.selection():
            self.show_details()

    def _row_values(self, app):
        info = app.get('info', {})
        encrypted = info.get('encrypted')
        status, _ = self.status.get(app['bundle'], ('', ''))
        if not status and app.get('offloaded'):
            status = Text('st_offloaded')
        version = app['version']
        if app['build'] and app['build'] != app['version']:
            version = '{} ({})'.format(version, app['build']) if version else app['build']
        if app.get('offloaded'):
            check = ''
        else:
            check = CHECKED if app['bundle'] in self.checked else UNCHECKED
        return (check, app['name'], app['bundle'], version,
                '' if encrypted is None else self.t('yes' if encrypted else 'no'),
                info.get('team_id', ''), info.get('signer', '') or info.get('error', ''),
                info.get('developer', '') or info.get('profile_team', ''), self.render(status))

    def _row_tags(self, bundle):
        _, tag = self.status.get(bundle, ('', ''))
        tags = [tag] if tag else []
        if self.apps.get(bundle, {}).get('offloaded'):
            tags.append('offloaded')
        if bundle in self.checked:
            tags.append('checked')
        return tags

    def _update_row(self, bundle):
        if self.tree.exists(bundle) and bundle in self.apps:
            self.tree.item(bundle, values=self._row_values(self.apps[bundle]), tags=self._row_tags(bundle))

    def _visible_apps(self):
        needle = self.var_search.get().strip().lower()
        for app in self.apps.values():
            if self.var_user_only.get() and not is_user_app(app['path']):
                continue
            if self.var_non_apple.get() and is_apple_app(app['bundle']):
                continue
            # Apps whose signature is still being read stay visible until it is known.
            if self.var_encrypted_only.get() and app.get('info', {}).get('encrypted') is False:
                continue
            if needle and needle not in app['name'].lower() and needle not in app['bundle'].lower():
                continue
            yield app

    def refresh_tree(self):
        if self.root_frame is None:
            return
        selected = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        index = [c[0] for c in COLUMNS].index(self.sort_column)
        rows = [(app, self._row_values(app)) for app in self._visible_apps()]
        rows.sort(key=lambda row: natural_key(row[1][index]), reverse=self.sort_reverse)
        for app, values in rows:
            self.tree.insert('', 'end', iid=app['bundle'], values=values, tags=self._row_tags(app['bundle']))
        self.tree.selection_set([b for b in selected if self.tree.exists(b)])
        self.lbl_count.configure(text=self.t('count', shown=len(rows), total=len(self.apps)))
        self._checks_changed()

    def sort_by(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column, self.sort_reverse = column, False
        self.refresh_tree()

    # ------------------------------------------------------------- checks
    def set_checked(self, bundles, value):
        for bundle in bundles:
            if value and self.apps.get(bundle, {}).get('offloaded'):
                continue  # nothing on the device to extract
            if value:
                self.checked.add(bundle)
            else:
                self.checked.discard(bundle)
            self._update_row(bundle)
        self._checks_changed()

    def _checks_changed(self):
        visible = self.tree.get_children()
        all_checked = bool(visible) and all(b in self.checked for b in visible)
        self.tree.heading('check', text=CHECKED if all_checked else UNCHECKED)
        state = 'disabled' if self.dumping or not self.checked else 'normal'
        self.btn_dump.configure(text=self.t('dump', n=len(self.checked)),
                                state='disabled' if self.frida_connecting or self.installing else state)
        self.btn_extract.configure(text=self.t('extract', n=len(self.checked)), state=state)

    def on_tree_click(self, event):
        if self.dumping:
            return None
        if self.tree.identify_region(event.x, event.y) == 'cell' and self.tree.identify_column(event.x) == '#1':
            bundle = self.tree.identify_row(event.y)
            if bundle:
                rows = self.tree.get_children()
                anchor = self.check_anchor
                if event.state & SHIFT_MASK and anchor in rows and anchor != bundle:
                    # Shift-click: give the whole range the anchor's state, like file managers.
                    first, last = sorted((rows.index(anchor), rows.index(bundle)))
                    self.set_checked(rows[first:last + 1], anchor in self.checked)
                else:
                    self.set_checked([bundle], bundle not in self.checked)
                    self.check_anchor = bundle
                return 'break'
        return None

    def on_tree_menu(self, event):
        bundle = self.tree.identify_row(event.y)
        if not bundle or self.dumping:
            return 'break'
        if bundle not in self.tree.selection():
            self.tree.selection_set([bundle])
        selection = self.tree.selection()
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label=self.t('menu_check', n=len(selection)),
                         command=lambda: self.set_checked(selection, True))
        menu.add_command(label=self.t('menu_uncheck', n=len(selection)),
                         command=lambda: self.set_checked(selection, False))
        menu.tk_popup(event.x_root, event.y_root)
        return 'break'

    def on_tree_double_click(self, event):
        # A fast second click on a checkbox arrives here instead of <Button-1>,
        # so every double-click on a row toggles it exactly once.
        bundle = self.tree.identify_row(event.y)
        if bundle and not self.dumping and self.tree.identify_region(event.x, event.y) == 'cell':
            self.set_checked([bundle], bundle not in self.checked)
        return 'break'

    def on_space(self, event):
        selection = self.tree.selection()
        if selection and not self.dumping:
            self.set_checked(selection, not all(b in self.checked for b in selection))
        return 'break'

    def toggle_visible(self):
        visible = self.tree.get_children()
        if not self.dumping:
            self.set_checked(visible, not all(b in self.checked for b in visible))

    def check_all(self):
        if not self.dumping:
            self.set_checked(self.tree.get_children(), True)

    def check_none(self):
        if not self.dumping:
            self.set_checked(list(self.checked), False)

    def check_failed(self):
        if not self.dumping:
            failed = [b for b, (_, tag) in self.status.items() if tag == 'failed' and b in self.apps]
            self.set_checked(list(self.checked), False)
            self.set_checked(failed, True)

    def check_partial(self):
        """Check apps whose decrypted IPA still has encrypted files (verified this session, or found
        in the output folder under a partial file name)."""
        if self.dumping:
            return
        partial = []
        for bundle in self.tree.get_children():
            app = self.apps[bundle]
            verify = app.get('verify')
            if verify:
                if verify['status'] != ipa_verify.DECRYPTED:
                    partial.append(bundle)
                continue
            try:
                names = {kind: self.ipa_name(app, 'dump', kind) for kind in DUMP_KINDS}
            except app_info.NameTemplateError as error:
                self._show_name_error('dump', error)
                return
            exists = {kind: os.path.exists(os.path.join(self.output_dir('dump'), name + '.ipa'))
                      for kind, name in names.items()}
            # Without {type} in the template every result has the same name and cannot be told apart.
            if not exists[ipa_verify.DECRYPTED] and any(exists[k] for k in DUMP_KINDS[1:]):
                partial.append(bundle)
        self.set_checked(list(self.checked), False)
        self.set_checked(partial, True)

    def check_unextracted(self):
        """Check shown apps with neither a decrypted nor an original IPA under the current file names."""
        if self.dumping:
            return
        missing = []
        for bundle in self.tree.get_children():
            app = self.apps[bundle]
            if app.get('offloaded'):
                continue
            paths = []
            for mode, kinds in (('dump', DUMP_KINDS), ('extract', (None,))):
                try:
                    paths += [os.path.join(self.output_dir(mode), self.ipa_name(app, mode, kind) + '.ipa')
                              for kind in kinds]  # a partially decrypted IPA counts as extracted
                except app_info.NameTemplateError as error:
                    self._show_name_error(mode, error)
                    return
            if not any(os.path.exists(path) for path in paths):
                missing.append(bundle)
        self.set_checked(list(self.checked), False)
        self.set_checked(missing, True)

    def check_invert(self):
        if not self.dumping:
            visible = self.tree.get_children()
            was_checked = [b for b in visible if b in self.checked]
            self.set_checked([b for b in visible if b not in self.checked], True)
            self.set_checked(was_checked, False)

    def show_details(self):
        selection = self.tree.selection()
        lines = []
        if len(selection) == 1 and selection[0] in self.apps:
            app = self.apps[selection[0]]
            info = app.get('info', {})
            encrypted = info.get('encrypted')
            archs = info.get('archs') or []
            bits = {64: 'arch_64', 32: 'arch_32', 0: 'arch_both'}[app_info.arch_bits(archs)] if archs else ''
            arch = '{} ({})'.format(self.t(bits), ', '.join(archs)) if archs else ''
            developer = self.t('d_dev', dev=info.get('developer', ''))
            if info.get('profile'):
                # Only developer, ad hoc, enterprise and sideloaded builds embed a provisioning profile.
                developer += '    ' + self.t('d_profile', profile=info['profile'], team=info.get('profile_team', ''))
            lines = [
                self.t('d_app', name=app['name'], bundle=app['bundle'], version=app['version'],
                       build=app['build'], pid=app['pid'] or self.t('d_not_running')),
                self.t('d_binary', exe=info.get('executable', ''), arch=arch, min_os=info.get('min_os', ''),
                       enc='?' if encrypted is None else (self.t('d_enc_yes') if encrypted else self.t('no'))),
                self.t('d_sign', signer=info.get('signer', ''), team=info.get('team_id', ''),
                       ident=info.get('identifier', '')),
                developer,
                self.t('d_path', path=app['path']),
                self.t('d_data', path=app['data']),
            ]
            try:
                verified = (app.get('verify') or {}).get('status')  # the name the last extraction got
                lines.append(self.t('d_output', decrypted=self.ipa_name(app, 'dump', verified) + '.ipa',
                                    original=self.ipa_name(app, 'extract') + '.ipa'))
            except app_info.NameTemplateError:
                pass
            verify = app.get('verify')
            if verify:
                if verify['status'] == ipa_verify.DECRYPTED:
                    lines.append(self.t('d_verify_ok', n=verify['total']))
                elif verify['status'] == ipa_verify.PARTIAL_32BIT:
                    lines.append(self.t('d_verify_partial32', n=len(verify['files']), total=verify['total']))
                else:
                    lines.append(self.t('d_verify_partial', n=len(verify['files']), total=verify['total']))
                lines += ['    ' + self.t('log_verify_file', file=f['file'], archs=f['archs'],
                                           reason=self.render(self.reason_text(f))) for f in verify['files']]
            if app.get('offloaded'):
                lines.append(self.t('d_offloaded'))
            if info.get('error'):
                lines.append(self.t('d_error', error=info['error']))
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        self.details.insert('end', '\n'.join(lines))
        self.details.configure(state='disabled')

    def set_status(self, bundle, text, tag=''):
        self.status[bundle] = (text, tag)
        self._update_row(bundle)

    # ---------------------------------------------------------------- dump
    def choose_dir(self, var, fallback=script_dir, parent=None):
        path = filedialog.askdirectory(initialdir=var.get() or fallback, parent=parent or self)
        if path:
            var.set(os.path.normpath(path))
            self._save_config()

    def open_dir(self, path):
        try:
            os.makedirs(path, exist_ok=True)
            if IS_WINDOWS:
                os.startfile(path)
            else:
                subprocess.Popen(['open' if IS_MACOS else 'xdg-open', path])
        except OSError as error:
            messagebox.showerror(self.t('m_outdir_t'), str(error))

    def _checked_in_order(self):
        # Process in the order shown in the list.
        shown = list(self.tree.get_children())
        bundles = [b for b in shown if b in self.checked]
        bundles += sorted(b for b in self.checked if b not in shown and b in self.apps)
        if not bundles:
            messagebox.showinfo(self.t('m_none_t'), self.t('m_none'))
        return bundles

    def _jobs(self, mode, bundles):
        """[(bundle, ipa base name)], or None after telling the user the file names cannot be used."""
        try:
            jobs = [(bundle, self.ipa_name(self.apps[bundle], mode)) for bundle in bundles]
        except app_info.NameTemplateError as error:
            self._show_name_error(mode, error)
            return None
        owners = {}
        for bundle, name in jobs:
            owners.setdefault(name.lower(), (name, []))[1].append(bundle)  # Windows file names ignore case
        clashes = ['{}.ipa: {}'.format(name, ', '.join(b)) for name, b in owners.values() if len(b) > 1]
        if clashes:
            messagebox.showerror(self.t('m_dup_t'), self.t(
                'm_dup', files='\n'.join(clashes[:15]) + ('\n…' if len(clashes) > 15 else '')))
            self.open_settings(tab=1)
            return None
        return jobs

    def check_dump_dir(self, dump_dir):
        """True when frida-ios-dump at dump_dir can run; otherwise offer to fix it."""
        if dump_dir_status(dump_dir) == 'ok':
            return True
        self.install_dependencies()  # explains an unset folder, offers a download or the npm install
        return False

    def _prepare_batch(self, mode, jobs, names=None):
        """Check the output folder and overwrites, then mark jobs queued. Returns the folder or None.

        names ({bundle: {kind: name}}) lists every name a decrypted IPA may end up with.
        """
        outdir = self.output_dir(mode)
        try:
            os.makedirs(outdir, exist_ok=True)
        except OSError as error:
            messagebox.showerror(self.t('m_outdir_t'), str(error))
            return None
        candidates = [n for bundle, name in jobs
                      for n in dict.fromkeys(names[bundle].values() if names else [name])]
        existing = [n + '.ipa' for n in candidates if os.path.exists(os.path.join(outdir, n + '.ipa'))]
        if existing and not messagebox.askyesno(self.t('m_overwrite_t'), self.t(
                'm_overwrite', files='\n'.join(existing[:15]) + ('\n…' if len(existing) > 15 else ''))):
            return None
        self._save_config()
        self.dumping = True
        self.cancel_requested.clear()
        self.btn_cancel.configure(state='normal')
        for bundle, _ in jobs:
            self.set_status(bundle, Text('st_queued'), 'queued')
        self._checks_changed()
        self._set_overall(0, None)
        return outdir

    def start_dump(self):
        if self.dumping:
            return
        if self.ssh is None:
            messagebox.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        bundles = self._checked_in_order()
        if not bundles:
            return
        direct = self.direct_method()
        dump_dir = self.var_dump_dir.get().strip()
        if not direct and not self.check_dump_dir(dump_dir):
            return
        jobs = self._jobs('dump', bundles)
        if jobs is None:
            return
        if self.frida_version is None or self.tunnel is None:
            self.connect_frida(then=self.start_dump)
            return
        # A decrypted IPA is named after its verification result, so any of these may be written.
        names = {bundle: {kind: self.ipa_name(self.apps[bundle], 'dump', kind) for kind in DUMP_KINDS}
                 for bundle, _ in jobs}
        outdir = self._prepare_batch('dump', jobs, names)
        if outdir is None:
            return
        self.log(Text('log_start_direct' if direct else 'log_start', n=len(jobs)))
        options = dict(direct=direct, method=decrypt_method(self.device_os),
                       host=self.var_host.get().strip(), port=self.var_port.get().strip(),
                       user=self.var_user.get().strip(), password=self.var_password.get(),
                       frida='127.0.0.1:{}'.format(self.tunnel.local_port), frida_version=self.frida_version,
                       outdir=outdir,
                       dump_dir=dump_dir, close_after=self.var_close_after.get(),
                       restart_frida=self.var_restart_frida.get(), generation=self.generation, names=names,
                       repair=direct or self.var_repair.get(), ios=self.device_os or '')
        self.run_background(self._dump_worker, jobs, options)

    def start_extract(self):
        if self.dumping:
            return
        if self.ssh is None or not self.apps:
            messagebox.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        bundles = self._checked_in_order()
        if not bundles:
            return
        jobs = self._jobs('extract', bundles)
        if jobs is None:
            return
        outdir = self._prepare_batch('extract', jobs)
        if outdir is None:
            return
        self.log(Text('log_extract_start', n=len(jobs)))
        self.run_background(self._extract_worker, jobs, outdir)

    def _extract_worker(self, jobs, outdir):
        succeeded = 0
        try:
            for index, (bundle, name) in enumerate(jobs):
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

    def cancel_batch(self):
        if not messagebox.askyesno(self.t('m_cancel_t'), self.t('m_cancel')):
            return
        self.cancel_requested.set()
        process = self.current_process
        if process is not None and process.poll() is None:
            process.terminate()
        self.log(Text('log_cancel'))

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
            for attempt in (1, 2):
                if options['direct']:
                    # Only SSH is involved: a copy that broke off (Wi-Fi, a stalled channel) is tried once more.
                    ok, message = self._copy_bundle(index, total, bundle, name, options)
                    kind = None
                    if ok or self.cancel_requested.is_set() or attempt == 2:
                        break
                    self.post(self.log, Text('log_failed', bundle=bundle, msg=message))
                    self.post(self.log, Text('log_retry', bundle=bundle))
                    continue
                ok, message = self._dump_one(index, total, bundle, name, options)
                kind = None if ok else classify_error(message)
                if ok or self.cancel_requested.is_set() or attempt == 2 or kind not in RETRY_ERRORS:
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
        final = os.path.join(options['outdir'], options['names'][bundle][status] + '.ipa')
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
        self.post(self._set_verify, bundle, status, len(result.files), files)
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
                if todo:
                    self._run_repair_worker(bundle, todo, work, options, pid)
                # frida-server sometimes crashes or stops responding: when asked, restart it (killing a
                # crashed one is harmless) and try what it took down again, as long as that gets further.
                for _ in range(REPAIR_RETRIES):
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
                if any(job.connection_lost() for job in todo if not job.repaired):
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
                failures[job.member] = repair_failure(error)
        self.post(self.log, Text('log_repair_done', bundle=bundle, n=changed, total=len(jobs)))
        return failures

    def _run_repair_worker(self, bundle, jobs, work, options, pid):
        """Run repair_worker.py with the device's frida; marks each job's decrypted slices."""
        jobs_path = os.path.join(work, 'jobs.json')
        with open(jobs_path, 'w', encoding='utf-8') as handle:
            json.dump([job.to_json() for job in jobs], handle)
        command = [sys.executable, '-u', REPAIR_WORKER, options['frida'], jobs_path, work,
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

    def _set_verify(self, bundle, status, total, files):
        """Remember the verification result for the details pane and "Check partially decrypted apps"."""
        if bundle in self.apps:
            self.apps[bundle]['verify'] = dict(status=status, total=total, files=files)
            if bundle in self.tree.selection():
                self.show_details()

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
            ok, error = probe_frida(options['frida_version'], address)
            if options['generation'] != self.generation:
                return False  # disconnected meanwhile; the tunnel is gone
            if ok:
                self.post(self.log, Text('log_restarted'))
                self._release_gated(options, bundle)
                return True
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
        command = [sys.executable, '-u', WORKER, bundle, '-R', options['frida'],
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

    def direct_method(self):
        """Whether decrypted IPAs are made by decrypting the installed files (R4), not by frida-ios-dump."""
        return self.var_dump_method.get() == METHOD_FRIDA_DIRECT

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

    def _set_overall(self, value, text):
        self.overall = (value, text)
        self.progress['value'] = value
        if isinstance(text, tuple):
            text = text[0] + self.render(text[1])
        self.lbl_progress.configure(text=self.render(text or '')[:PROGRESS_LABEL_CHARS])

    def _batch_finished(self, mode, outdir, succeeded, total, paused, partial=0):
        self.dumping = False
        self.btn_cancel.configure(state='disabled')
        if self.cancel_requested.is_set():
            self._set_overall(0, Text('progress_cancelled', ok=succeeded, total=total))
        elif paused:
            self._set_overall(self.progress['value'], Text('progress_paused', ok=succeeded, total=total))
        else:
            if succeeded == total:
                self._set_overall(100, Text('progress_done', total=total))
            else:
                self._set_overall(100, Text('progress_done_failed', ok=succeeded, failed=total - succeeded))
        self._checks_changed()
        self.log(Text('log_extract_finished' if mode == 'extract' else 'log_finished',
                      ok=succeeded, total=total, dir=outdir))
        if partial:
            self.log(Text('log_partial_summary', n=partial))
        if paused:
            messagebox.showwarning(self.t('m_paused_t'), self.t('m_paused', n=MAX_CONSECUTIVE_FRIDA_ERRORS))

    # ------------------------------------------------------- dependencies
    def install_frida_ios_dump(self):
        """Download frida-ios-dump into a folder the user picks."""
        parent = filedialog.askdirectory(title=self.t('install_dump_pick'), parent=self.settings_window or self,
                                         initialdir=os.path.dirname(DEFAULT_DUMP_DIR))
        if not parent:
            return
        parent = os.path.normpath(parent)
        # An empty folder is used as is; otherwise it gets a frida-ios-dump subfolder.
        target = parent if not os.listdir(parent) else os.path.join(parent, 'frida-ios-dump')
        self.offer_download(target, 'm_download_to')

    def offer_download(self, dump_dir, question='m_download'):
        if os.path.isdir(dump_dir) and os.listdir(dump_dir):
            messagebox.showerror(self.t('m_download_t'), self.t('m_dump_dir_busy', path=dump_dir))
            self.open_settings(tab=2)
            return
        if not messagebox.askyesno(self.t('m_download_t'),
                                   self.t(question, path=dump_dir, url=FRIDA_IOS_DUMP_URL)):
            return
        self.var_dump_dir.set(dump_dir)
        self._save_config()
        self.btn_dump.configure(state='disabled')
        self.log(Text('log_downloading', path=dump_dir))
        self.run_background(self._download_worker, dump_dir)

    def _download_worker(self, dump_dir):
        try:
            download_frida_ios_dump(dump_dir, lambda line: self.post(self.log, '  ' + line))
        except Exception as error:
            self.post(self.log, Text('log_download_failed', error=error))
            self.post(self._checks_changed)
            return
        self.post(self._download_done)

    def _download_done(self):
        self.log(Text('log_download_done'))
        self.var_dump_dir.set(self.var_dump_dir.get())  # refresh the status shown in Settings
        self._checks_changed()
        # Its confirmation lists the commands it is about to run.
        self.install_dependencies()

    def install_dependencies(self):
        if self.dumping:
            return
        if self.direct_method():
            # Decrypting the files directly needs frida only, not frida-ios-dump or its npm packages.
            self.open_install_dialog(None)
            return
        dump_dir = self.var_dump_dir.get().strip()
        state = dump_dir_status(dump_dir)
        if state == 'empty':
            messagebox.showerror(self.t('m_no_dump_dir_t'), self.t('m_no_dump_dir'))
            self.open_settings(tab=2)
            return
        if state == 'missing':
            self.offer_download(dump_dir)  # installs dependencies once downloaded
            return
        self.open_install_dialog(dump_dir)

    def open_install_dialog(self, dump_dir):
        """Let the user pick the frida version to install; the dialog doubles as the confirmation."""
        if self.install_window is not None and self.install_window.winfo_exists():
            self.install_window.lift()
            return
        window = self.install_window = tk.Toplevel(self)
        window.title('{} – Install Frida dependencies'.format(APP_NAME))
        window.transient(self)
        window.resizable(True, False)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill='both', expand=True)
        device = [self.device_frida_version]
        # 'found', 'missing' (no frida-server on the device), 'no_ssh' or 'checking'
        device_state = ['found' if device[0] else ('no_ssh' if self.ssh is None else 'checking')]
        latest = [None]
        choice = tk.StringVar(value='device' if device[0] else 'latest')
        custom = tk.StringVar()
        versions = ttk.Label(frame)
        versions.pack(anchor='w', pady=(0, 8))
        # Installed versions, each with a delete button.
        ttk.Label(frame, text=self.t('inst_installed')).pack(anchor='w')
        installed_frame = ttk.Frame(frame)
        installed_frame.pack(fill='x', padx=(16, 0), pady=(2, 10))
        ttk.Label(frame, text=self.t('inst_add')).pack(anchor='w', pady=(0, 2))
        device_option = ttk.Radiobutton(frame, variable=choice, value='device')
        device_option.pack(anchor='w')
        latest_option = ttk.Radiobutton(frame, variable=choice, value='latest',
                                        text=self.t('inst_latest', version=self.t('inst_loading')))
        latest_option.pack(anchor='w', pady=2)
        custom_row = ttk.Frame(frame)
        custom_row.pack(anchor='w')
        ttk.Radiobutton(custom_row, variable=choice, value='custom', text=self.t('inst_custom')).pack(side='left')
        custom_box = ttk.Combobox(custom_row, textvariable=custom, width=14)
        custom_box.pack(side='left', padx=4)
        custom_box.bind('<<ComboboxSelected>>', lambda e: choice.set('custom'))
        custom_box.bind('<KeyRelease>', lambda e: choice.set('custom'))
        warning = WrapLabel(frame, foreground='#57606a', justify='left')
        warning.pack(fill='x', pady=(6, 0))
        WrapLabel(frame, text=self.t('inst_will_run', path=frida_versions.ROOT), justify='left').pack(
            fill='x', pady=(10, 2))
        commands_text = tk.Text(frame, height=5, width=80, wrap='char', font='TkTextFont',
                                background=self.theme_background, relief='solid', borderwidth=1)
        commands_text.pack(fill='x')
        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(12, 0))
        ttk.Button(buttons, text=self.t('inst_cancel'), command=window.destroy).pack(side='right')
        run_button = ttk.Button(buttons, text=self.t('inst_run'))
        run_button.pack(side='right', padx=6)

        def selected():
            version = {'device': device[0], 'latest': latest[0], 'custom': custom.get().strip()}[choice.get()]
            return version if version and re.fullmatch(r'\d+\.\d+\.\d+', version) else None

        def delete(version):
            if self.dumping or self.installing:
                return
            if not messagebox.askyesno(self.t('m_frida_delete_t'), self.t('m_frida_delete', version=version),
                                       parent=window):
                return
            in_use = version == self.frida_version
            if in_use:
                self._drop_frida()
                self.set_frida_state(Text('state_unused'), 'idle')
            try:
                frida_versions.remove(version)
                self.log(Text('log_frida_deleted', version=version))
            except OSError as error:
                messagebox.showerror(self.t('m_frida_delete_t'), str(error), parent=window)
            refresh()
            if in_use and self.ssh is not None:
                self.connect_frida()  # picks another installed version, or offers a download

        def refresh_installed():
            for child in installed_frame.winfo_children():
                child.destroy()
            installed = frida_versions.installed()
            if not installed:
                ttk.Label(installed_frame, text=self.t('not_installed'), foreground='#57606a').pack(anchor='w')
            for version in installed:
                row = ttk.Frame(installed_frame)
                row.pack(fill='x', pady=1)
                text = version
                if version == self.frida_version:
                    text = self.t('inst_in_use', version=version)
                elif device[0] and version == frida_versions.pick(device[0], installed):
                    text = self.t('inst_for_device', version=version)
                ttk.Label(row, text=text, width=28).pack(side='left')
                ttk.Button(row, text=self.t('inst_delete'), command=lambda v=version: delete(v)).pack(side='left')

        def refresh(*args):
            if not window.winfo_exists():
                return
            state = device_state[0]
            shown = {'found': device[0], 'missing': self.t('not_installed'), 'no_ssh': self.t('inst_no_ssh'),
                     'checking': self.t('inst_checking')}[state]
            versions.configure(text=self.t('inst_device_version', device=shown))
            refresh_installed()
            device_option.configure(
                text={'found': self.t('inst_device', version=device[0]),
                      'missing': self.t('inst_device_missing'), 'no_ssh': self.t('inst_device_no_ssh'),
                      'checking': self.t('inst_device_checking')}[state],
                state='normal' if device[0] else 'disabled')
            version = selected()
            if version and version in frida_versions.installed():
                warning.set_text(self.t('inst_reinstall', version=version))
            elif version and device[0] and major(version) != major(device[0]):
                warning.set_text(self.t('inst_other_major', device=device[0]))
            else:
                warning.set_text('')
            commands = self._install_commands(version or '?', dump_dir)
            commands_text.configure(state='normal')
            commands_text.delete('1.0', 'end')
            commands_text.insert('end', '\n'.join('{}   ({})'.format(' '.join(c), cwd) for c, cwd in commands))
            commands_text.configure(state='disabled')
            run_button.configure(state='normal' if version and not self.installing else 'disabled')

        def loaded(found_device, releases, error):
            if not window.winfo_exists():
                return
            if device_state[0] == 'checking':
                device_state[0] = found_device
            if found_device not in ('missing', 'no_ssh') and not device[0]:
                device[0] = self.device_frida_version = found_device
                device_state[0] = 'found'
                choice.set('device')
            if releases:
                latest[0] = releases[0]
                latest_option.configure(text=self.t('inst_latest', version=releases[0]))
                custom_box.configure(values=releases)
            else:
                latest_option.configure(text=self.t('inst_fetch_failed', error=error), state='disabled')
                if choice.get() == 'latest':
                    choice.set('custom')
            refresh()

        def fetch():
            found_device = device_state[0]
            if device_state[0] == 'checking':
                try:
                    found_device = frida_server_status(self.ssh)[0] or 'missing'
                except Exception:
                    found_device = 'no_ssh'
            try:
                releases, error = frida_releases(), None
            except Exception as exc:
                releases, error = [], exc
            self.post(loaded, found_device, releases, error)

        def run():
            version = selected()
            if not version or self.dumping or self.installing:
                return
            window.destroy()
            self.installing = True
            self._checks_changed()
            self.run_background(self._install_worker, version, dump_dir, None)

        run_button.configure(command=run)
        choice.trace_add('write', refresh)
        custom.trace_add('write', refresh)
        refresh()
        self.run_background(fetch)

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

    def _install_worker(self, version, dump_dir, then):
        """Install frida `version` side by side with the others; then() runs once Frida reconnects."""
        ok = False
        try:
            commands = self._install_commands(version, dump_dir)
            frida_versions.prepare_install(version)
            if self._run_command(*commands[0]):
                frida_versions.finish_install(version)
                ok = all(self._run_command(*command) for command in commands[1:])
            else:
                shutil.rmtree(frida_versions.staging(version), ignore_errors=True)
        except OSError as error:
            self.post(self.log, Text('log_exec_failed', error=error))
        finally:
            self.post(self._install_finished, version, ok, then)

    def _install_finished(self, version, ok, then):
        self.installing = False
        self._checks_changed()
        if not ok:
            if self.ssh is not None and self.frida_version is None:
                self.set_frida_state(Text('state_failed'), 'error')
            return
        self.log(Text('log_frida_installed', version=version))
        # No restart needed: reconnect so the best version for this device is picked again.
        if self.ssh is not None and not self.dumping and dump_dir_status(self.var_dump_dir.get().strip()) == 'ok':
            self._drop_frida()
            self.connect_frida(then)

    # --------------------------------------------------------------- close
    def on_close(self):
        if self.dumping:
            if not messagebox.askyesno(self.t('m_busy_t'), self.t('m_close')):
                return
            self.cancel_requested.set()
            if self.current_process is not None and self.current_process.poll() is None:
                self.current_process.terminate()
        self._save_config()
        if self.ssh is not None:
            self.disconnect('state_disconnected')
        self.destroy()


def install_base_packages():
    """Ask to pip install what the tool needs to start; True once paramiko imports."""
    global paramiko
    locales = i18n.load_locales()
    strings = locales[i18n.resolve(locales, load_config().get('lang', i18n.AUTO))]

    def t(key, **params):
        return (strings.get(key) or locales[i18n.FALLBACK][key]).format(**params)

    root = tk.Tk()
    root.withdraw()
    command = pip_install(BASE_PACKAGES)
    if not messagebox.askyesno(t('m_missing_t'), t('m_missing', packages='\n'.join(BASE_PACKAGES),
                                                   command=' '.join(command))):
        root.destroy()
        return False
    root.configure(cursor='watch')
    process = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                             creationflags=NO_WINDOW)
    try:
        if process.returncode:
            raise RuntimeError((process.stdout + process.stderr).strip()[-1500:])
        import importlib
        importlib.invalidate_caches()
        paramiko = importlib.import_module('paramiko')
    except Exception as error:
        messagebox.showerror(t('m_missing_t'), t('m_missing_failed', error=error))
        root.destroy()
        return False
    root.destroy()
    return True


def main():
    if IS_WINDOWS:
        # Without its own app ID, pythonw's taskbar button shows the Python icon.
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('IPAExtractor')
        except (AttributeError, OSError):
            pass
    if paramiko is None and not install_base_packages():
        return
    DumpGUI().mainloop()


if __name__ == '__main__':
    main()
