#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPA Extractor: Tkinter GUI that pulls original or decrypted IPAs off a jailbroken device over SSH."""

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import tkinter.font as tkfont

import app_info
import device_apps
import engine
import frida_versions
import i18n
import ipa_verify
import native_decrypt
import remote
from engine import (
    APP_NAME, ASSETS, BASE_PACKAGES, DEFAULTS, DEFAULT_DUMP_DIR, DEFAULT_FONT_SIZE, DUMP_KINDS, FRIDA_IOS_DUMP_URL,
    IS_MACOS, IS_WINDOWS, MAX_CONSECUTIVE_FRIDA_ERRORS, METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP, METHOD_NATIVE,
    NO_WINDOW, THEMES, THEME_BLACK, THEME_DARK, THEME_LIGHT, DumpEngine, Indented, SSHTunnel, Text, __version__,
    decrypt_method, download_frida_ios_dump, dump_dir_status, dump_method_setting, frida_method_setting,
    frida_releases, frida_server_status, ios_major, is_apple_app, is_user_app, load_config, major, natural_key,
    open_ssh, pip_install, probe_frida, resolve_theme, script_dir, theme_setting)

CHECKED, UNCHECKED = '☑', '☐'
# UI colours per theme (the theme setting). Light keeps the platform's native look; dark and black
# restyle ttk's "clam" theme. PALETTE holds the current one and is changed in place.
_STATUS_LIGHT = dict(ok='#1a7f37', busy='#d4a72c', error='#cf222e', idle='#8c959f',
                     partial='#bc4c00', running='#0969da', queued='#9a6700')
_STATUS_DARK = dict(ok='#3fb950', busy='#d29922', error='#f85149', idle='#6e7681',
                    partial='#f0883e', running='#58a6ff', queued='#d29922')
PALETTES = {
    THEME_LIGHT: dict(bg='#f0f0f0', fg='#000000', field='#ffffff', button='#e1e1e1', hover='#e5f1fb', border='#adadad',
                      select='#0078d7', muted='#57606a', checked='#ddf4ff', tooltip='#ffffe0', accent='#0078d7',
                      **_STATUS_LIGHT),
    THEME_DARK: dict(bg='#202020', fg='#e6e6e6', field='#2b2b2b', button='#333333', hover='#404040', border='#4a4a4a',
                     select='#264f78', muted='#9da5ae', checked='#1c3a57', tooltip='#2d2d2d', accent='#2f81f7',
                     **_STATUS_DARK),
    THEME_BLACK: dict(bg='#000000', fg='#e6e6e6', field='#000000', button='#141414', hover='#262626', border='#3a3a3a',
                      select='#1b3d63', muted='#8b949e', checked='#0d2a47', tooltip='#111111', accent='#2f81f7',
                      **_STATUS_DARK),
}
PALETTE = dict(PALETTES[THEME_LIGHT])




# Named Tk fonts the UI uses; all follow the font chosen in Settings.
UI_FONTS = ('TkDefaultFont', 'TkTextFont', 'TkMenuFont', 'TkHeadingFont', 'TkCaptionFont',
            'TkSmallCaptionFont', 'TkIconFont', 'TkTooltipFont')
# Fonts sv-ttk's widgets use instead of the Tk named fonts.
SUN_VALLEY_FONTS = ('SunValleyBodyFont', 'SunValleyBodyStrongFont', 'SunValleyCaptionFont')
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

UNSPACED = '฀-๿぀-ヿ㐀-鿿豈-﫿'
WRAP_TOKEN = re.compile(r'(?:[^\W' + UNSPACED + r']|[.\-/\\:@{}()«»„“”‘’"])+|\s+|.')


def wrap_text(text, width, font='TkDefaultFont'):
    """Insert line breaks so text fits width pixels.

    Tk only breaks lines at spaces, which Chinese, Japanese and Thai text rarely has, so this
    breaks between any two characters of those scripts, and otherwise only between words.
    """
    font = tkfont.nametofont(font) if isinstance(font, str) else font
    lines = []
    for paragraph in text.split('\n'):
        line = ''
        for token in WRAP_TOKEN.findall(paragraph):
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
        tk.Label(self.window, text=wrap_text(self.text, 420), justify='left', background=PALETTE['tooltip'],
                 foreground=PALETTE['fg'], relief='solid', borderwidth=1, padx=6, pady=4).pack()

    def hide(self, event=None):
        if self.window is not None:
            self.window.destroy()
            self.window = None



class DumpGUI(DumpEngine, tk.Tk):
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
        self.helper_warned = False
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
        self.var_native_helper = tk.StringVar(value=native_decrypt.setting(c['native_helper']))
        self.frida_method = frida_method_setting(c['frida_method'], self.var_dump_method.get())
        self.var_family = tk.StringVar(value='native' if self.var_dump_method.get() == METHOD_NATIVE else 'frida')
        self.var_name_decrypted = tk.StringVar(value=c['name_decrypted'])
        self.var_name_original = tk.StringVar(value=c['name_original'])
        self.var_separate_dirs = tk.BooleanVar(value=c['separate_dirs'])
        self.var_theme = tk.StringVar(value=theme_setting(c['theme']))
        self.var_font = tk.StringVar(value=c['font'])  # '' follows the language
        self.var_font_size = tk.StringVar(value=str(c['font_size']))
        self.var_lang = tk.StringVar()
        self.var_search.trace_add('write', lambda *a: self.refresh_tree())
        self.style = ttk.Style(self)
        self.apply_theme()
        self.apply_icon()
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
        """Light: native theme on Windows and macOS, Sun Valley (sv-ttk) on Linux instead of Tk's dated
        default. Dark and black: "clam" restyled with the palette (black is a pure black background)."""
        name = resolve_theme(self.var_theme.get())     # the system's choice is read here, once per start or change
        PALETTE.clear()
        PALETTE.update(PALETTES[name])
        if name == THEME_LIGHT:
            if IS_WINDOWS:
                self.style.theme_use('vista')
            elif IS_MACOS:
                self.style.theme_use('aqua')
            else:
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
            if getattr(self, 'dark_options', False):
                self.option_clear()
                self.dark_options = False
        else:
            self._style_dark(PALETTE)
            self.theme_background = PALETTE['bg']
        self.configure(background=self.theme_background)
        self.style.configure('TNotebook.Tab', padding=(18, 7))
        if hasattr(self, 'installed_fonts'):
            self.apply_fonts()

    def _style_dark(self, p):
        style = self.style
        style.theme_use('clam')
        style.configure('.', background=p['bg'], foreground=p['fg'], fieldbackground=p['field'],
                        bordercolor=p['border'], lightcolor=p['border'], darkcolor=p['border'],
                        troughcolor=p['field'], insertcolor=p['fg'], selectbackground=p['select'],
                        selectforeground=p['fg'], focuscolor=p['bg'], arrowcolor=p['fg'])
        style.map('.', foreground=[('disabled', p['muted'])], background=[('disabled', p['bg']), ('active', p['bg'])])
        style.configure('TButton', background=p['button'], padding=(8, 3))
        style.map('TButton', background=[('disabled', p['bg']), ('pressed', p['select']), ('active', p['hover'])])
        style.configure('TEntry', fieldbackground=p['field'], padding=2)
        style.map('TEntry', fieldbackground=[('disabled', p['bg'])])
        style.configure('TSpinbox', fieldbackground=p['field'], background=p['button'])
        style.map('TSpinbox', fieldbackground=[('disabled', p['bg'])])
        style.configure('TCombobox', fieldbackground=p['field'], background=p['button'])
        style.map('TCombobox', fieldbackground=[('disabled', p['bg']), ('readonly', p['field'])],
                  foreground=[('disabled', p['muted'])], selectbackground=[('readonly', p['field'])],
                  selectforeground=[('readonly', p['fg'])])
        for kind in ('TCheckbutton', 'TRadiobutton'):
            style.configure(kind, indicatorbackground=p['field'], indicatorforeground=p['fg'],
                            upperbordercolor=p['border'], lowerbordercolor=p['border'])
            style.map(kind, indicatorbackground=[('disabled', p['bg']), ('pressed', p['hover']), ('!disabled', p['field'])],
                      indicatorforeground=[('disabled', p['muted'])])
        style.configure('TNotebook', background=p['bg'], bordercolor=p['border'])
        style.configure('TNotebook.Tab', background=p['button'], foreground=p['fg'])
        # clam shrinks the selected tab through its own padding map; give it the tab padding, 2 px taller on top
        style.map('TNotebook.Tab', background=[('selected', p['bg']), ('active', p['hover'])],
                  padding=[('selected', (18, 9, 18, 7))])
        style.configure('Treeview', background=p['field'], fieldbackground=p['field'], foreground=p['fg'])
        style.map('Treeview', background=[('selected', p['select'])], foreground=[('selected', p['fg'])])
        style.configure('Treeview.Heading', background=p['button'], foreground=p['fg'], relief='flat')
        style.map('Treeview.Heading', background=[('active', p['hover'])])
        style.configure('TScrollbar', background=p['button'], troughcolor=p['bg'], bordercolor=p['bg'],
                        arrowcolor=p['fg'])
        style.map('TScrollbar', background=[('active', p['hover'])])
        style.configure('TProgressbar', background=p['accent'], troughcolor=p['field'])
        style.configure('TLabelframe', background=p['bg'], bordercolor=p['border'])
        style.configure('TLabelframe.Label', background=p['bg'], foreground=p['fg'])
        style.configure('TSeparator', background=p['border'])
        style.configure('Sash', background=p['border'])
        # Classic Tk widgets and the combobox drop-down list follow the option database.
        for pattern, value in (('*Text.background', p['field']), ('*Text.foreground', p['fg']),
                               ('*Text.insertBackground', p['fg']), ('*Text.selectBackground', p['select']),
                               ('*Text.selectForeground', p['fg']),
                               ('*Menu.background', p['field']), ('*Menu.foreground', p['fg']),
                               ('*Menu.activeBackground', p['select']), ('*Menu.activeForeground', p['fg']),
                               ('*TCombobox*Listbox.background', p['field']),
                               ('*TCombobox*Listbox.foreground', p['fg']),
                               ('*TCombobox*Listbox.selectBackground', p['select']),
                               ('*TCombobox*Listbox.selectForeground', p['fg'])):
            self.option_add(pattern, value)
        self.dark_options = True

    def style_titlebar(self, window):
        """Dark title bar on Windows 10 and 11 for the dark themes; other systems keep theirs."""
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            window.update_idletasks()
            handle = ctypes.windll.user32.GetParent(window.winfo_id())
            value = ctypes.c_int(0 if resolve_theme(self.var_theme.get()) == THEME_LIGHT else 1)
            for attribute in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE, and its number before Windows 10 20H1
                ctypes.windll.dwmapi.DwmSetWindowAttribute(handle, attribute, ctypes.byref(value), ctypes.sizeof(value))
        except (OSError, AttributeError, tk.TclError):
            pass

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
        self.show_frida_indicator()

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
        WrapLabel(table, text=self.t('hint'), foreground=PALETTE['muted'], justify='left').pack(fill='x', pady=(0, 2))
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
        # Shown over the empty table while the app list is being read.
        self.lbl_tree_busy = tk.Label(self.tree, text=self.t('tree_loading'), foreground=PALETTE['muted'],
                                     background=ttk.Style().lookup('Treeview', 'background') or 'white',
                                     borderwidth=0)
        self.tree.tag_configure('checked', background=PALETTE['checked'])
        self.tree.tag_configure('done', foreground=PALETTE['ok'])
        self.tree.tag_configure('failed', foreground=PALETTE['error'])
        self.tree.tag_configure('partial', foreground=PALETTE['partial'])
        self.tree.tag_configure('running', foreground=PALETTE['running'])
        self.tree.tag_configure('queued', foreground=PALETTE['queued'])
        self.tree.tag_configure('offloaded', foreground=PALETTE['idle'])
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
        window.configure(background=self.theme_background)
        self.style_titlebar(window)
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
        self.theme_choices = {self.t('theme_' + name): name for name in THEMES}
        theme_name = tk.StringVar(value=self.t('theme_' + theme_setting(self.var_theme.get())))
        ttk.Label(general, text=self.t('theme')).grid(row=3, column=0, sticky='w', pady=4)
        themes = ttk.Combobox(general, textvariable=theme_name, values=list(self.theme_choices), state='readonly',
                              width=24)
        themes.grid(row=3, column=1, sticky='w', padx=6)
        themes.bind('<<ComboboxSelected>>', lambda e: self.change_theme(self.theme_choices[theme_name.get()]))

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
            ttk.Label(fields, text=self.t('name_insert'), foreground=PALETTE['muted']).pack(side='left')
            for field in app_info.NAME_FIELDS:
                ttk.Button(fields, text=self.t('field_' + field), width=-1,
                           command=lambda e=entry, f=field: self._insert_field(e, f)).pack(side='left', padx=1)
            preview = ttk.Label(names, foreground=PALETTE['muted'])
            preview.grid(row=row + 2, column=1, sticky='w', padx=4, pady=(2, 8))
            update = lambda *a, v=var, l=preview, k=kind: self._update_name_preview(v, l, k)
            var.trace_add('write', update)
            update()
            row += 3
        names.columnconfigure(1, weight=1)
        WrapLabel(names, text=self.t('name_help'), foreground=PALETTE['muted'], justify='left').grid(
            row=row, column=0, columnspan=3, sticky='we')
        ttk.Checkbutton(extract, text=self.t('separate_dirs'), variable=self.var_separate_dirs,
                        command=self._folders_changed).pack(anchor='w', pady=(10, 0))

        frida = ttk.Frame(tabs, padding=12)     # the Decryption tab
        tabs.add(frida, text=self.t('tab_decrypt'))
        WrapLabel(frida, text=self.t('decrypt_help'), foreground=PALETTE['muted'], justify='left').grid(
            row=0, column=0, columnspan=3, sticky='we', pady=(0, 8))
        ttk.Label(frida, text=self.t('dump_method')).grid(row=1, column=0, columnspan=3, sticky='w')
        # Two kinds of method: helper programs on the device (no Frida), and Frida with its two modes. The method
        # setting itself keeps one of three values; the family only decides which group of them is in use.
        self.var_family.set('native' if self.native_method() else 'frida')
        native_family = ttk.Radiobutton(frida, text=self.t('family_native'), value='native', variable=self.var_family)
        native_family.grid(row=2, column=0, columnspan=3, sticky='w', pady=(4, 0))
        Tooltip(native_family, self.t('family_native_tip'))
        native_box = ttk.Frame(frida)
        native_box.grid(row=3, column=0, columnspan=3, sticky='we', padx=(24, 0))
        native_widgets = []
        for row, (value, key) in enumerate(((native_decrypt.AUTO, 'native_auto'), (native_decrypt.MREMAP, 'native_mremap'),
                                            (native_decrypt.MEMORY, 'native_memory'))):
            option = ttk.Radiobutton(native_box, text=self.t(key), value=value, variable=self.var_native_helper)
            option.grid(row=row, column=0, sticky='w', pady=(3, 0))
            Tooltip(option, self.t(key + '_tip'))
            native_widgets.append(option)

        frida_family = ttk.Radiobutton(frida, text=self.t('family_frida'), value='frida', variable=self.var_family)
        frida_family.grid(row=4, column=0, columnspan=3, sticky='w', pady=(14, 0))
        Tooltip(frida_family, self.t('family_frida_tip'))
        frida_box = ttk.Frame(frida)
        frida_box.grid(row=5, column=0, columnspan=3, sticky='we', padx=(24, 0))
        frida_box.columnconfigure(1, weight=1)
        frida_widgets = []
        # R4: copy the app and decrypt its files without running it.
        direct_option = ttk.Radiobutton(frida_box, text=self.t('dump_method_frida_direct'), value=METHOD_FRIDA_DIRECT,
                                        variable=self.var_dump_method)
        direct_option.grid(row=0, column=0, columnspan=3, sticky='w', pady=(3, 0))
        Tooltip(direct_option, self.t('dump_method_frida_direct_tip'))
        dump_option = ttk.Radiobutton(frida_box, text=self.t('dump_method_frida_ios_dump'), value=METHOD_FRIDA_IOS_DUMP,
                                      variable=self.var_dump_method)
        dump_option.grid(row=1, column=0, columnspan=3, sticky='w', pady=(8, 0))
        Tooltip(dump_option, self.t('dump_method_frida_ios_dump_tip'))
        dump_box = ttk.Frame(frida_box)
        dump_box.grid(row=2, column=0, columnspan=3, sticky='we', padx=(24, 0))
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
        ttk.Separator(frida_box).grid(row=3, column=0, columnspan=3, sticky='we', pady=12)
        # Both Frida methods talk to frida-server, which can crash or hang with either.
        restart = ttk.Checkbutton(frida_box, text=self.t('restart_frida'), variable=self.var_restart_frida)
        restart.grid(row=4, column=0, columnspan=3, sticky='w', pady=(0, 8))
        port_label = ttk.Label(frida_box, text=self.t('frida_port'))
        port_label.grid(row=5, column=0, sticky='w')
        port_entry = ttk.Entry(frida_box, textvariable=self.var_frida_port, width=8)
        port_entry.grid(row=5, column=1, sticky='w', padx=4)
        install = ttk.Button(frida_box, text=self.t('install'), command=self.install_dependencies)
        install.grid(row=6, column=0, columnspan=3, sticky='w', pady=(8, 0))
        frida_widgets += [direct_option, dump_option, restart, port_label, port_entry, install]

        def update_status(*args):
            state = dump_dir_status(self.var_dump_dir.get().strip())
            status.configure(text=self.t('dump_dir_' + state),
                             foreground=PALETTE['ok'] if state == 'ok' else PALETTE['error'])
            # A missing or unset folder can be fixed by downloading frida-ios-dump.
            if state in ('empty', 'missing'):
                install_dump.pack(side='left', padx=8)
            else:
                install_dump.pack_forget()

        def update_method(*args):
            # What does not belong to the chosen method is greyed out (and unused): the choice of helper with the
            # Frida modes, everything of Frida with the native helpers, and the options of frida-ios-dump with
            # the other Frida mode.
            method = self.var_dump_method.get()
            if method in (METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP):
                self.frida_method = method
            self.var_family.set('native' if method == METHOD_NATIVE else 'frida')
            native = method == METHOD_NATIVE
            for widget in native_widgets:
                widget.state(['disabled'] if not native else ['!disabled'])
            for widget in frida_widgets:
                widget.state(['!disabled'] if not native else ['disabled'])
            self.show_frida_indicator()
            dump_enabled = method == METHOD_FRIDA_IOS_DUMP
            for widget in dump_widgets:
                widget.state(['!disabled'] if dump_enabled else ['disabled'])
            status.configure(foreground=status.cget('foreground') if dump_enabled else PALETTE['idle'])
            if dump_enabled:
                update_status()

        def update_family(*args):
            native = self.var_family.get() == 'native'
            if native and self.var_dump_method.get() != METHOD_NATIVE:
                self.var_dump_method.set(METHOD_NATIVE)
            elif not native and self.var_dump_method.get() == METHOD_NATIVE:
                self.var_dump_method.set(self.frida_method)

        self.var_dump_dir.trace_add('write', update_status)
        self.var_dump_method.trace_add('write', update_method)
        self.var_family.trace_add('write', update_family)
        update_status()
        update_method()
        frida.columnconfigure(1, weight=1)
        tabs.select(tab)

        def close():
            for var in (self.var_name_decrypted, self.var_name_original, self.var_dump_dir, self.var_dump_method,
                        self.var_native_helper, self.var_family):
                for mode, callback in var.trace_info():
                    var.trace_remove(mode, callback)
            self._save_config()
            window.destroy()
            self.show_details()
            # A folder fixed in Settings takes effect without reconnecting.
            if (self.ssh is not None and self.needs_frida() and self.frida_version is None
                    and not self.frida_connecting
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
            label.configure(text=self.t('name_preview', file=name + '.ipa'), foreground=PALETTE['muted'])
        except app_info.NameTemplateError as error:
            label.configure(text=self.t('name_bad', error=self.name_error_text(error)), foreground=PALETTE['error'])

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

    def change_theme(self, name):
        if name == theme_setting(self.var_theme.get()):
            return
        self.var_theme.set(name)
        self._save_config()
        reopen = self.settings_window is not None and self.settings_window.winfo_exists()
        tab = self.settings_tabs.index('current') if reopen else 0
        if reopen:
            self.settings_close()
        self.apply_theme()
        self.style_titlebar(self)
        self._build_ui()
        if reopen:
            self.open_settings(tab=tab)

    def _indicator(self, parent, title):
        frame = ttk.Frame(parent)
        frame.pack(side='left', padx=(6, 18))
        dot = tk.Canvas(frame, width=14, height=14, highlightthickness=0, background=self.theme_background)
        dot.create_oval(2, 2, 12, 12, fill=PALETTE['idle'], outline='', tags='dot')
        dot.pack(side='left')
        label = ttk.Label(frame)
        label.pack(side='left', padx=2)
        label.title = title
        return dot, label

    def show_frida_indicator(self):
        """The Frida status beside SSH is only there while a Frida method is chosen."""
        frame = self.frida_dot.master
        if self.native_method():
            frame.pack_forget()
        else:
            frame.pack(side='left', padx=(6, 18))

    def _set_indicator(self, dot, label, text, color):
        dot.itemconfigure('dot', fill=PALETTE[color])
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
                    dump_method=self.var_dump_method.get(), native_helper=self.var_native_helper.get(),
                    frida_method=self.frida_method,
                    name_decrypted=self.var_name_decrypted.get(), name_original=self.var_name_original.get(),
                    separate_dirs=self.var_separate_dirs.get(), font=self.var_font.get(),
                    font_size=self.var_font_size.get(), theme=self.var_theme.get())
        data = {key: value for key, value in data.items() if str(value) != str(DEFAULTS[key])}
        if self.var_remember.get():
            data['password'] = self.var_password.get()
        try:
            with open(engine.CONFIG_PATH, 'w', encoding='utf-8') as handle:
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
        self.post(self.log, Text('log_ssh_connecting', user=user, host=host, port=port))
        try:
            client = open_ssh(host, port, user, password, lambda text: self.post(self.log, text))
        except Exception as error:
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
        if self.native_method():
            self.set_frida_state(Text('state_unused'), 'idle')
            self.run_background(self._read_ios_version, self.generation, client)
        elif self.direct_method() or dump_dir_status(self.var_dump_dir.get().strip()) == 'ok':
            self.connect_frida()
        else:
            self.set_frida_state(Text('state_no_dump'), 'idle')
            self.log(Text('log_frida_skipped'))

    def _read_ios_version(self, generation, client):
        """The device's iOS version without Frida (which otherwise reports it), for choosing the helper."""
        try:
            status, output = remote.run(client, 'sw_vers -productVersion')
            version = output.strip() if status == 0 else ''
        except Exception:
            version = ''
        if version:
            self.post(self._set_device_os, generation, 'iOS ' + version)

    def _set_device_os(self, generation, device_os):
        if generation == self.generation and self.ssh is not None and not self.device_os:
            self.device_os = device_os

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
        if not detail:
            try:
                detail = 'iOS ' + remote.run(client, 'sw_vers -productVersion')[1].strip()
            except Exception:
                detail = ''
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
        self._set_tree_busy(False)
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
        self._set_tree_busy(True)
        self.run_background(self._load_apps_worker, self.generation, self.ssh)

    def _load_apps_worker(self, generation, client):
        # SSH alone is enough, so original IPAs can be extracted without Frida.
        try:
            apps = device_apps.list_apps(client)
        except Exception as error:
            self.post(self._set_tree_busy, False)
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

    def _set_tree_busy(self, busy):
        if self.root_frame is None:
            return
        if busy and not self.tree.get_children():
            self.lbl_tree_busy.place(relx=0.5, rely=0.4, anchor='center')
        else:
            self.lbl_tree_busy.place_forget()

    def _apps_loaded(self, generation, apps):
        if generation != self.generation:
            return
        self._set_tree_busy(False)
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
                verified = (app.get('verify') or {}).get('type')  # the name the last extraction got
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

    def helper_problem(self, error):
        """A helper could not be used on the device: one warning for the whole batch, the apps say why in the list."""
        if self.helper_warned:
            return
        self.helper_warned = True
        messagebox.showwarning(self.t('m_helper_t'), self.t('m_helper', error=error))

    def start_dump(self):
        if self.dumping:
            return
        if self.ssh is None:
            messagebox.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        bundles = self._checked_in_order()
        if not bundles:
            return
        self.helper_warned = False
        direct = self.direct_method()
        dump_dir = self.var_dump_dir.get().strip()
        if not direct and not self.check_dump_dir(dump_dir):
            return
        jobs = self._jobs('dump', bundles)
        if jobs is None:
            return
        native = self.native_method()
        if native and not self.device_os:
            # Connected before the method was switched to native: the version comes over SSH.
            try:
                version = native_decrypt.Device(self.ssh, self.var_user.get().strip(), self.var_password.get()).ios_version()
            except Exception:
                version = ''
            self.device_os = 'iOS ' + version if version else None
        if native:
            try:
                native_decrypt.local_helper(native_decrypt.choose(self.var_native_helper.get(), ios_major(self.device_os)))
            except native_decrypt.HelperError as error:
                messagebox.showwarning(self.t('m_helper_t'), self.t('m_helper', error=error))
                return
        if native and native_decrypt.refused(self.var_native_helper.get(), ios_major(self.device_os)):
            messagebox.showerror(self.t('m_mremap_t'), self.t('m_mremap', version=native_decrypt.version_text(self.device_os)))
            return
        if not native and (self.frida_version is None or self.tunnel is None):
            self.connect_frida(then=self.start_dump)
            return
        # frida-ios-dump compiles its agent with frida.Compiler (frida 16 and later).
        if not direct and not native and int(major(self.frida_version) or 0) < 16:
            messagebox.showerror(self.t('m_frida_t'), self.t('m_dump_old_frida', version=self.frida_version))
            return
        # A decrypted IPA is named after its verification result, so any of these may be written.
        names = {bundle: {kind: self.ipa_name(self.apps[bundle], 'dump', kind) for kind in DUMP_KINDS}
                 for bundle, _ in jobs}
        outdir = self._prepare_batch('dump', jobs, names)
        if outdir is None:
            return
        self.log(Text('log_start_native' if native else 'log_start_direct' if direct else 'log_start', n=len(jobs)))
        helper = native_decrypt.choose(self.var_native_helper.get(), ios_major(self.device_os)) if native else None
        options = dict(direct=direct, native=helper, method=helper or decrypt_method(self.device_os),
                       host=self.var_host.get().strip(), port=self.var_port.get().strip(),
                       user=self.var_user.get().strip(), password=self.var_password.get(),
                       frida='127.0.0.1:{}'.format(self.tunnel.local_port) if self.tunnel else None,
                       frida_version=self.frida_version,
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

    def cancel_batch(self):
        if not messagebox.askyesno(self.t('m_cancel_t'), self.t('m_cancel')):
            return
        self.cancel_requested.set()
        process = self.current_process
        if process is not None and process.poll() is None:
            process.terminate()
        self.log(Text('log_cancel'))

    def _set_verify(self, bundle, status, total, files, type_=None):
        """Remember the verification result for the details pane and "Check partially decrypted apps"."""
        if bundle in self.apps:
            self.apps[bundle]['verify'] = dict(status=status, total=total, files=files, type=type_ or status)
            if bundle in self.tree.selection():
                self.show_details()

    def direct_method(self):
        """Whether decrypted IPAs are made by decrypting the installed files (R4: with Frida, or natively), not by
        frida-ios-dump."""
        return self.var_dump_method.get() in (METHOD_FRIDA_DIRECT, METHOD_NATIVE)

    def native_method(self):
        """Whether the files are decrypted by the helper programs, which need no Frida."""
        return self.var_dump_method.get() == METHOD_NATIVE

    def needs_frida(self):
        return not self.native_method()

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
        if self.native_method():
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
        warning = WrapLabel(frame, foreground=PALETTE['muted'], justify='left')
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
                ttk.Label(installed_frame, text=self.t('not_installed'), foreground=PALETTE['muted']).pack(anchor='w')
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

    def _install_worker(self, version, dump_dir, then):
        """Install frida `version` side by side with the others; then() runs once Frida reconnects."""
        ok = False
        try:
            ok = self.install_frida(version, dump_dir)
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
        if (self.ssh is not None and not self.dumping and self.needs_frida()
                and (self.direct_method() or dump_dir_status(self.var_dump_dir.get().strip()) == 'ok')):
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
        engine.paramiko = importlib.import_module('paramiko')
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
    if len(sys.argv) > 1:
        # Any argument means the command line (ipa_cli.py), so ./ipa_extractor.sh apps works too.
        import ipa_cli
        sys.exit(ipa_cli.main())
    if engine.paramiko is None and not install_base_packages():
        return
    DumpGUI().mainloop()


if __name__ == '__main__':
    main()
