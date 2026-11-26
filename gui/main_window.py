# -*- coding: utf-8 -*-
"""The main window: the connection, the list of apps, the batches and their log.

The logic is the one the Tk window had (connect, scan, check, extract, decrypt, close); what changed is the drawing.
The engine (engine.DumpEngine) does the work, this class provides what it needs: t(), render(), post(), log(),
set_status(), _set_overall(), _set_verify() and _batch_finished().
"""

import os
import subprocess
import sys
import threading
import time
import traceback

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QMainWindow, QMenu, QPlainTextEdit, QProgressBar, QPushButton, QSizePolicy,
                               QSplitter, QVBoxLayout, QWidget)

import app_info
import device_apps
import engine
import frida_versions
import i18n
import ipa_verify
import native_decrypt
import remote
import usbmux
from engine import (
    APP_NAME, ASSETS, CONNECTION_SSH, CONNECTION_USB, DEFAULTS, DEFAULT_DUMP_DIR, DUMP_KINDS, FRIDA_IOS_DUMP_URL,
    IS_MACOS, IS_WINDOWS, MAX_CONSECUTIVE_FRIDA_ERRORS, METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP, METHOD_NATIVE,
    DumpEngine, Indented, SSHTunnel, Text, __version__, connection_setting, decrypt_method,
    download_frida_ios_dump, error_text, dump_dir_status, dump_method_setting, frida_method_setting, frida_server_status,
    ios_major, is_apple_app, is_user_app, load_config, major, natural_key, open_device, probe_frida, theme_setting,
    version_note)
from gui import dialogs, theme
from gui.app_tree import AppTree
from gui.state import BooleanVar, StringVar, bind_check, bind_text
from gui.widgets import Card, FlowLayout, Indicator, muted_label, pair

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
PROGRESS_LABEL_CHARS = 70    # the progress label has a fixed width
CLOSE_WAIT = 20             # seconds a cancelled batch gets to clean up when the window is closed


class _Poster(QObject):
    """Carries calls from the worker threads to the window's thread (a queued signal)."""
    posted = Signal(object)


class MainWindow(DumpEngine, QMainWindow):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.resize(1320, 840)
        self.setMinimumSize(0, 620)         # the width follows from the content: rows wrap instead of being cut off
        self._poster = _Poster()
        self._poster.posted.connect(self._run_posted)
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
        self.reading_os = None   # the connection (generation) whose iOS version is being read: a start waits for it
        self.os_asked = None     # the connection (generation) whose iOS version was asked for a native start
        self.preparing = False   # one is being set up: its questions are open, nothing may change under them
        self.batch_thread = None
        self.closing = False
        self.can_close = False
        self.downloading = False       # frida-ios-dump is being downloaded
        self.apps_serial = 0       # numbers the scans of the app list; only the latest goes on
        self.frida_declined = False      # the offer to install frida was refused on this connection
        self.cancel_requested = threading.Event()
        self.current_process = None
        self.generation = 0      # invalidates background work from older connections
        aside = self.set_damaged_settings_aside()
        if aside:
            self.after(200, self.log, 'The settings file could not be read, so the defaults are used. It was kept as ' + aside)
        c = dict(DEFAULTS, **load_config())
        self.locales = i18n.load_locales()
        self.lang_setting = c['lang'] if c['lang'] in self.locales else i18n.AUTO
        self.lang = i18n.resolve(self.locales, self.lang_setting)
        self.ssh_state = (Text('state_idle'), 'idle')
        self.frida_state = (Text('state_unused'), 'idle')
        self.helper_warned = False
        self.overall = (0, None)
        self.var_host = StringVar(c['host'])
        self.var_connection = StringVar(connection_setting(c['connection']))
        self.var_usb_device = StringVar(c['usb_device'])
        self.usb_devices = []       # the usbmux.Device objects usbmuxd lists, named
        self.usb_listed = False     # whether usbmuxd has answered yet
        self.var_usb_label = StringVar()     # what the USB device box shows (the name); var_usb_device keeps the UDID
        self.applied_connection = connection_setting(c['connection'])     # the one the window is built for
        self.usb_tunnel = self.endpoint = None      # a USB connection's local end; the (host, port) SSH really uses
        self.var_port = StringVar(c['port'])
        self.var_user = StringVar(c['user'])
        self.var_password = StringVar(c.get('password', ''))
        self.var_frida_port = StringVar(c['frida_port'])
        self.var_remember = BooleanVar('password' in c)
        self.var_search = StringVar()
        self.var_user_only = BooleanVar(c['user_only'])
        self.var_non_apple = BooleanVar(c['non_apple'])
        self.var_encrypted_only = BooleanVar(c['encrypted_only'])
        self.var_outdir = StringVar(c['outdir'])
        self.var_extract_dir = StringVar(c['extract_dir'])
        self.var_dump_dir = StringVar(c['dump_dir'])
        self.var_close_after = BooleanVar(c['close_after'])
        self.var_restart_frida = BooleanVar(c['restart_frida'])
        self.var_repair = BooleanVar(c['repair'])
        self.var_dump_method = StringVar(dump_method_setting(c['dump_method']))
        self.var_native_helper = StringVar(native_decrypt.setting(c['native_helper']))
        self.frida_method = frida_method_setting(c['frida_method'], self.var_dump_method.get())
        self.var_family = StringVar('native' if self.var_dump_method.get() == METHOD_NATIVE else 'frida')
        self.var_name_decrypted = StringVar(c['name_decrypted'])
        self.var_name_original = StringVar(c['name_original'])
        self.var_separate_dirs = BooleanVar(c['separate_dirs'])
        self.var_theme = StringVar(theme_setting(c['theme']))
        self.var_font = StringVar(c['font'])  # '' follows the language
        self.var_font_size = StringVar(c['font_size'])
        self.var_lang = StringVar()
        self.var_search.trace_add('write', lambda *a: self.refresh_tree())
        # The platform's UI font (Segoe UI on Windows, the system font on macOS), before Settings change it.
        self.system_font = QApplication.font().family()
        self.installed_fonts = theme.installed_fonts()
        self.apply_theme()
        self.apply_icon()
        self.root_frame = None
        self.settings_window = None
        self.install_window = None
        self.ssh_connecting = False
        self.frida_connecting = False
        self.installing = False   # a frida version is being installed
        dialogs.parent_widget = self
        dialogs.translate = self.t
        self._build_ui()
        # Unticking the box removes the saved password at once, not with the next unrelated save.
        self.var_remember.trace_add('write', lambda *args: self._save_config())
        self._watch_timer = QTimer(self)
        self._watch_timer.timeout.connect(self._watch_connection)
        self._watch_timer.start(3000)
        self.log(self.ready_text())

    def ready_text(self):
        """What to do first, for the connection in use."""
        return Text('log_ready_usb' if connection_setting(self.var_connection.get()) == CONNECTION_USB else 'log_ready')

    def t(self, key, **params):
        template = self.locales[self.lang].get(key) or self.locales[i18n.FALLBACK].get(key, key)
        return template.format(**params)

    def after(self, ms, func, *args):
        QTimer.singleShot(ms, lambda: func(*args))

    def apply_icon(self):
        name = 'icon.ico' if IS_WINDOWS else 'icon.png'
        path = os.path.join(ASSETS, name)
        if os.path.exists(path):
            icon = QIcon(path)
            self.setWindowIcon(icon)
            self.app.setWindowIcon(icon)

    def font_size(self):
        try:
            return min(16, max(8, int(self.var_font_size.get())))
        except ValueError:
            return engine.DEFAULT_FONT_SIZE

    def apply_theme(self):
        """The palette of the theme setting (the system's choice is read here, once per start or change)."""
        theme.apply_theme(self.app, self.var_theme.get(), self.font_size())
        theme.apply_font(self.app, self.var_font.get() or self.auto_font(), self.font_size())

    def style_titlebar(self, window):
        theme.style_titlebar(window, self.var_theme.get())

    def auto_font(self):
        """First installed font the language prefers (locale "_fonts"), else the platform's UI font."""
        installed = set(self.installed_fonts)
        for family in self.locales[self.lang].get('_fonts', []):
            if family in installed:
                return family
        return self.system_font

    def apply_fonts(self):
        self.apply_theme()          # the style sheet carries the size; the font the family

    def render(self, text):
        if isinstance(text, Indented):
            return '    ' + self.render(text.text)
        if isinstance(text, Text):
            params = {k: self.render(v) for k, v in text.params.items()}
            return self.t(text.key, **params)
        return str(text)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        log_content = ''
        selection = []
        if self.root_frame is not None:
            log_content = self.log_text.toPlainText()
            selection = self.tree.selection()
        self.setWindowTitle(APP_NAME)
        root = QWidget()
        root.setObjectName('root')
        column = QVBoxLayout(root)
        column.setContentsMargins(10, 10, 10, 8)
        column.setSpacing(8)

        # The first line: the heading of the device section, and Settings at the top right (it is not part of the
        # device). The frame of the device starts below, and has no title of its own.
        settings = QPushButton(self.t('settings'))
        settings.clicked.connect(lambda: self.open_settings())
        first = QHBoxLayout()
        first.addWidget(QLabel(self.t('device')))
        first.addStretch(1)
        first.addWidget(settings)
        column.addLayout(first)
        conn = Card()
        grid = QGridLayout()
        conn.box.addLayout(grid)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)
        usb = connection_setting(self.var_connection.get()) == CONNECTION_USB
        fields = [('ssh_port', self.var_port, 6), ('user', self.var_user, 10), ('password', self.var_password, 14)]
        row = 0
        self.usb_box = None
        if usb:
            # Where the device's address is for the network: the USB device in a row of its own; below it the row of
            # the network layout from the SSH port on, unchanged.
            picker = QHBoxLayout()
            picker.setSpacing(8)
            picker.addWidget(QLabel(self.t('usb_device')))
            self.usb_box = QComboBox()
            self.usb_box.setMinimumWidth(320)
            self.usb_box.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
            self.usb_box.setMinimumContentsLength(24)
            self.usb_box.activated.connect(self.usb_chosen)
            picker.addWidget(self.usb_box, 1)
            refresh = QPushButton(self.t('usb_refresh'))
            refresh.clicked.connect(self.refresh_usb)
            picker.addWidget(refresh)
            grid.addLayout(picker, 0, 0, 1, 12)
            row = 1
        else:
            fields.insert(0, ('host', self.var_host, 16))
        # The account fields wrap onto a second line when the window is narrow (or the font big); Settings stays top right.
        digit = self.fontMetrics().horizontalAdvance('0')
        flow = FlowLayout(hspacing=14)
        for label, var, chars in fields:
            edit = QLineEdit()
            edit.setFixedWidth(digit * chars + 24)
            if var is self.var_password:
                edit.setEchoMode(QLineEdit.Password)
            bind_text(edit, var)
            edit.returnPressed.connect(self.connect_device)
            flow.addWidget(pair(self.t(label), edit))
        remember = QCheckBox(self.t('remember'))
        bind_check(remember, self.var_remember)
        flow.addWidget(remember)
        self.btn_connect = QPushButton(self.t('disconnect' if self.ssh is not None else 'connect'))
        self.btn_connect.setEnabled(not self.ssh_connecting)
        self.btn_connect.clicked.connect(self.toggle_connection)
        flow.addWidget(self.btn_connect)
        grid.addLayout(flow, row, 0, 1, 12)
        indicators = QHBoxLayout()
        self.ssh_indicator = Indicator('SSH')
        self.frida_indicator = Indicator('Frida')
        indicators.addWidget(self.ssh_indicator)
        indicators.addWidget(self.frida_indicator)
        indicators.addStretch(1)
        grid.addLayout(indicators, row + 1, 0, 1, 12)
        column.addWidget(conn)
        if usb:
            self.show_usb_device()
            self.refresh_usb()
        self.show_frida_indicator()

        folders = ((('outdir', self.var_outdir), ('extract_dir', self.var_extract_dir))
                   if self.var_separate_dirs.get() else (('outdir_single', self.var_outdir),))
        dirs = QGridLayout()
        dirs.setHorizontalSpacing(6)
        for number, (label, var) in enumerate(folders):
            dirs.addWidget(QLabel(self.t(label)), number, 0)
            edit = QLineEdit()
            bind_text(edit, var)
            dirs.addWidget(edit, number, 1)
            browse = QPushButton(self.t('browse'))
            browse.clicked.connect(lambda checked=False, v=var: self.choose_dir(v))
            dirs.addWidget(browse, number, 2)
            open_button = QPushButton(self.t('open_dir'))
            open_button.clicked.connect(lambda checked=False, v=var: self.open_dir(v.get()))
            dirs.addWidget(open_button, number, 3)
        dirs.setColumnStretch(1, 1)
        column.addLayout(dirs)

        tools = FlowLayout(hspacing=12)
        search = QLineEdit()
        search.setFixedWidth(digit * 20)
        bind_text(search, self.var_search)
        tools.addWidget(pair(self.t('search'), search))
        for key, var in (('user_only', self.var_user_only), ('non_apple', self.var_non_apple),
                         ('encrypted_only', self.var_encrypted_only)):
            box = QCheckBox(self.t(key))
            bind_check(box, var)
            box.toggled.connect(lambda checked: self.refresh_tree())
            tools.addWidget(box)
        refresh_apps = QPushButton(self.t('refresh'))
        refresh_apps.clicked.connect(self.load_apps)
        tools.addWidget(refresh_apps)
        self.lbl_count = QLabel('')
        tools.addWidget(self.lbl_count)
        column.addLayout(tools)

        checks = FlowLayout(hspacing=6)
        for key, command, tip in (('check_all', self.check_all, None), ('check_none', self.check_none, None),
                                  ('check_invert', self.check_invert, None), ('check_failed', self.check_failed, None),
                                  ('check_partial', self.check_partial, 'check_partial_tip'),
                                  ('check_unextracted', self.check_unextracted, 'check_unextracted_tip')):
            button = QPushButton(self.t(key))
            button.clicked.connect(lambda checked=False, c=command: c())
            if tip:
                button.setToolTip(self.t(tip))
            checks.addWidget(button)
        column.addLayout(checks)

        panes = QSplitter(Qt.Vertical)
        panes.setChildrenCollapsible(False)
        table = QWidget()
        table_box = QVBoxLayout(table)
        table_box.setContentsMargins(0, 0, 0, 0)
        table_box.setSpacing(4)
        self.tree = AppTree(COLUMNS)
        self.tree.setHeaderLabels(['' if key == 'check' else self.t('col_' + key) for key, _ in COLUMNS])
        self.tree.selection_changed.connect(self.show_details)
        self.tree.check_clicked.connect(self.on_check_click)
        self.tree.row_double_clicked.connect(self.on_tree_double_click)
        self.tree.space_pressed.connect(self.on_space)
        self.tree.menu_requested.connect(self.on_tree_menu)
        self.tree.header_clicked.connect(self.on_header_click)
        table_box.addWidget(self.tree, 1)
        panes.addWidget(table)

        lower = QWidget()
        lower_box = QVBoxLayout(lower)
        lower_box.setContentsMargins(0, 0, 0, 0)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.details.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.details.setMaximumHeight(self.fontMetrics().lineSpacing() * 9)
        lower_box.addWidget(self.details)
        actions = QHBoxLayout()
        self.btn_extract = QPushButton()
        self.btn_extract.setToolTip(self.t('extract_tip'))
        self.btn_extract.clicked.connect(self.start_extract)
        self.btn_dump = QPushButton()
        self.btn_dump.setObjectName('primary')
        self.btn_dump.setToolTip(self.t('dump_tip'))
        self.btn_dump.clicked.connect(self.start_dump)
        self.btn_cancel = QPushButton(self.t('cancel'))
        self.btn_cancel.setEnabled(self.dumping)
        self.btn_cancel.clicked.connect(self.cancel_batch)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        self.lbl_progress = QLabel('')
        self.lbl_progress.setMinimumWidth(1)
        self.lbl_progress.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)      # long text is cut, never widens the window
        for widget in (self.btn_extract, self.btn_dump, self.btn_cancel):
            actions.addWidget(widget)
        actions.addWidget(self.progress, 1)
        actions.addWidget(self.lbl_progress)
        lower_box.addLayout(actions)
        self.log_text = QPlainTextEdit()
        self.log_text.setObjectName('log')
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QPlainTextEdit.NoWrap)
        lower_box.addWidget(self.log_text, 1)
        if log_content:
            self.log_text.setPlainText(log_content.rstrip('\n'))
            self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
        panes.addWidget(lower)
        panes.setStretchFactor(0, 4)
        panes.setStretchFactor(1, 2)
        column.addWidget(panes, 1)

        self.root_frame = root
        self.setCentralWidget(root)
        self.set_ssh_state(*self.ssh_state)
        self.set_frida_state(*self.frida_state)
        self._set_overall(*self.overall)
        self.refresh_tree()
        selection = [b for b in selection if self.tree.exists(b)]
        if selection:
            self.tree.selection_set(selection)
            self.tree.see(selection[0])

    def open_settings(self, tab=0):
        from gui import settings_dialog
        settings_dialog.open_settings(self, tab)

    def settings_open(self):
        return self.settings_window is not None

    def _folders_changed(self):
        self._save_config()
        self._build_ui()

    def _update_name_preview(self, var, label, kind):
        selection = self.tree.selection()
        app = self.apps.get(selection[0]) if selection else None
        app = app or dict(name='App', bundle='com.example.app', version='1.0', build='100')
        try:
            name = app_info.format_ipa_name(var.get(), app['name'], app['bundle'], app['version'],
                                            app['build'], kind)
            label.setText(self.t('name_preview', file=name + '.ipa'))
            label.setObjectName('muted')
        except app_info.NameTemplateError as error:
            label.setText(self.t('name_bad', error=self.name_error_text(error)))
            label.setObjectName('')
            label.setStyleSheet('color: {};'.format(theme.PALETTE['error']))
            return
        label.setStyleSheet('')
        label.style().unpolish(label)
        label.style().polish(label)

    def name_error_text(self, error):
        key, params = error.args
        return self.t(key, **params)

    def _show_name_error(self, mode, error):
        dialogs.showerror(self.t('m_name_t'), self.t(
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

    def _reopen_settings(self, change):
        """Run change() with the Settings window closed, and open it again on the same page afterwards."""
        reopen = self.settings_open()
        tab = self.settings_window.current_page() if reopen else 0
        if reopen:
            self.settings_close()
        change()
        if reopen:
            self.open_settings(tab=tab)

    def change_language(self, setting):
        if setting != self.lang_setting:
            self.lang_setting = setting
            self.lang = i18n.resolve(self.locales, setting)
            self._save_config()

            def rebuild():
                self.apply_fonts()
                self._build_ui()
            self._reopen_settings(rebuild)

    def change_connection(self, name):
        """Switch between SSH over the network and over USB: the device section of the window changes with it."""
        name = connection_setting(name)
        previous = self.applied_connection
        self.var_connection.set(name)
        if name == previous:
            return
        if self.busy():
            dialogs.showwarning(self.t('m_busy_t'), self.t('m_busy'))
            self.var_connection.set(previous)       # the radio button goes back
            return
        if self.ssh is not None or self.ssh_connecting:
            answer = dialogs.askyesno(self.t('connection'), self.t('m_conn_switch'))
            if not answer or self.busy():       # a batch may have begun while the question was open
                self.var_connection.set(previous)       # the radio button goes back
                return
            self.disconnect('state_disconnected')       # the old connection ends here: nothing of it outlives the switch
        self.applied_connection = name
        self._save_config()

        def rebuild():
            self._build_ui()
            self.log(self.ready_text())       # what to enter now, once per change
        self._reopen_settings(rebuild)

    def usb_labels(self):
        return [device.label() for device in self.usb_devices]

    def show_usb_label(self, label):
        self.var_usb_label.set(label)
        if self.usb_box is not None:
            self.usb_box.setToolTip(label)

    def show_usb_device(self):
        """The USB device box shows the chosen device by its name (the UDID is what is kept); with nothing attached it
        says so, however the remembered device is."""
        if self.usb_box is None:
            return
        serial = self.var_usb_device.get().strip()
        labels = self.usb_labels()
        self.usb_box.blockSignals(True)
        self.usb_box.clear()
        self.usb_box.addItems(labels)
        self.usb_box.blockSignals(False)
        for index, device in enumerate(self.usb_devices):
            if device.serial == serial:
                self.usb_box.setCurrentIndex(index)
                self.show_usb_label(device.label())
                return
        self.usb_box.setCurrentIndex(-1)
        if not self.usb_listed:
            self.usb_box.setPlaceholderText('')          # the first answer has not come yet
        else:
            self.usb_box.setPlaceholderText('' if self.usb_devices else self.t('usb_none'))
        self.var_usb_label.set('')

    def usb_chosen(self, index=None):
        if self.usb_box is None:
            return
        index = self.usb_box.currentIndex()
        if 0 <= index < len(self.usb_devices):
            device = self.usb_devices[index]
            self.var_usb_device.set(device.serial)
            self._save_config()
            self.show_usb_label(device.label())

    def refresh_usb(self):
        """List the devices on USB in the background and fill the box; the one attached device is chosen."""
        self.usb_listing = getattr(self, 'usb_listing', 0) + 1
        number = self.usb_listing

        def work():
            try:
                devices, error = [usbmux.describe(device) for device in usbmux.list_devices()], None
            except usbmux.UsbmuxError as failure:
                devices, error = [], failure
            self.post(self._usb_listed, devices, error, number)
        self.run_background(work)

    def _usb_listed(self, devices, error, number=None):
        if number is not None and number != self.usb_listing:
            return      # an older answer, slower than a later Refresh: the later one is the truth
        self.usb_devices, self.usb_listed = devices, True
        if self.usb_box is not None:
            if len(devices) == 1 and self.var_usb_device.get() not in [d.serial for d in devices]:
                self.var_usb_device.set(devices[0].serial)
            self.show_usb_device()
        if error is None:
            self.usb_error_logged = None
        elif str(error) != getattr(self, 'usb_error_logged', None):
            self.usb_error_logged = str(error)      # a rebuilt window asks again: say it once, not each time
            self.log(error_text(error))

    def change_theme(self, name):
        if name == theme_setting(self.var_theme.get()):
            return
        self.var_theme.set(name)
        self._save_config()

        def rebuild():
            self.apply_theme()
            self.style_titlebar(self)
            self._build_ui()
        self._reopen_settings(rebuild)

    def show_frida_indicator(self):
        """The Frida status beside SSH is only there while a Frida method is chosen."""
        self.frida_indicator.setVisible(not self.native_method())

    def set_ssh_state(self, text, color):
        self.ssh_state = (text, color)
        self.ssh_indicator.set(self.render(text), color)

    def set_frida_state(self, text, color):
        self.frida_state = (text, color)
        self.frida_indicator.set(self.render(text), color)

    def log(self, text):
        self.log_text.appendPlainText(time.strftime('[%H:%M:%S] ') + self.render(text))
        bar = self.log_text.verticalScrollBar()
        bar.setValue(bar.maximum())

    # ------------------------------------------------------- thread plumbing
    def post(self, func, *args):
        """Run func(*args) on the window's thread."""
        self._poster.posted.emit((func, args))

    def _run_posted(self, payload):
        func, args = payload
        try:
            func(*args)
        except Exception:       # one failing callback must not stop every later update of the window
            try:
                traceback.print_exc()
            except Exception:       # started by a double click there is no stderr to write to
                pass

    def run_background(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread

    # ----------------------------------------------------------- connection
    @staticmethod
    def set_damaged_settings_aside():
        """A settings file that cannot be read is renamed to .bad, so the next save does not destroy it."""
        try:
            engine.load_config(strict=True)
        except ValueError:
            target, number = engine.CONFIG_PATH + '.bad', 1
            while os.path.exists(target):               # an earlier .bad is not overwritten
                number += 1
                target = '{}.bad{}'.format(engine.CONFIG_PATH, number)
            try:
                os.replace(engine.CONFIG_PATH, target)
                return target
            except OSError:
                pass
        return None

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
                    font_size=self.var_font_size.get(), theme=self.var_theme.get(),
                    connection=self.var_connection.get(), usb_device=self.var_usb_device.get().strip())
        for key in ('port', 'frida_port', 'font_size'):       # typed as text, kept as numbers like the defaults
            if data[key].isdecimal():
                data[key] = int(data[key])
        data = {key: value for key, value in data.items() if str(value) != str(DEFAULTS[key])}
        if self.var_remember.get():
            data['password'] = self.var_password.get()
        for key, value in load_config().items():       # keys of a newer version stay in the file
            if key not in DEFAULTS and key != 'password':
                data.setdefault(key, value)
        try:
            engine.save_config(data)
        except OSError as error:
            self.log(Text('log_config_fail', error=error))

    def toggle_connection(self):
        if self.ssh is not None:
            if self.busy():
                dialogs.showwarning(self.t('m_busy_t'), self.t('m_busy'))
                return
            self.disconnect('state_disconnected')
        else:
            self.connect_device()

    def connect_device(self):
        if self.ssh is not None or self.ssh_connecting:
            return
        if self.busy():            # the batch still runs on the old connection
            dialogs.showwarning(self.t('m_busy_t'), self.t('m_busy'))
            return
        try:
            port = int(self.var_port.get())
        except ValueError:
            dialogs.showerror(self.t('m_param_t'), self.t('m_ports'))
            return
        usb = connection_setting(self.var_connection.get()) == CONNECTION_USB
        host = self.var_host.get().strip()
        if not host and not usb:
            dialogs.showerror(self.t('m_param_t'), self.t('m_host'))
            return
        if not self.var_user.get().strip():
            dialogs.showerror(self.t('m_param_t'), self.t('m_user'))
            return
        serial = self.var_usb_device.get().strip() if usb else ''
        if usb:
            host = 'USB ' + serial if serial else 'USB'
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
        self.btn_connect.setEnabled(False)
        self.set_ssh_state(Text('state_connecting'), 'busy')
        self.run_background(self._connect_worker, self.generation, host, port,
                            self.var_user.get().strip(), self.var_password.get(),
                            CONNECTION_USB if usb else CONNECTION_SSH, serial)

    def _connect_worker(self, generation, host, port, user, password, connection, serial):
        self.post(self.log, Text('log_ssh_connecting', user=user, host=host, port=port))
        try:
            client, address, tunnel = open_device(connection, host, port, user, password,
                                                  lambda text: self.post(self.log, text), usb_device=serial)
        except Exception as error:
            self.post(self._connect_failed, generation, error)
            return
        self.post(self._ssh_connected, generation, client, host, address, tunnel)

    def _connect_failed(self, generation, error):
        self.ssh_connecting = False
        if generation != self.generation:
            return
        self.log(Text('log_ssh_failed', error=error_text(error)))
        self.set_ssh_state(Text('state_failed'), 'error')
        self.btn_connect.setEnabled(True)
        self.btn_connect.setText(self.t('connect'))

    def _ssh_connected(self, generation, client, host, address, tunnel):
        self.ssh_connecting = False
        if generation != self.generation:
            client.close()
            if tunnel is not None:
                tunnel.close()
            return
        self.ssh, self.endpoint, self.usb_tunnel = client, address, tunnel
        self.set_ssh_state(Text('state_connected', host=host), 'ok')
        self.btn_connect.setEnabled(True)
        self.btn_connect.setText(self.t('disconnect'))
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
            dialogs.showerror(self.t('m_param_t'), self.t('m_ports'))
            return
        if self.frida_connecting:
            return
        self.frida_connecting = True
        self.set_frida_state(Text('state_checking'), 'busy')
        self.btn_dump.setEnabled(False)
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
            self.post(self.log, version_note(version, device_version))
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
            dialogs.showerror(self.t('m_frida_t'), self.t('m_frida', error=self.render(error)))

    def _frida_missing(self, generation, device_version, then):
        """No installed frida fits the device: offer to install the device's own version."""
        self.frida_connecting = False
        self._checks_changed()
        if generation != self.generation:
            return
        self.set_frida_state(Text('state_no_local', major=major(device_version)), 'error')
        self.log(Text('log_frida_missing', device=device_version, major=major(device_version)))
        if self.busy() or self.installing:
            return
        answer = dialogs.askyesno(self.t('m_frida_get_t'), self.t(
            'm_frida_get', device=device_version, major=major(device_version),
            command=' '.join(frida_versions.install_command(device_version))))
        if generation != self.generation or self.installing:      # the connection went away or an install began
            return
        if not answer:
            self.frida_declined = True
            return
        self.set_frida_state(Text('state_installing', version=device_version), 'busy')
        self.installing = True
        self._checks_changed()
        self.run_background(self._install_worker, device_version, None, then, generation)

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
        self.frida_connecting = False
        self.apps_serial += 1        # the scan of the old connection stops without a message
        self.frida_declined = False
        self.ssh_connecting = False         # a connect still running is stale now: its answer is dropped
        self._drop_frida()
        if self.ssh is not None:
            self.ssh.close()
        if self.usb_tunnel is not None:
            self.usb_tunnel.close()
        self.usb_tunnel = self.endpoint = None
        self.ssh = self.device_frida_version = self.device_os = None
        self.set_ssh_state(Text(reason), 'idle' if reason == 'state_disconnected' else 'error')
        self.set_frida_state(Text('state_unused'), 'idle')
        self.btn_connect.setEnabled(True)
        self.btn_connect.setText(self.t('connect'))
        self.log(Text('log_disconnected', reason=Text(reason)))

    def _watch_connection(self):
        transport = self.ssh.get_transport() if self.ssh is not None else None
        if self.ssh is not None and (transport is None or not transport.is_active()):
            self.disconnect('state_dropped')

    # ---------------------------------------------------------------- apps
    def load_apps(self):
        if self.ssh is None:
            dialogs.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        if self.busy():            # the batch reads self.apps: a new list would take its apps away
            dialogs.showwarning(self.t('m_busy_t'), self.t('m_busy'))
            return
        self.log(Text('log_loading'))
        self._set_tree_busy(True)
        self.apps_serial += 1        # a scan still running is stale now: it stops and its answers are dropped
        self.run_background(self._load_apps_worker, self.generation, self.ssh, self.apps_serial)

    def _load_apps_worker(self, generation, client, serial):
        # SSH alone is enough, so original IPAs can be extracted without Frida.
        try:
            apps = device_apps.list_apps(client)
        except Exception as error:
            if serial == self.apps_serial:
                self.post(self._set_tree_busy, False)
                self.post(self.log, Text('log_load_failed', error=error))
            return
        if serial != self.apps_serial:
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
                if generation != self.generation or serial != self.apps_serial:
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
        if serial == self.apps_serial:
            self.post(self._app_info_done, generation)

    def _set_tree_busy(self, busy):
        if self.root_frame is None:
            return
        self.tree.set_busy(self.t('tree_loading'), bool(busy and self.tree.topLevelItemCount() == 0))

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
        return ('', app['name'], app['bundle'], version,
                '' if encrypted is None else self.t('yes' if encrypted else 'no'),
                info.get('team_id', ''), info.get('signer', '') or info.get('error', ''),
                info.get('developer', '') or info.get('profile_team', ''), self.render(status))

    def _row_check(self, app):
        """The state of the row's check box; None for an app with nothing on the device to extract (no box)."""
        return None if app.get('offloaded') else app['bundle'] in self.checked

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
            app = self.apps[bundle]
            self.tree.item(bundle, self._row_values(app), self._row_tags(bundle), self._row_check(app))

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
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.delete_all()
            index = [c[0] for c in COLUMNS].index(self.sort_column)
            rows = [(app, self._row_values(app)) for app in self._visible_apps()]
            rows.sort(key=lambda row: natural_key(row[1][index]), reverse=self.sort_reverse)
            for app, values in rows:
                self.tree.insert(app['bundle'], values, self._row_tags(app['bundle']), self._row_check(app))
            self.tree.set_sort_indicator(self.sort_column, self.sort_reverse)
            self.tree.selection_set([b for b in selected if self.tree.exists(b)])
        finally:
            self.tree.setUpdatesEnabled(True)
        self.lbl_count.setText(self.t('count', shown=len(rows), total=len(self.apps)))
        self._checks_changed()

    def on_header_click(self, index):
        key = COLUMNS[index][0]
        if key == 'check':
            self.toggle_visible()
        else:
            self.sort_by(key)

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
        self.tree.set_all_checked(all_checked)
        enabled = not (self.dumping or not self.checked)
        dump_enabled = enabled and not ((self.frida_connecting or self.installing or self.downloading) and self.needs_frida())
        self.btn_dump.setText(self.t('dump', n=len(self.checked)))
        self.btn_dump.setEnabled(dump_enabled)
        self.btn_extract.setText(self.t('extract', n=len(self.checked)))
        self.btn_extract.setEnabled(enabled)

    def on_check_click(self, bundle, shift):
        if self.dumping:
            return
        rows = self.tree.get_children()
        anchor = self.check_anchor
        if shift and anchor in rows and anchor != bundle:
            # Shift-click: give the whole range the anchor's state, like file managers.
            first, last = sorted((rows.index(anchor), rows.index(bundle)))
            self.set_checked(rows[first:last + 1], anchor in self.checked)
        else:
            self.set_checked([bundle], bundle not in self.checked)
            self.check_anchor = bundle

    def on_tree_menu(self, bundle, position):
        if not bundle or self.dumping:
            return
        if bundle not in self.tree.selection():
            self.tree.selection_set([bundle])
        selection = self.tree.selection()
        menu = QMenu(self)
        menu.addAction(self.t('menu_check', n=len(selection)), lambda: self.set_checked(selection, True))
        menu.addAction(self.t('menu_uncheck', n=len(selection)), lambda: self.set_checked(selection, False))
        menu.exec(position)

    def on_tree_double_click(self, bundle):
        if bundle and not self.dumping:
            self.set_checked([bundle], bundle not in self.checked)

    def on_space(self):
        selection = self.tree.selection()
        if selection and not self.dumping:
            self.set_checked(selection, not all(b in self.checked for b in selection))

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
        self.details.setPlainText('\n'.join(lines))

    def set_status(self, bundle, text, tag=''):
        self.status[bundle] = (text, tag)
        self._update_row(bundle)

    # ---------------------------------------------------------------- dump
    def choose_dir(self, var, fallback=engine.app_paths.OUTPUT_BASE, parent=None):
        path = dialogs.askdirectory(initialdir=var.get() or fallback, parent=parent or self)
        if path:
            var.set(os.path.normpath(path))
            self._save_config()

    def open_dir(self, path):
        try:
            os.makedirs(path, exist_ok=True)
            if IS_WINDOWS:
                os.startfile(path)
            else:
                subprocess.Popen(['open' if IS_MACOS else 'xdg-open', path], stdin=subprocess.DEVNULL)
        except OSError as error:
            dialogs.showerror(self.t('m_outdir_t'), str(error))

    def _checked_in_order(self):
        # Process in the order shown in the list.
        shown = list(self.tree.get_children())
        bundles = [b for b in shown if b in self.checked]
        bundles += sorted(b for b in self.checked if b not in shown and b in self.apps)
        if not bundles:
            dialogs.showinfo(self.t('m_none_t'), self.t('m_none'))
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
            dialogs.showerror(self.t('m_dup_t'), self.t(
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
            dialogs.showerror(self.t('m_outdir_t'), str(error))
            return None
        candidates = [n for bundle, name in jobs
                      for n in dict.fromkeys(names[bundle].values() if names else [name])]
        existing = [n + '.ipa' for n in candidates if os.path.exists(os.path.join(outdir, n + '.ipa'))]
        if existing and not dialogs.askyesno(self.t('m_overwrite_t'), self.t(
                'm_overwrite', files='\n'.join(existing[:15]) + ('\n…' if len(existing) > 15 else ''))):
            return None
        self._save_config()
        self.dumping = True
        self.cancel_requested.clear()
        self.btn_cancel.setEnabled(True)
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
        self.log(self.t('m_helper', error=error))        # a dialog would stop the progress of an unattended batch

    def busy(self):
        """A batch runs or is being set up: connection, frida versions and the app list must stay as they are."""
        return self.dumping or self.preparing or self.reading_os == self.generation

    def start_dump(self):
        self._prepared(self._start_dump)

    def start_extract(self):
        self._prepared(self._start_extract)

    def _prepared(self, start):
        """Run start() as the one batch being set up. Its dialogs keep the window handling events (a pending
        connection could start another batch meanwhile), so a second start is refused until it is over."""
        if self.busy():
            return
        self.preparing = True
        try:
            start()
        finally:
            self.preparing = False

    def _start_dump(self):
        if self.ssh is None:
            dialogs.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
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
        if native and not self.device_os and self.os_asked != self.generation:
            # Connected before the method was switched to native: the version comes over SSH, off the window's thread
            # (a connection that hangs must not freeze the window); the start goes on when it is known.
            self.os_asked = self.reading_os = self.generation
            self.log(Text('log_reading_ios'))
            self.run_background(self._ios_version_worker, self.generation, self.ssh, self.var_user.get().strip(),
                                self.var_password.get())
            return
        if native:
            try:
                native_decrypt.local_helper(native_decrypt.choose(self.var_native_helper.get(), ios_major(self.device_os)))
            except native_decrypt.HelperError as error:
                dialogs.showwarning(self.t('m_helper_t'), self.t('m_helper', error=error))
                return
        if not native and (self.frida_version is None or self.tunnel is None):
            self.connect_frida(then=self.start_dump)
            return
        # frida-ios-dump compiles its agent with frida.Compiler (frida 16 and later).
        if not direct and not native and int(major(self.frida_version) or 0) < 16:
            dialogs.showerror(self.t('m_frida_t'), self.t('m_dump_old_frida', version=self.frida_version))
            return
        # A decrypted IPA is named after its verification result, so any of these may be written.
        names = {bundle: {kind: self.ipa_name(self.apps[bundle], 'dump', kind) for kind in DUMP_KINDS}
                 for bundle, _ in jobs}
        outdir = self._prepare_batch('dump', jobs, names)
        if outdir is None:
            return
        self.log(Text('log_start_native' if native else 'log_start_direct' if direct else 'log_start', n=len(jobs)))
        helper = native_decrypt.choose(self.var_native_helper.get(), ios_major(self.device_os)) if native else None
        try:
            # The overwrite question may have stayed open while the connection dropped: nothing is left to read here.
            options = dict(direct=direct, native=helper, method=helper or decrypt_method(self.device_os),
                           native_auto=bool(native) and native_decrypt.auto_maps(self.var_native_helper.get(), ios_major(self.device_os)),
                           host=self.endpoint[0], port=str(self.endpoint[1]),
                           user=self.var_user.get().strip(), password=self.var_password.get(),
                           frida='127.0.0.1:{}'.format(self.tunnel.local_port) if self.tunnel else None,
                           frida_version=self.frida_version,
                           outdir=outdir,
                           dump_dir=dump_dir, close_after=self.var_close_after.get(),
                           restart_frida=self.var_restart_frida.get(), generation=self.generation, names=names,
                           repair=direct or self.var_repair.get(), ios=self.device_os or '')
        except (TypeError, AttributeError):
            self.dumping = False        # _prepare_batch had set it: the buttons would stay locked
            self.btn_cancel.setEnabled(False)
            self._checks_changed()
            dialogs.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
            return
        self.batch_thread = self.run_background(self._dump_worker, jobs, options)

    def _ios_version_worker(self, generation, client, user, password):
        try:
            version = native_decrypt.Device(client, user, password).ios_version()
        except Exception:
            version = ''
        self.post(self._ios_version_known, generation, version)

    def _ios_version_known(self, generation, version):
        if self.reading_os == generation:
            self.reading_os = None
        if generation != self.generation or self.ssh is None:
            return
        self.device_os = 'iOS ' + version if version else None
        if not self.native_method() or self.busy():
            return                  # the method was changed while reading: the next press of the button starts
        self.start_dump()           # an unknown version is not asked for again on this connection

    def _start_extract(self):
        if self.ssh is None or not self.apps:
            dialogs.showinfo(self.t('m_not_connected_t'), self.t('m_not_connected'))
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
        self.batch_thread = self.run_background(self._extract_worker, jobs, outdir)

    def cancel_batch(self):
        if not dialogs.askyesno(self.t('m_cancel_t'), self.t('m_cancel')):
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
        self.progress.setValue(int(value))
        if isinstance(text, tuple):
            text = text[0] + self.render(text[1])
        self.lbl_progress.setText(self.render(text or '')[:PROGRESS_LABEL_CHARS])

    def _batch_finished(self, mode, outdir, succeeded, total, paused, partial=0):
        self.dumping = False
        self.btn_cancel.setEnabled(False)
        if self.cancel_requested.is_set():
            self._set_overall(0, Text('progress_cancelled', ok=succeeded, total=total))
        elif paused:
            self._set_overall(self.progress.value(), Text('progress_paused', ok=succeeded, total=total))
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
            dialogs.showwarning(self.t('m_paused_t'), self.t('m_paused', n=MAX_CONSECUTIVE_FRIDA_ERRORS))

    # ------------------------------------------------------- dependencies
    def install_frida_ios_dump(self):
        """Download frida-ios-dump into a folder the user picks."""
        parent = dialogs.askdirectory(title=self.t('install_dump_pick'), parent=self.settings_window or self,
                                      initialdir=os.path.dirname(DEFAULT_DUMP_DIR))
        if not parent:
            return
        parent = os.path.normpath(parent)
        # An empty folder is used as is; otherwise it gets a frida-ios-dump subfolder.
        try:
            empty = not os.listdir(parent)
        except OSError as error:         # a folder that may not be read (the picker lets one choose it)
            dialogs.showerror(self.t('m_download_t'), str(error))
            return
        target = parent if empty else os.path.join(parent, 'frida-ios-dump')
        self.offer_download(target, 'm_download_to')

    @staticmethod
    def folder_readable_empty(path):
        """Whether the folder can be listed and has nothing in it."""
        try:
            return not os.listdir(path)
        except OSError:
            return False

    def offer_download(self, dump_dir, question='m_download'):
        if self.downloading:
            return
        if os.path.isdir(dump_dir) and not self.folder_readable_empty(dump_dir):
            dialogs.showerror(self.t('m_download_t'), self.t('m_dump_dir_busy', path=dump_dir))
            self.open_settings(tab=2)
            return
        if not dialogs.askyesno(self.t('m_download_t'),
                                self.t(question, path=dump_dir, url=FRIDA_IOS_DUMP_URL)):
            return
        self.var_dump_dir.set(dump_dir)
        self._save_config()
        self.downloading = True
        self._checks_changed()
        self.log(Text('log_downloading', path=dump_dir))
        self.run_background(self._download_worker, dump_dir)

    def _download_worker(self, dump_dir):
        try:
            download_frida_ios_dump(dump_dir, lambda line: self.post(self.log, '  ' + line))
        except Exception as error:
            self.post(self.log, Text('log_download_failed', error=error))
            self.post(self._download_ended)
            return
        self.post(self._download_ended)
        self.post(self._download_done)

    def _download_ended(self):
        self.downloading = False
        self._checks_changed()

    def _download_done(self):
        self.log(Text('log_download_done'))
        self.var_dump_dir.set(self.var_dump_dir.get())  # refresh the status shown in Settings
        self._checks_changed()
        # Its confirmation lists the commands it is about to run.
        self.install_dependencies()

    def install_dependencies(self):
        if self.busy():
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
            dialogs.showerror(self.t('m_no_dump_dir_t'), self.t('m_no_dump_dir'))
            self.open_settings(tab=2)
            return
        if state == 'missing':
            self.offer_download(dump_dir)  # installs dependencies once downloaded
            return
        self.open_install_dialog(dump_dir)

    def open_install_dialog(self, dump_dir):
        from gui import install_dialog
        install_dialog.open_install_dialog(self, dump_dir)

    def _install_worker(self, version, dump_dir, then, generation=None):
        """Install frida `version` side by side with the others; then() runs once Frida reconnects."""
        ok = False
        try:
            ok = self.install_frida(version, dump_dir)
        finally:
            self.post(self._install_finished, version, ok, then, generation)

    def _install_finished(self, version, ok, then, generation=None):
        self.installing = False
        self._checks_changed()
        if generation is not None and generation != self.generation:
            then = None            # started on a connection that is gone: it must not begin work on the new one
        if not ok:
            if self.ssh is not None and self.frida_version is None:
                self.set_frida_state(Text('state_failed'), 'error')
            return
        self.frida_declined = False
        self.log(Text('log_frida_installed', version=frida_versions.client_version(version)))
        # No restart needed: reconnect so the best version for this device is picked again.
        if (self.ssh is not None and not self.busy() and self.needs_frida()
                and (self.direct_method() or dump_dir_status(self.var_dump_dir.get().strip()) == 'ok')):
            self._drop_frida()
            self.connect_frida(then)
        elif self.ssh is not None and self.frida_version is None:
            self.set_frida_state(Text('state_unused'), 'idle')      # not left on "installing"

    # --------------------------------------------------------------- close
    def closeEvent(self, event):
        if self.can_close:
            event.accept()
            return
        event.ignore()
        self.on_close()

    def on_close(self):
        if self.closing:         # the wait below keeps the window answering: a second click must not start another
            return
        self.closing = True
        try:
            self._close()
        except Exception:
            self.closing = False        # the window must stay closable
            raise

    def _close(self):
        if self.dumping:
            if not dialogs.askyesno(self.t('m_busy_t'), self.t('m_close')):
                self.closing = False
                return
            self.cancel_requested.set()
            if self.current_process is not None and self.current_process.poll() is None:
                self.current_process.terminate()
            # The batch removes what it left on the device (suspended apps, temporary folders, a half-written IPA)
            # when it stops: give it the time before the connection goes away.
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                waited = 0.0
                while self.batch_thread is not None and self.batch_thread.is_alive() and waited < CLOSE_WAIT:
                    self.batch_thread.join(0.1)         # in small steps, so the window keeps answering
                    QApplication.processEvents()
                    waited += 0.1
            finally:
                QApplication.restoreOverrideCursor()
        engine.stop_children()      # a pip, npm or git still running must not outlive the window (after the question)
        self._save_config()
        if self.ssh is not None:
            self.disconnect('state_disconnected')
        if self.settings_window is not None:
            self.settings_close()
        self.can_close = True
        self.close()
