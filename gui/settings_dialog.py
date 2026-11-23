# -*- coding: utf-8 -*-
"""The Settings window: a list of pages on the left, the page in a scroll area on the right, Close fixed at the bottom.

The window never grows past the screen (the pages scroll instead). It works on the main window's settings (the Vars)."""

import webbrowser

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QVBoxLayout, QWidget)

import app_info
import engine
import native_decrypt
from engine import (CONNECTIONS, DEFAULT_DUMP_DIR, METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP, METHOD_NATIVE, THEMES,
                    dump_dir_status, theme_setting)
from gui import dialogs
from gui.state import bind_check, bind_radio, bind_text
from gui.theme import PALETTE
from gui.widgets import Card, Option, StatusLine, muted_label


def open_settings(window, tab=0):
    if window.settings_window is not None:
        window.settings_window.set_page(tab)
        window.settings_window.raise_()
        window.settings_window.activateWindow()
        return
    dialog = SettingsDialog(window, tab)
    window.settings_window = dialog
    window.settings_close = dialog.finish
    dialog.show()
    window.style_titlebar(dialog)


def later(function):
    """Run function once the signal that asked for it has returned (it may close this window)."""
    QTimer.singleShot(0, function)


class SettingsDialog(QDialog):
    PAGES = ('tab_general', 'tab_extract', 'tab_decrypt', 'tab_connection', 'tab_about')

    def __init__(self, window, tab=0):
        super().__init__(window)
        self.w = window
        self.finished_once = False
        self.traces = []
        self.setWindowTitle(window.t('settings'))
        self.setModal(False)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        body = QHBoxLayout()
        body.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName('nav')
        self.nav.setFixedWidth(190)
        self.stack = QStackedWidget()
        builders = (self.general_page, self.output_page, self.decrypt_page, self.connection_page, self.about_page)
        for key, build in zip(self.PAGES, builders):
            self.nav.addItem(window.t(key))
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)                 # follows the width; scrolls when the page is too tall
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            holder = QWidget()
            column = QVBoxLayout(holder)
            column.setContentsMargins(24, 20, 24, 20)
            column.setSpacing(14)
            title = QLabel(window.t(key))
            title.setObjectName('title')
            column.addWidget(title)
            build(column)
            column.addStretch(1)
            scroll.setWidget(holder)
            self.stack.addWidget(scroll)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(tab)
        body.addWidget(self.nav)
        body.addWidget(self.stack, 1)
        outer.addLayout(body, 1)
        bar = QFrame()
        bar.setObjectName('bar')
        row = QHBoxLayout(bar)
        row.setContentsMargins(16, 10, 16, 10)
        row.addStretch(1)
        close = QPushButton(window.t('close'))
        close.setObjectName('primary')
        close.clicked.connect(self.close)
        row.addWidget(close)
        outer.addWidget(bar)
        available = QApplication.primaryScreen().availableGeometry()
        self.resize(min(960, available.width() - 40), min(700, available.height() - 80))
        self.setMinimumSize(min(560, available.width()), min(320, available.height()))

    # ------------------------------------------------------------------ the window
    def current_page(self):
        return self.nav.currentRow()

    def set_page(self, index):
        self.nav.setCurrentRow(index)

    def trace(self, var, callback):
        var.trace_add('write', callback)
        self.traces.append((var, callback))

    def finish(self):
        """Save, let go of what the pages watch, and close (once)."""
        if self.finished_once:
            return
        self.finished_once = True
        w = self.w
        for var, callback in self.traces:
            var.trace_remove('write', callback)
        w._save_config()
        w.settings_window = None
        self.hide()
        self.deleteLater()
        w.show_details()
        # A folder fixed in Settings takes effect without reconnecting.
        if (w.ssh is not None and w.needs_frida() and w.frida_version is None
                and not w.frida_connecting and not w.frida_declined
                and (w.direct_method() or dump_dir_status(w.var_dump_dir.get().strip()) == 'ok')):
            w.connect_frida()

    def done(self, result):
        self.finish()
        super().done(result)

    def closeEvent(self, event):
        self.finish()
        event.accept()

    # ------------------------------------------------------------------ General
    def general_page(self, column):
        w = self.w
        card = Card()
        # Language
        w.language_choices = {w.t('lang_auto', language=w.locales[i18n_system(w)]['_name']): 'auto'}
        w.language_choices.update((locale['_name'], code) for code, locale in
                                  sorted(w.locales.items(), key=lambda item: item[1]['_name'].casefold()))
        language = QComboBox()
        language.addItems(list(w.language_choices))
        current = next(name for name, code in w.language_choices.items() if code == w.lang_setting)
        language.setCurrentText(current)
        language.activated.connect(lambda i: later(lambda: w.change_language(w.language_choices[language.itemText(i)])))
        card.box.addLayout(self.row(w.t('language'), language))
        # Font: the ones the languages recommend come first
        auto = w.t('font_auto', family=w.auto_font())
        preferred = [f for locale in w.locales.values() for f in locale.get('_fonts', []) if f in w.installed_fonts]
        families = list(dict.fromkeys(preferred + w.installed_fonts))
        fonts = QComboBox()
        fonts.addItems([auto] + families)
        fonts.setCurrentText(w.var_font.get() or auto)
        fonts.setMaxVisibleItems(20)

        def font_chosen(index):
            text = fonts.itemText(index)
            w.var_font.set('' if text == auto else text)
            later(lambda: (w.apply_fonts(), w._save_config()))
        fonts.activated.connect(font_chosen)
        card.box.addLayout(self.row(w.t('font'), fonts))
        size = QSpinBox()
        size.setRange(8, 16)
        size.setKeyboardTracking(False)           # one change when the number is settled, not one per digit
        size.setValue(w.font_size())

        def size_chosen(value):
            w.var_font_size.set(str(value))
            later(lambda: (w.apply_fonts(), w._save_config()))
        size.valueChanged.connect(size_chosen)
        card.box.addLayout(self.row(w.t('font_size'), size, stretch=False))
        theme_choices = {w.t('theme_' + name): name for name in THEMES}
        themes = QComboBox()
        themes.addItems(list(theme_choices))
        themes.setCurrentText(w.t('theme_' + theme_setting(w.var_theme.get())))
        themes.activated.connect(lambda i: later(lambda: w.change_theme(theme_choices[themes.itemText(i)])))
        card.box.addLayout(self.row(w.t('theme'), themes))
        column.addWidget(card)

    @staticmethod
    def row(caption, widget, stretch=True):
        row = QHBoxLayout()
        row.setSpacing(12)
        label = QLabel(caption)
        label.setMinimumWidth(130)
        label.setWordWrap(True)
        row.addWidget(label, 0, Qt.AlignTop)
        row.addWidget(widget, 1 if stretch else 0)
        if not stretch:
            row.addStretch(1)
        return row

    # ------------------------------------------------------------------ Output
    def output_page(self, column):
        w = self.w
        card = Card(w.t('name_group'))
        for key, var, default, kind in (
                ('name_decrypted', w.var_name_decrypted, app_info.DEFAULT_DECRYPTED_NAME, 'decrypted'),
                ('name_original', w.var_name_original, app_info.DEFAULT_ORIGINAL_NAME, 'encrypted')):
            entry = QLineEdit()
            bind_text(entry, var)
            reset = QPushButton(w.t('name_reset'))
            reset.clicked.connect(lambda checked=False, v=var, d=default: v.set(d))
            line = QHBoxLayout()
            line.addWidget(entry, 1)
            line.addWidget(reset)
            card.box.addWidget(QLabel(w.t(key)))
            card.box.addLayout(line)
            fields = QHBoxLayout()
            fields.setSpacing(4)
            fields.addWidget(muted_label(w.t('name_insert'), wrap=False))
            for field in app_info.NAME_FIELDS:
                chip = QPushButton(w.t('field_' + field))
                chip.setObjectName('chip')
                chip.clicked.connect(lambda checked=False, e=entry, f=field: self.insert_field(e, f))
                fields.addWidget(chip)
            fields.addStretch(1)
            card.box.addLayout(fields)
            preview = muted_label()
            card.box.addWidget(preview)

            def update(*args, v=var, p=preview, k=kind):
                w._update_name_preview(v, p, k)
            self.trace(var, update)
            update()
        card.box.addWidget(muted_label(w.t('name_help')))
        column.addWidget(card)
        separate = QCheckBox(w.t('separate_dirs'))
        bind_check(separate, w.var_separate_dirs)
        separate.clicked.connect(lambda checked=False: w._folders_changed())
        column.addWidget(separate)

    @staticmethod
    def insert_field(entry, field):
        entry.insert('{' + field + '}')
        entry.setFocus()

    # ------------------------------------------------------------------ Decryption
    def decrypt_page(self, column):
        w = self.w
        card = Card(w.t('dump_method'))
        # Two kinds of method: helper programs on the device (no Frida), and Frida with its two modes. The method
        # setting itself keeps one of three values; the family only decides which group of them is in use.
        w.var_family.set('native' if w.native_method() else 'frida')
        native_family = Option(w.t('family_native'), w.t('family_native_tip'))
        bind_radio(native_family.radio, w.var_family, 'native')
        card.box.addWidget(native_family)
        native_widgets = []
        for value, key in ((native_decrypt.AUTO, 'native_auto'), (native_decrypt.MREMAP, 'native_mremap'),
                           (native_decrypt.MEMORY, 'native_memory')):
            option = Option(w.t(key), w.t(key + '_tip'))
            option.setContentsMargins(24, 0, 0, 0)
            bind_radio(option.radio, w.var_native_helper, value)
            card.box.addWidget(option)
            native_widgets.append(option)
        frida_family = Option(w.t('family_frida'), w.t('family_frida_tip'))
        bind_radio(frida_family.radio, w.var_family, 'frida')
        card.box.addWidget(frida_family)
        frida_widgets = []
        direct_option = Option(w.t('dump_method_frida_direct'), w.t('dump_method_frida_direct_tip'))
        direct_option.setContentsMargins(24, 0, 0, 0)
        bind_radio(direct_option.radio, w.var_dump_method, METHOD_FRIDA_DIRECT)
        card.box.addWidget(direct_option)
        dump_option = Option(w.t('dump_method_frida_ios_dump'), w.t('dump_method_frida_ios_dump_tip'))
        dump_option.setContentsMargins(24, 0, 0, 0)
        bind_radio(dump_option.radio, w.var_dump_method, METHOD_FRIDA_IOS_DUMP)
        card.box.addWidget(dump_option)
        column.addWidget(card)

        dump_card = Card(w.t('dump_dir'))
        dump_entry = QLineEdit()
        bind_text(dump_entry, w.var_dump_dir)
        dump_browse = QPushButton(w.t('browse'))
        dump_browse.clicked.connect(lambda: w.choose_dir(w.var_dump_dir, DEFAULT_DUMP_DIR, self))
        line = QHBoxLayout()
        line.addWidget(dump_entry, 1)
        line.addWidget(dump_browse)
        dump_card.box.addLayout(line)
        status = StatusLine()
        install_dump = QPushButton(w.t('install_dump'))
        install_dump.clicked.connect(w.install_frida_ios_dump)
        status_row = QHBoxLayout()
        status_row.addWidget(status, 1)
        status_row.addWidget(install_dump)
        dump_card.box.addLayout(status_row)
        repair_box = QCheckBox(w.t('repair'))
        repair_box.setToolTip(w.t('repair_tip'))
        bind_check(repair_box, w.var_repair)
        close_after = QCheckBox(w.t('close_after'))
        bind_check(close_after, w.var_close_after)
        dump_card.box.addWidget(repair_box)
        dump_card.box.addWidget(muted_label(w.t('repair_tip')))
        dump_card.box.addWidget(close_after)
        dump_widgets = [dump_entry, dump_browse, status, install_dump, repair_box, close_after]
        column.addWidget(dump_card)

        frida_card = Card('Frida')
        restart = QCheckBox(w.t('restart_frida'))
        bind_check(restart, w.var_restart_frida)
        frida_card.box.addWidget(restart)
        port_entry = QLineEdit()
        port_entry.setFixedWidth(100)
        bind_text(port_entry, w.var_frida_port)
        frida_card.box.addLayout(self.row(w.t('frida_port'), port_entry, stretch=False))
        install = QPushButton(w.t('install'))
        install.clicked.connect(w.install_dependencies)
        install_row = QHBoxLayout()
        install_row.addWidget(install)
        install_row.addStretch(1)
        frida_card.box.addLayout(install_row)
        column.addWidget(frida_card)
        frida_widgets += [direct_option, dump_option, restart, port_entry, install]

        def update_status(*args):
            state = dump_dir_status(w.var_dump_dir.get().strip())
            status.set(w.t('dump_dir_' + state), {'ok': 'ok', 'no_bridge': 'partial'}.get(state, 'error'))
            # A missing or unset folder can be fixed by downloading frida-ios-dump.
            install_dump.setVisible(state in ('empty', 'missing'))

        def update_method(*args):
            # What does not belong to the chosen method is greyed out (and unused): the choice of helper with the
            # Frida modes, everything of Frida with the native helpers, and the options of frida-ios-dump with
            # the other Frida mode.
            method = w.var_dump_method.get()
            if method in (METHOD_FRIDA_DIRECT, METHOD_FRIDA_IOS_DUMP):
                w.frida_method = method
            w.var_family.set('native' if method == METHOD_NATIVE else 'frida')
            native = method == METHOD_NATIVE
            for widget in native_widgets:
                widget.setEnabled(native)
            for widget in frida_widgets:
                widget.setEnabled(not native)
            w.show_frida_indicator()
            dump_enabled = method == METHOD_FRIDA_IOS_DUMP
            for widget in dump_widgets:
                widget.setEnabled(dump_enabled)
            dump_card.setEnabled(dump_enabled)
            if dump_enabled:
                update_status()
            else:
                status.dot.set_color('idle')

        def update_family(*args):
            native = w.var_family.get() == 'native'
            if native and w.var_dump_method.get() != METHOD_NATIVE:
                w.var_dump_method.set(METHOD_NATIVE)
            elif not native and w.var_dump_method.get() == METHOD_NATIVE:
                w.var_dump_method.set(w.frida_method)

        self.trace(w.var_dump_dir, update_status)
        self.trace(w.var_dump_method, update_method)
        self.trace(w.var_family, update_family)
        update_status()
        update_method()

    # ------------------------------------------------------------------ Connection
    def connection_page(self, column):
        w = self.w
        column.addWidget(muted_label(w.t('connection_help')))
        card = Card(w.t('connection'))
        for name in CONNECTIONS:
            option = Option(w.t('conn_' + name), w.t('conn_' + name + '_tip'))
            bind_radio(option.radio, w.var_connection, name,
                       lambda: later(lambda: w.change_connection(w.var_connection.get())))
            card.box.addWidget(option)
        column.addWidget(card)

    # ------------------------------------------------------------------ About
    def about_page(self, column):
        w = self.w
        heading = QLabel('{} {}'.format(engine.APP_NAME, engine.__version__))
        heading.setObjectName('cardtitle')
        column.addWidget(heading)
        column.addWidget(muted_label(w.t('about_text')))
        details = engine.about_details()
        card = Card()
        for key, value in details:
            if key == 'about_project':
                link = QLabel('<a href="{0}" style="color:{1}">{0}</a>'.format(value, PALETTE['accent']))
                link.setTextFormat(Qt.RichText)
                link.setOpenExternalLinks(True)
                card.box.addLayout(self.row(w.t(key), link))
            else:
                label = QLabel(value)
                label.setWordWrap(True)
                label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                card.box.addLayout(self.row(w.t(key), label))
        column.addWidget(card)
        text = '\n'.join('{}: {}'.format(w.t(key), value) for key, value in [('tab_about', engine.APP_NAME)] + details)
        copy = QPushButton(w.t('about_copy'))
        copy.clicked.connect(lambda: QApplication.clipboard().setText(text))
        licenses = QPushButton(w.t('about_licenses'))
        licenses.clicked.connect(self.show_licenses)
        row = QHBoxLayout()
        row.addWidget(copy)
        row.addWidget(licenses)
        row.addStretch(1)
        column.addLayout(row)

    def show_licenses(self):
        """The license texts of the program and of what it contains, in a window of their own."""
        dialog = QDialog(self)
        dialog.setWindowTitle(self.w.t('about_licenses'))
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit()
        text.setReadOnly(True)
        text.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        text.setPlainText(engine.licenses_text())
        layout.addWidget(text)
        close = QPushButton(self.w.t('close'))
        close.clicked.connect(dialog.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)
        dialog.resize(820, 640)
        dialog.exec()


def i18n_system(window):
    import i18n
    return i18n.system_language(window.locales)
