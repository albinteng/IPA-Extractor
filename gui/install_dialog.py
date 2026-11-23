# -*- coding: utf-8 -*-
"""The Install Frida dependencies window: pick the frida version to install (it doubles as the confirmation)."""

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QRadioButton,
                               QVBoxLayout, QWidget)

import engine
import frida_versions
from engine import Text, frida_releases, frida_server_status, major
from gui import dialogs
from gui.state import StringVar, bind_radio
from gui.widgets import muted_label


def open_install_dialog(w, dump_dir):
    """Let the user pick the frida version to install; the dialog doubles as the confirmation."""
    if w.install_window is not None:
        w.install_window.raise_()
        w.install_window.activateWindow()
        return
    window = w.install_window = QDialog(w)
    window.setWindowTitle('{} – Install Frida dependencies'.format(engine.APP_NAME))
    window.setMinimumWidth(640)
    alive = [True]

    def closed(*args):
        alive[0] = False
        if w.install_window is window:
            w.install_window = None
    window.finished.connect(closed)
    box = QVBoxLayout(window)
    box.setContentsMargins(18, 16, 18, 14)
    box.setSpacing(8)
    device = [w.device_frida_version]
    # 'found', 'missing' (no frida-server on the device), 'no_ssh' or 'checking'
    device_state = ['found' if device[0] else ('no_ssh' if w.ssh is None else 'checking')]
    latest = [None]
    choice = StringVar('device' if device[0] else 'latest')
    custom = StringVar()
    versions = QLabel()
    box.addWidget(versions)
    # Installed versions, each with a delete button.
    box.addWidget(QLabel(w.t('inst_installed')))
    installed_box = QVBoxLayout()
    installed_box.setContentsMargins(16, 0, 0, 6)
    installed_holder = QWidget()
    installed_holder.setLayout(installed_box)
    box.addWidget(installed_holder)
    box.addWidget(QLabel(w.t('inst_add')))
    device_option = QRadioButton()
    bind_radio(device_option, choice, 'device')
    box.addWidget(device_option)
    latest_option = QRadioButton(w.t('inst_latest', version=w.t('inst_loading')))
    bind_radio(latest_option, choice, 'latest')
    box.addWidget(latest_option)
    custom_row = QHBoxLayout()
    custom_radio = QRadioButton(w.t('inst_custom'))
    bind_radio(custom_radio, choice, 'custom')
    custom_row.addWidget(custom_radio)
    custom_box = QComboBox()
    custom_box.setEditable(True)
    custom_box.setMinimumWidth(160)
    custom_box.activated.connect(lambda i: (custom.set(custom_box.itemText(i)), choice.set('custom')))
    custom_box.editTextChanged.connect(lambda text: (custom.set(text), choice.set('custom') if text else None))
    custom_row.addWidget(custom_box)
    custom_row.addStretch(1)
    box.addLayout(custom_row)
    warning = muted_label()
    box.addWidget(warning)
    box.addWidget(QLabel(w.t('inst_will_run', path=frida_versions.ROOT)))
    commands_text = QPlainTextEdit()
    commands_text.setReadOnly(True)
    commands_text.setFixedHeight(commands_text.fontMetrics().lineSpacing() * 6)
    box.addWidget(commands_text)
    buttons = QHBoxLayout()
    buttons.addStretch(1)
    run_button = QPushButton(w.t('inst_run'))
    run_button.setObjectName('primary')
    cancel_button = QPushButton(w.t('inst_cancel'))
    cancel_button.clicked.connect(window.close)
    buttons.addWidget(run_button)
    buttons.addWidget(cancel_button)
    box.addLayout(buttons)

    def selected():
        version = {'device': device[0], 'latest': latest[0], 'custom': custom.get().strip()}[choice.get()]
        return version if version and re.fullmatch(r'\d+\.\d+\.\d+', version) else None

    def delete(version):
        if w.busy() or w.installing:
            return
        if w.frida_connecting:
            return
        if not dialogs.askyesno(w.t('m_frida_delete_t'), w.t('m_frida_delete', version=version), parent=window):
            return
        if w.busy() or w.installing or w.frida_connecting:      # begun while the question was open
            return
        in_use = version == w.frida_version
        if in_use:
            w._drop_frida()
            w.set_frida_state(Text('state_unused'), 'idle')
        try:
            frida_versions.remove(version)
            w.log(Text('log_frida_deleted', version=version))
        except OSError as error:
            dialogs.showerror(w.t('m_frida_delete_t'), str(error), parent=window)
        refresh()
        if in_use and w.ssh is not None:
            w.connect_frida()  # picks another installed version, or offers a download

    def refresh_installed():
        while installed_box.count():
            item = installed_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count():
                    child = item.layout().takeAt(0)
                    if child.widget():
                        child.widget().deleteLater()
        installed = frida_versions.installed()
        if not installed:
            installed_box.addWidget(muted_label(w.t('not_installed')))
        for version in installed:
            row = QHBoxLayout()
            text = version
            if version == w.frida_version:
                text = w.t('inst_in_use', version=version)
            elif device[0] and version == frida_versions.pick(device[0], installed):
                text = w.t('inst_for_device', version=version)
            label = QLabel(text)
            label.setMinimumWidth(220)
            row.addWidget(label)
            delete_button = QPushButton(w.t('inst_delete'))
            delete_button.clicked.connect(lambda checked=False, v=version: delete(v))
            row.addWidget(delete_button)
            row.addStretch(1)
            installed_box.addLayout(row)

    def refresh(*args):
        if not alive[0]:
            return
        state = device_state[0]
        shown = {'found': device[0], 'missing': w.t('not_installed'), 'no_ssh': w.t('inst_no_ssh'),
                 'checking': w.t('inst_checking')}[state]
        versions.setText(w.t('inst_device_version', device=shown))
        refresh_installed()
        device_option.setText({'found': w.t('inst_device', version=device[0]),
                               'missing': w.t('inst_device_missing'), 'no_ssh': w.t('inst_device_no_ssh'),
                               'checking': w.t('inst_device_checking')}[state])
        device_option.setEnabled(bool(device[0]))
        version = selected()
        if version and version in frida_versions.installed():
            warning.setText(w.t('inst_reinstall', version=version))
        elif version and device[0] and major(version) != major(device[0]):
            warning.setText(w.t('inst_other_major', device=device[0]))
        else:
            warning.setText('')
        commands = w._install_commands(version or '?', dump_dir)
        commands_text.setPlainText('\n'.join(' '.join(c) + ('   ({})'.format(cwd) if cwd else '')
                                             for c, cwd in commands))
        run_button.setEnabled(bool(version and not w.installing))

    def loaded(found_device, releases, error):
        if not alive[0]:
            return
        if device_state[0] == 'checking':
            device_state[0] = found_device
        if found_device not in ('missing', 'no_ssh') and not device[0]:
            device[0] = w.device_frida_version = found_device
            device_state[0] = 'found'
            choice.set('device')
        if releases:
            latest[0] = releases[0]
            latest_option.setText(w.t('inst_latest', version=releases[0]))
            custom_box.blockSignals(True)
            custom_box.clear()
            custom_box.addItems(releases)
            custom_box.setEditText(custom.get())
            custom_box.blockSignals(False)
        else:
            latest_option.setText(w.t('inst_fetch_failed', error=error))
            latest_option.setEnabled(False)
            if choice.get() == 'latest':
                choice.set('custom')
        refresh()

    def fetch():
        found_device = device_state[0]
        if device_state[0] == 'checking':
            try:
                found_device = frida_server_status(w.ssh)[0] or 'missing'
            except Exception:
                found_device = 'no_ssh'
        try:
            releases, error = frida_releases(), None
        except Exception as exc:
            releases, error = [], exc
        w.post(loaded, found_device, releases, error)

    def run():
        version = selected()
        if not version or w.busy() or w.installing or w.frida_connecting:
            return
        window.close()
        w.installing = True
        w._checks_changed()
        w.run_background(w._install_worker, version, dump_dir, None)

    run_button.clicked.connect(run)
    choice.trace_add('write', refresh)
    custom.trace_add('write', refresh)
    refresh()
    window.show()
    w.style_titlebar(window)
    w.run_background(fetch)
