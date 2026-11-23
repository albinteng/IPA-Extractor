"""The real window (PySide6, drawn into memory): connection modes, Settings, the app list, and the refusals that stop a batch
before it starts. Skipped where PySide6 is not installed."""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.support import needs_window  # noqa: F401  (sets QT_QPA_PLATFORM=offscreen before Qt is imported)

try:
    from PySide6.QtCore import QCoreApplication, QEvent, Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFrame, QLabel, QLineEdit, QPlainTextEdit,
                                   QPushButton, QRadioButton, QScrollArea)
except ImportError:
    raise unittest.SkipTest('PySide6 is not installed (the window needs it, the command line does not)')

import engine
from gui import dialogs, install_dialog, theme
from gui.main_window import MainWindow

APP = QApplication.instance() or QApplication([])


def pump(seconds=0.0, until=None):
    """Let the window handle its events (for `seconds`, or until `until()` is true)."""
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if until is not None and until():
            return True
        if time.time() >= end:
            return until is None
        time.sleep(0.01)


def texts(root):
    found = []
    for widget in root.findChildren(QLabel) + root.findChildren(QPushButton) + root.findChildren(QCheckBox) + \
            root.findChildren(QRadioButton):
        found.append(widget.text())
    return found


def app_entry(bundle, name='App', path='/var/containers/Bundle/Application/X/App.app', **extra):
    app = dict(bundle=bundle, name=name, version='1', build='1', path=path, pid=0, data='')
    app.update(extra)
    return app


class WindowTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.mkdtemp(prefix='window-test-')
        patcher = mock.patch.object(engine, 'CONFIG_PATH', os.path.join(folder, 'settings.json'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gui = MainWindow(APP)
        self.addCleanup(self.close)
        self.gui._save_config = lambda: None

    def close(self):
        self.gui._watch_timer.stop()
        if self.gui.settings_window is not None:
            self.gui.settings_close()
        self.gui.can_close = True
        self.gui.close()
        self.gui.deleteLater()
        # Really destroy it: a window left alive is restyled by every later setStyleSheet, and the suite slows down.
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)

    def select_page(self, key):
        dialog = self.gui.settings_window
        dialog.set_page(dialog.PAGES.index(key))
        pump(0.02)

    def settings_widgets(self, cls):
        return self.gui.settings_window.findChildren(cls)

    def go_usb(self, devices=()):
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=list(devices)), \
                mock.patch.object(engine.usbmux, 'describe', side_effect=lambda d: d):
            gui.open_settings()
            gui.change_connection('usb')
            pump(0.1)

    def test_the_frida_status_beside_ssh_shows_only_with_a_frida_method(self):
        indicator = self.gui.frida_indicator
        for method, shown in ((engine.METHOD_NATIVE, False), (engine.METHOD_FRIDA_DIRECT, True),
                              (engine.METHOD_NATIVE, False), (engine.METHOD_FRIDA_IOS_DUMP, True)):
            self.gui.var_dump_method.set(method)
            self.gui.show_frida_indicator()
            self.assertEqual(not indicator.isHidden(), shown, method)

    def test_ssh_is_the_default_and_usb_swaps_the_device_address_for_the_usb_device(self):
        gui = self.gui
        self.assertEqual(gui.var_connection.get(), 'ssh')
        labels = texts(gui.root_frame)
        self.assertIn(gui.t('host'), labels)
        self.assertNotIn(gui.t('usb_device'), labels)
        self.go_usb()
        labels = texts(gui.root_frame)
        self.assertNotIn(gui.t('host'), labels)
        self.assertIn(gui.t('usb_device'), labels)
        for key in ('ssh_port', 'user', 'password'):
            self.assertIn(gui.t(key), labels)       # the device's SSH port and account are still needed
        gui.settings_close()

    def test_the_connection_has_its_own_settings_page_with_the_two_choices(self):
        gui = self.gui
        gui.open_settings()
        pages = [gui.settings_window.nav.item(i).text() for i in range(gui.settings_window.nav.count())]
        self.assertIn(gui.t('tab_connection'), pages)
        self.select_page('tab_connection')
        radios = [w for w in self.settings_widgets(QRadioButton) if w.text() in (gui.t('conn_ssh'), gui.t('conn_usb'))]
        self.assertEqual(sorted(w.text() for w in radios), sorted([gui.t('conn_ssh'), gui.t('conn_usb')]))
        general = [w.text() for w in self.settings_widgets(QLabel)]
        self.assertEqual(general.count(gui.t('connection')), 1)      # the choice is only on the Connection page
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            next(w for w in radios if w.text() == gui.t('conn_usb')).click()
            pump(0.1)
        self.assertEqual(gui.var_connection.get(), 'usb')
        gui.settings_close()

    def test_the_connection_choices_explain_themselves_on_the_page(self):
        gui = self.gui
        for name in ('ssh', 'usb'):
            tip = gui.t('conn_{}_tip'.format(name))
            self.assertTrue(tip and tip != 'conn_{}_tip'.format(name))
        self.assertIn('IP', gui.t('conn_ssh_tip'))
        self.assertIn('usbmuxd', gui.t('conn_usb_tip'))
        gui.open_settings()
        self.select_page('tab_connection')
        self.assertIn(gui.t('conn_usb_tip'), [w.text() for w in self.settings_widgets(QLabel)])    # shown, not hidden in a tooltip
        gui.settings_close()

    def test_the_usb_device_has_a_box_of_its_own_with_the_account_fields_below(self):
        gui = self.gui
        self.go_usb()
        self.assertIsNotNone(gui.usb_box)
        labels = texts(gui.root_frame)
        for label in ('ssh_port', 'user', 'password', 'remember', 'usb_refresh', 'settings'):
            self.assertIn(gui.t(label), labels, label)
        gui.settings_close()

    def test_the_connection_is_saved_and_kept_while_a_batch_runs(self):
        gui = self.gui
        del gui._save_config        # the real one, which writes the patched settings file
        self.go_usb()
        with open(engine.CONFIG_PATH, encoding='utf-8') as handle:
            self.assertEqual(json.load(handle)['connection'], 'usb')
        gui.dumping = True
        with mock.patch.object(dialogs, 'showwarning') as warning:
            gui.change_connection('ssh')
        warning.assert_called_once()
        self.assertEqual(gui.var_connection.get(), 'usb')      # the radio button goes back
        gui.dumping = False
        gui.settings_close()

    def test_switching_the_connection_asks_first_and_ends_the_old_one(self):
        gui = self.gui
        self.go_usb()
        for connected, connecting in ((True, False), (False, True)):
            client = mock.Mock()
            gui.ssh, gui.ssh_connecting = (client if connected else None), connecting
            generation = gui.generation
            with mock.patch.object(dialogs, 'askyesno', return_value=False) as ask:
                gui.change_connection('ssh')
            ask.assert_called_once()
            self.assertEqual(gui.var_connection.get(), 'usb')           # declined: nothing changed
            self.assertEqual(gui.generation, generation)
            with mock.patch.object(dialogs, 'askyesno', return_value=True):
                gui.change_connection('ssh')
            self.assertEqual(gui.var_connection.get(), 'ssh')
            self.assertIsNone(gui.ssh)
            self.assertFalse(gui.ssh_connecting)                        # a connect still running is stale
            self.assertGreater(gui.generation, generation)              # so its answer is dropped
            if connected:
                client.close.assert_called_once()
            with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
                gui.change_connection('usb')
        gui.settings_close()

    def test_a_device_list_error_is_logged_once_not_at_every_rebuild(self):
        gui = self.gui
        error = engine.usbmux.UsbmuxError('usb_err_none')
        gui.usb_listing = 5
        before = gui.log_text.toPlainText()
        gui._usb_listed([], error, 5)
        gui._usb_listed([], error, 5)
        added = gui.log_text.toPlainText()[len(before):]
        self.assertEqual(added.count(gui.t('usb_err_none')), 1)

    def usb_box_after(self, attached):
        """Press Refresh with these devices attached; what the window's USB device box shows afterwards."""
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=attached), \
                mock.patch.object(engine.usbmux, 'describe', side_effect=lambda d: d):
            gui.refresh_usb()
            pump(0.4)
        box = gui.usb_box
        values = [box.itemText(i) for i in range(box.count())]
        shown = box.currentText() if box.currentIndex() >= 0 else box.placeholderText()
        return values, shown

    def test_refresh_follows_the_devices_as_they_come_and_go(self):
        gui = self.gui
        self.go_usb()
        self.assertEqual(self.usb_box_after([]), ([], gui.t('usb_none')))
        phone = engine.usbmux.Device(1, 'UDID-A')
        phone.name, phone.model, phone.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        values, shown = self.usb_box_after([phone])
        self.assertEqual((values, shown), ([phone.label()], phone.label()))
        # unplugged: nothing is attached, and the box says that (not the remembered device, not a bare UDID)
        self.assertEqual(self.usb_box_after([]), ([], gui.t('usb_none')))
        self.assertEqual(gui.var_usb_device.get(), 'UDID-A')      # remembered, so the same phone is chosen again
        values, shown = self.usb_box_after([phone])
        self.assertEqual(shown, phone.label())
        other = engine.usbmux.Device(2, 'UDID-B')
        other.name = 'Other'
        values, shown = self.usb_box_after([other])
        self.assertEqual((values, shown, gui.var_usb_device.get()), ([other.label()], other.label(), 'UDID-B'))
        gui.settings_close()

    def test_an_older_slower_answer_does_not_overwrite_a_later_refresh(self):
        gui = self.gui
        self.go_usb()
        gui.usb_listing = 5
        gone = engine.usbmux.Device(1, 'UDID-A')
        gui._usb_listed([gone], None, 4)        # the answer of Refresh number 4 arrives after number 5 was asked
        self.assertEqual(gui.usb_devices, [])
        gui._usb_listed([], None, 5)
        self.assertEqual(gui.usb_devices, [])
        gui.settings_close()

    def test_a_failing_callback_does_not_stop_the_window_from_taking_later_events(self):
        gui = self.gui
        seen = []
        with mock.patch('gui.main_window.traceback.print_exc'):
            gui.post(lambda: 1 / 0)
            gui.post(seen.append, 'later')
            pump(0.05)
        self.assertEqual(seen, ['later'])

    def click(self, widget):
        QTest.mouseClick(widget, Qt.LeftButton)
        pump(0.05)

    def test_the_settings_window_opens_again_after_it_was_closed_with_the_buttons(self):
        # It once opened only the first time: the settings the first window had bound to were still calling into its
        # deleted widgets, and building the second window raised. Real clicks, and the widgets really destroyed.
        gui = self.gui
        gui.show()
        for round_ in range(4):
            settings = next(b for b in gui.findChildren(QPushButton) if b.text() == gui.t('settings'))
            self.click(settings)
            self.assertIsNotNone(gui.settings_window, round_)
            self.assertTrue(gui.settings_window.isVisible(), round_)
            close = next(b for b in gui.settings_window.findChildren(QPushButton) if b.text() == gui.t('close'))
            self.click(close)
            self.assertIsNone(gui.settings_window, round_)
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)

    def test_settings_changed_after_a_window_was_rebuilt_do_not_reach_its_deleted_widgets(self):
        gui = self.gui
        gui.change_language('de')               # rebuilds the whole window: the old widgets are deleted
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        for var in (gui.var_host, gui.var_user, gui.var_remember, gui.var_search):
            var.set(var.get())                  # must not raise "Internal C++ object already deleted"
        gui.var_host.set('1.2.3.4')
        gui.change_language('en')

    def test_the_boxes_beside_buttons_and_entries_sit_on_the_middle_of_the_row(self):
        from PySide6.QtWidgets import QWidget
        from gui.widgets import FlowLayout
        holder = QWidget()
        flow = FlowLayout(holder)
        tall, short = QPushButton('A tall button'), QCheckBox('a box')
        tall.setFixedHeight(60)
        flow.addWidget(tall)
        flow.addWidget(short)
        holder.resize(800, 200)
        holder.show()
        pump(0.05)
        centre = lambda widget: widget.geometry().center().y()
        self.assertLessEqual(abs(centre(tall) - centre(short)), 1)
        holder.resize(100, 200)          # too narrow for both: they wrap onto two lines
        pump(0.05)
        self.assertGreater(short.geometry().top(), tall.geometry().bottom() - 1)
        holder.close()

    def test_in_the_window_the_boxes_share_the_middle_of_the_row_with_the_buttons_beside_them(self):
        gui = self.gui
        gui.show()
        pump(0.1)
        pairs = ((gui.t('remember'), QCheckBox, gui.t('connect')), (gui.t('user_only'), QCheckBox, gui.t('refresh')))
        for box_text, box_class, button_text in pairs:
            box = next(c for c in gui.findChildren(box_class) if c.text() == box_text)
            button = next(b for b in gui.findChildren(QPushButton) if b.text() == button_text)
            centre = lambda widget: widget.mapTo(gui, widget.rect().center()).y()
            if abs(centre(box) - centre(button)) < button.height():       # on the same line (a narrow screen wraps them)
                self.assertLessEqual(abs(centre(box) - centre(button)), 1, box_text)

    def test_the_device_heading_and_settings_share_the_first_line_above_the_frame(self):
        gui = self.gui
        gui.show()
        pump(0.1)
        title = next(l for l in gui.findChildren(QLabel) if l.text() == gui.t('device'))
        settings = next(b for b in gui.findChildren(QPushButton) if b.text() == gui.t('settings'))
        frame = next(f for f in gui.findChildren(QFrame) if f.objectName() == 'card')
        self.assertNotEqual(title.objectName(), 'cardtitle')              # plain text, not bold
        self.assertLessEqual(abs(title.mapTo(gui, title.rect().center()).y() - settings.mapTo(gui, settings.rect().center()).y()), 2)
        self.assertLess(title.mapTo(gui, title.rect().bottomLeft()).y(), frame.mapTo(gui, frame.rect().topLeft()).y())
        self.assertGreater(settings.mapTo(gui, settings.rect().topRight()).x(), frame.mapTo(gui, frame.rect().topRight()).x() - 40)
        self.assertNotIn('hint', gui.locales['en'])
        self.assertNotIn('decrypt_help', gui.locales['en'])
        self.assertFalse([l for l in gui.findChildren(QLabel) if l.text().startswith('Tip:')])

    def test_a_call_posted_from_another_thread_runs_on_the_window_thread(self):
        gui = self.gui
        ran = []
        worker = threading.Thread(target=lambda: gui.post(lambda: ran.append(threading.current_thread())))
        worker.start()
        worker.join()
        self.assertTrue(pump(2, until=lambda: ran))
        self.assertIs(ran[0], threading.main_thread())

    def test_the_ready_line_follows_the_connection_each_time_it_changes(self):
        gui = self.gui

        def lines():
            return gui.log_text.toPlainText().splitlines()
        self.assertIn(gui.t('log_ready'), lines()[-1])
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
            self.assertIn(gui.t('log_ready_usb'), lines()[-1])
            gui.change_connection('ssh')
            self.assertIn(gui.t('log_ready'), lines()[-1])
            gui.change_connection('usb')
            self.assertIn(gui.t('log_ready_usb'), lines()[-1])
        self.assertEqual(sum(gui.t('log_ready_usb') in line for line in lines()), 2)
        self.assertNotIn('', lines())       # rebuilding the window leaves no blank lines in the log
        self.assertNotIn('IP', gui.t('log_ready_usb'))
        gui.settings_close()

    def test_changing_the_theme_restyles_the_window_and_keeps_the_log(self):
        gui = self.gui
        gui.log('a line the rebuild must keep')
        for name in ('dark', 'light', 'black', 'dark'):
            gui.change_theme(name)
            self.assertEqual(theme.PALETTE['bg'], theme.PALETTES[name]['bg'])
            self.assertIn(theme.PALETTES[name]['bg'], APP.styleSheet())
        self.assertIn('a line the rebuild must keep', gui.log_text.toPlainText())

    def test_the_usb_device_box_shows_the_name_and_keeps_the_udid(self):
        gui = self.gui
        device = engine.usbmux.Device(1, '00008030-0014394602E0802E')
        device.name, device.model, device.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        self.go_usb([device])
        self.assertEqual(gui.usb_devices, [device])
        self.assertEqual(gui.var_usb_device.get(), '00008030-0014394602E0802E')     # kept: the UDID
        self.assertEqual(gui.usb_box.itemText(0), device.label())
        self.assertEqual(gui.usb_box.toolTip(), device.label())      # a long name is read in full from the tooltip
        gui.settings_close()

    def test_the_settings_keep_showing_the_frida_options_with_a_native_helper(self):
        self.gui.open_settings()
        self.select_page('tab_decrypt')
        port = [w for w in self.settings_widgets(QLineEdit) if w.width() == 100 or w.maximumWidth() == 100][0]
        for method, enabled in ((engine.METHOD_NATIVE, False), (engine.METHOD_FRIDA_DIRECT, True)):
            self.gui.var_dump_method.set(method)
            pump(0.02)
            self.assertFalse(port.isHidden(), method)            # still there, greyed out with the native helpers
            self.assertEqual(port.isEnabled(), enabled, method)
        self.gui.settings_close()

    def test_every_settings_page_scrolls_and_the_window_stays_inside_the_screen(self):
        gui = self.gui
        gui.open_settings()
        dialog = gui.settings_window
        screen = APP.primaryScreen().availableGeometry()
        self.assertLessEqual(dialog.height(), screen.height())
        self.assertLessEqual(dialog.width(), screen.width())
        self.assertEqual(len(dialog.findChildren(QScrollArea)), len(dialog.PAGES))
        gui.settings_close()

    def test_the_about_page_has_the_version_and_a_copy_button(self):
        gui = self.gui
        gui.open_settings()
        self.assertEqual(gui.settings_window.PAGES[-1], 'tab_about')
        self.select_page('tab_about')
        shown = [w.text() for w in self.settings_widgets(QLabel)]
        self.assertIn('{} {}'.format(engine.APP_NAME, engine.__version__), shown)
        self.assertNotIn(engine.__version__, gui.windowTitle())     # the title no longer carries the version
        button = next(w for w in self.settings_widgets(QPushButton) if w.text() == gui.t('about_copy'))
        button.click()
        copied = APP.clipboard().text()
        self.assertIn(engine.__version__, copied)
        self.assertIn(engine.CONFIG_PATH, copied)
        gui.settings_close()

    def test_the_licenses_button_shows_the_full_texts(self):
        gui = self.gui
        gui.open_settings()
        self.select_page('tab_about')
        button = next(w for w in self.settings_widgets(QPushButton) if w.text() == gui.t('about_licenses'))
        shown = {}

        def fake_exec(dialog):
            edit = dialog.findChild(QPlainTextEdit)
            shown['title'] = dialog.windowTitle()
            shown['text'] = edit.toPlainText()
            shown['read_only'] = edit.isReadOnly()
            return 0
        with mock.patch.object(QDialog, 'exec', fake_exec):
            button.click()
        self.assertEqual(shown['title'], gui.t('about_licenses'))
        self.assertTrue(shown['read_only'])
        self.assertIn('MIT License', shown['text'])
        self.assertIn('GNU Lesser General Public License', shown['text'])
        self.assertIn('Apache License', shown['text'])
        gui.settings_close()

    def test_changing_the_language_rebuilds_the_window_in_it_and_reopens_the_settings_page(self):
        gui = self.gui
        gui.open_settings()
        self.select_page('tab_extract')
        gui.change_language('de')
        self.assertEqual(gui.lang, 'de')
        self.assertIn(gui.t('connect'), texts(gui.root_frame))
        self.assertEqual(gui.settings_window.current_page(), 1)      # the same page, now in German
        gui.change_language('en')
        gui.settings_close()

    # ------------------------------------------------------------------ the app list
    def fill_apps(self, count=5):
        gui = self.gui
        gui.apps = {'a.b{}'.format(i): app_entry('a.b{}'.format(i), name='App {}'.format(chr(ord('A') + i)))
                    for i in range(count)}
        gui.refresh_tree()
        return gui.tree.get_children()

    def test_the_list_shows_the_apps_sorted_and_filtered_by_the_search_box(self):
        gui = self.gui
        rows = self.fill_apps()
        self.assertEqual(rows, ['a.b0', 'a.b1', 'a.b2', 'a.b3', 'a.b4'])
        gui.sort_by('name')                                          # the same column again: reversed
        self.assertEqual(gui.tree.get_children(), list(reversed(rows)))
        gui.var_search.set('app c')
        self.assertEqual(gui.tree.get_children(), ['a.b2'])
        self.assertIn('1', gui.lbl_count.text())
        gui.var_search.set('')

    def test_checking_rows_by_click_shift_click_double_click_and_space(self):
        gui = self.gui
        rows = self.fill_apps()
        gui.on_check_click(rows[1], False)
        self.assertEqual(gui.checked, {rows[1]})
        gui.on_check_click(rows[3], True)                            # Shift: the range from the anchor
        self.assertEqual(gui.checked, set(rows[1:4]))
        gui.on_tree_double_click(rows[0])
        self.assertIn(rows[0], gui.checked)
        gui.tree.selection_set([rows[0], rows[1]])
        gui.on_space()                                               # all checked: the space unchecks them
        self.assertNotIn(rows[0], gui.checked)
        self.assertNotIn(rows[1], gui.checked)
        self.assertIn('Extract decrypted IPA (2)', gui.btn_dump.text())
        self.assertIs(gui.tree.row_check(rows[0]), False)
        self.assertIs(gui.tree.row_check(rows[2]), True)
        self.assertFalse(gui.tree.header().all_checked)
        gui.on_header_click(0)                                       # the header's box checks every shown app
        self.assertEqual(gui.checked, set(rows))
        self.assertTrue(gui.tree.header().all_checked)
        self.assertTrue(all(gui.tree.row_check(b) for b in rows))

    def test_nothing_can_be_checked_while_a_batch_runs(self):
        gui = self.gui
        rows = self.fill_apps()
        gui.dumping = True
        gui.on_check_click(rows[0], False)
        gui.check_all()
        gui.on_space()
        self.assertEqual(gui.checked, set())
        gui.dumping = False

    def test_an_app_with_nothing_on_the_device_cannot_be_checked(self):
        gui = self.gui
        gui.apps = {'a.b': app_entry('a.b', offloaded=True)}
        gui.refresh_tree()
        gui.set_checked(['a.b'], True)
        self.assertEqual(gui.checked, set())
        self.assertIsNone(gui.tree.row_check('a.b'))                  # and it has no check box to show

    def test_a_status_colours_its_row_and_the_extract_buttons_follow_the_checks(self):
        gui = self.gui
        rows = self.fill_apps(2)
        self.assertFalse(gui.btn_extract.isEnabled())
        gui.set_checked([rows[0]], True)
        self.assertTrue(gui.btn_extract.isEnabled())
        gui.set_status(rows[0], engine.Text('st_queued'), 'queued')
        item = gui.tree.topLevelItem(0)
        self.assertEqual(item.text(8), gui.t('st_queued'))
        self.assertEqual(item.foreground(1).color().name(), theme.PALETTE['queued'])

    # ------------------------------------------------------------------ batches
    def dump_with(self, helper, device_os):
        gui = self.gui
        gui.var_dump_method.set(engine.METHOD_NATIVE)
        gui.var_native_helper.set(helper)
        gui.device_os = device_os
        gui.ssh = object()
        gui.apps = {'a.b': {'bundle': 'a.b', 'name': 'name', 'version': '1', 'build': '1'}}
        gui._checked_in_order = lambda: ['a.b']
        gui._jobs = lambda *args: [('a.b', 'name')]
        gui._prepare_batch = mock.Mock(return_value=None)       # stops right after the checks
        with mock.patch.object(dialogs, 'showerror') as error:
            gui.start_dump()
        return error, gui._prepare_batch

    def test_installing_frida_without_a_connection_still_lists_the_versions(self):
        """Not connected, nothing chosen yet: the install command is worked out for a placeholder version, and that
        once raised and stopped the window before it asked PyPI, leaving the version box empty and "loading..." for ever."""
        with mock.patch.object(install_dialog, 'frida_releases', return_value=['17.0.0', '16.6.6']):
            self.gui.open_install_dialog(None)
            window = self.gui.install_window
            self.assertTrue(pump(5, until=lambda: any(b.count() for b in window.findChildren(QComboBox))),
                            'the version box was never filled')
        box = window.findChildren(QComboBox)[0]
        self.assertIn('17.0.0', [box.itemText(i) for i in range(box.count())])
        self.assertIn(self.gui.t('inst_latest', version='17.0.0'), texts(window))
        window.close()

    def test_file_mapping_on_ios_16_is_explained_and_nothing_starts(self):
        error, prepare = self.dump_with('mremap', 'iOS 16.1.2')
        error.assert_called_once()
        self.assertIn('16.1.2', error.call_args[0][1])
        prepare.assert_not_called()

    def test_an_unreadable_helper_warns_and_nothing_starts(self):
        with mock.patch.object(engine.native_decrypt, 'local_helper',
                               side_effect=engine.native_decrypt.HelperError('x cannot be read')), \
                mock.patch.object(dialogs, 'showwarning') as warning:
            error, prepare = self.dump_with('memory', 'iOS 17.0')
        warning.assert_called_once()
        self.assertIn('x cannot be read', warning.call_args[0][1])
        prepare.assert_not_called()

    def test_a_connection_lost_while_the_overwrite_question_is_open_leaves_the_window_usable(self):
        gui = self.gui

        def question_answered(mode, jobs, names=None):
            gui.dumping = True                 # what _prepare_batch does once the question is answered
            gui.endpoint = None                # ... and the connection went away while it was open
            return '/tmp/out'

        gui.var_dump_method.set(engine.METHOD_NATIVE)
        gui.var_native_helper.set('memory')
        gui.device_os = 'iOS 17.0'
        gui.ssh = object()
        gui.endpoint = None
        gui.apps = {'a.b': {'bundle': 'a.b', 'name': 'name', 'version': '1', 'build': '1'}}
        gui._checked_in_order = lambda: ['a.b']
        gui._jobs = lambda *args: [('a.b', 'name')]
        gui._prepare_batch = question_answered
        gui.run_background = mock.Mock()
        with mock.patch.object(dialogs, 'showinfo') as info:
            gui.start_dump()
        self.assertFalse(gui.dumping)                  # it stayed True for good, and every button with it
        info.assert_called_once()
        gui.run_background.assert_not_called()

    def test_a_helper_that_fails_on_the_device_is_logged_once_per_batch_without_a_dialog(self):
        gui = self.gui
        gui.helper_warned = False
        gui.log = mock.Mock()
        with mock.patch.object(dialogs, 'showwarning') as warning:
            gui.helper_problem('would not start')
            gui.helper_problem('would not start')
        warning.assert_not_called()          # a dialog would stop the progress of an unattended batch
        gui.log.assert_called_once()

    def test_a_batch_being_set_up_is_not_started_a_second_time(self):
        gui = self.gui
        started = []
        gui._start_dump = lambda: started.append('dump')
        gui._start_extract = lambda: started.append('extract')
        gui.preparing = True                 # the first one still has its overwrite question open
        gui.start_dump()
        gui.start_extract()
        self.assertEqual(started, [])
        gui.preparing = False
        gui.start_dump()
        self.assertEqual(started, ['dump'])
        self.assertFalse(gui.preparing)      # given back once it is over, whatever it did

    def test_the_flag_is_given_back_when_setting_up_fails(self):
        gui = self.gui

        def broken():
            raise ValueError

        gui._start_dump = broken
        with self.assertRaises(ValueError):
            gui.start_dump()
        self.assertFalse(gui.preparing)

    def test_the_app_list_is_not_replaced_while_a_batch_is_being_set_up(self):
        gui = self.gui
        gui.ssh = object()
        gui.preparing = True
        gui.run_background = mock.Mock()
        with mock.patch.object(dialogs, 'showwarning') as warning:
            gui.load_apps()
        warning.assert_called_once()
        gui.run_background.assert_not_called()
        gui.preparing = False

    def test_file_mapping_on_ios_15_and_the_other_helpers_go_on(self):
        for helper, device_os in (('mremap', 'iOS 15.8'), ('auto', 'iOS 16.1.2'), ('memory', 'iOS 17.0')):
            error, prepare = self.dump_with(helper, device_os)
            error.assert_not_called()
            prepare.assert_called_once()

    # ------------------------------------------------------------------ closing
    def test_closing_while_a_batch_runs_asks_first_and_stays_open_when_declined(self):
        gui = self.gui
        gui.dumping = True
        with mock.patch.object(dialogs, 'askyesno', return_value=False) as ask:
            gui.close()
        ask.assert_called_once()
        self.assertFalse(gui.can_close)
        self.assertFalse(gui.closing)            # it can be closed again later
        gui.dumping = False

    def test_closing_while_a_batch_runs_cancels_it_and_waits_for_it(self):
        gui = self.gui
        gui.dumping = True
        worker = threading.Thread(target=lambda: gui.cancel_requested.wait(5))
        worker.start()
        gui.batch_thread = worker
        with mock.patch.object(dialogs, 'askyesno', return_value=True), mock.patch.object(engine, 'stop_children') as stop:
            gui.close()
        self.assertTrue(gui.cancel_requested.is_set())
        self.assertFalse(worker.is_alive())      # it was given the time to clean up
        stop.assert_called_once()
        self.assertTrue(gui.can_close)

    def test_closing_an_idle_window_just_closes_it(self):
        gui = self.gui
        with mock.patch.object(dialogs, 'askyesno') as ask:
            gui.close()
        ask.assert_not_called()
        self.assertTrue(gui.can_close)


if __name__ == '__main__':
    unittest.main()
