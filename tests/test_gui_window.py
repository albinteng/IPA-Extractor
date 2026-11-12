"""The real window: Settings → Decryption and the refusal of file mapping. Skipped where there is no display."""
import json
import os
import tempfile
import time
import unittest
from unittest import mock

try:
    from tkinter import messagebox, ttk
except ImportError:
    raise unittest.SkipTest('tkinter is not installed (the window needs it, the command line does not)')

import engine
import ipa_extractor as core


def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def label_with(root, text):
    for widget in walk(root):
        try:
            if widget.cget('text') == text:
                return widget
        except Exception:
            pass
    return None


class WindowTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.mkdtemp(prefix='window-test-')
        patcher = mock.patch.object(engine, 'CONFIG_PATH', os.path.join(folder, 'settings.json'))
        patcher.start()
        self.addCleanup(patcher.stop)
        try:
            self.gui = core.DumpGUI()
        except Exception as error:      # no display (tk.TclError), or no tkinter at all
            self.skipTest('no window available: {}'.format(error))
        self.addCleanup(self.close)
        self.gui.withdraw()
        self.gui._save_config = lambda: None

    def close(self):
        for callback in self.gui.tk.call('after', 'info'):      # the window's timers must not outlive it
            self.gui.after_cancel(callback)
        self.gui.destroy()

    def select_tab(self, key):
        for widget in walk(self.gui.settings_window):
            if isinstance(widget, ttk.Notebook):
                for index, tab in enumerate(widget.tabs()):
                    if widget.tab(tab, 'text') == self.gui.t(key):
                        widget.select(index)
        self.gui.update()

    def select_decryption_tab(self):
        for widget in walk(self.gui):
            if isinstance(widget, ttk.Notebook):
                for index, tab in enumerate(widget.tabs()):
                    if widget.tab(tab, 'text') == self.gui.t('tab_decrypt'):
                        widget.select(index)
        self.gui.update()

    def test_the_frida_status_beside_ssh_shows_only_with_a_frida_method(self):
        frame = self.gui.frida_dot.master
        for method, shown in ((engine.METHOD_NATIVE, False), (engine.METHOD_FRIDA_DIRECT, True),
                              (engine.METHOD_NATIVE, False), (engine.METHOD_FRIDA_IOS_DUMP, True)):
            self.gui.var_dump_method.set(method)
            self.gui.show_frida_indicator()
            self.assertEqual(bool(frame.winfo_manager()), shown, method)     # unpacked: no geometry manager

    def shown_labels(self):
        found = []
        for widget in walk(self.gui.root_frame):
            try:
                found.append(widget.cget('text'))
            except Exception:
                pass
        return found

    def test_ssh_is_the_default_and_usb_swaps_the_device_address_for_the_usb_device(self):
        gui = self.gui
        self.assertEqual(gui.var_connection.get(), 'ssh')
        labels = self.shown_labels()
        self.assertIn(gui.t('host'), labels)
        self.assertNotIn(gui.t('usb_device'), labels)
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
            gui.update()
        labels = self.shown_labels()
        self.assertNotIn(gui.t('host'), labels)
        self.assertIn(gui.t('usb_device'), labels)
        for key in ('ssh_port', 'user', 'password'):
            self.assertIn(gui.t(key), labels)       # the device's SSH port and account are still needed
        gui.settings_close()

    def test_the_connection_has_its_own_settings_tab_with_the_two_choices(self):
        gui = self.gui
        gui.open_settings()
        tabs = [gui.settings_tabs.tab(tab, 'text') for tab in gui.settings_tabs.tabs()]
        self.assertIn(gui.t('tab_connection'), tabs)
        self.select_tab('tab_connection')
        radios = [w for w in walk(gui.settings_window) if isinstance(w, ttk.Radiobutton)
                  and w.cget('text') in (gui.t('conn_ssh'), gui.t('conn_usb'))]
        self.assertEqual(sorted(w.cget('text') for w in radios), sorted([gui.t('conn_ssh'), gui.t('conn_usb')]))
        self.assertEqual({gui.settings_tabs.nametowidget(gui.settings_tabs.select()), }, {radios[0].master})   # on its tab
        general = [widget.cget('text') for widget in walk(gui.settings_window) if isinstance(widget, ttk.Label)]
        self.assertEqual(general.count(gui.t('connection')), 1)      # the choice is only in the Connection tab
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            next(w for w in radios if w.cget('text') == gui.t('conn_usb')).invoke()
        self.assertEqual(gui.var_connection.get(), 'usb')
        gui.settings_close()

    def test_the_connection_choices_explain_themselves_in_a_tooltip(self):
        gui = self.gui
        for name in ('ssh', 'usb'):
            tip = gui.t('conn_{}_tip'.format(name))
            self.assertTrue(tip and tip != 'conn_{}_tip'.format(name))
        self.assertIn('IP', gui.t('conn_ssh_tip'))
        self.assertIn('usbmuxd', gui.t('conn_usb_tip'))

    def test_the_usb_device_is_above_the_account_row_and_its_box_as_wide_as_its_text(self):
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
        box = gui.usb_box
        self.assertEqual(box.grid_info()['row'], 0)                      # the device on top, with Refresh
        row = gui.btn_connect.grid_info()['row']                         # below: account, Remember, Connect, Settings
        self.assertEqual(row, 1)
        for label in ('ssh_port', 'user', 'password', 'remember', 'settings'):
            widget = label_with(gui, gui.t(label))
            self.assertEqual(widget.grid_info()['row'], row, label)
        self.assertNotIn('e', box.grid_info().get('sticky', ''))       # it does not stretch across the window
        self.assertEqual(int(box.cget('width')), 24)                     # nothing attached: the minimum
        phone = engine.usbmux.Device(1, '00008030-0014394602E0802E')
        phone.name, phone.model, phone.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        self.usb_box_after([phone])
        self.assertEqual(int(gui.usb_box.cget('width')), min(56, len(phone.label())))     # attached: its text, up to a limit
        gui.settings_close()

    def test_the_connection_is_saved_and_kept_while_a_batch_runs(self):
        gui = self.gui
        del gui._save_config        # the real one, which writes the patched settings file
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
        with open(engine.CONFIG_PATH, encoding='utf-8') as handle:
            self.assertEqual(json.load(handle)['connection'], 'usb')
        gui.dumping = True
        with mock.patch.object(messagebox, 'showwarning') as warning:
            gui.change_connection('ssh')
        warning.assert_called_once()
        self.assertEqual(gui.var_connection.get(), 'usb')      # the radio button goes back
        gui.dumping = False
        gui.settings_close()

    def test_switching_the_connection_asks_first_and_ends_the_old_one(self):
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
            for connected, connecting in ((True, False), (False, True)):
                client = mock.Mock()
                gui.ssh, gui.ssh_connecting = (client if connected else None), connecting
                generation = gui.generation
                with mock.patch.object(messagebox, 'askyesno', return_value=False) as ask:
                    gui.change_connection('ssh')
                ask.assert_called_once()
                self.assertEqual(gui.var_connection.get(), 'usb')           # declined: nothing changed
                self.assertEqual(gui.generation, generation)
                with mock.patch.object(messagebox, 'askyesno', return_value=True):
                    gui.change_connection('ssh')
                self.assertEqual(gui.var_connection.get(), 'ssh')
                self.assertIsNone(gui.ssh)
                self.assertFalse(gui.ssh_connecting)                        # a connect still running is stale
                self.assertGreater(gui.generation, generation)              # so its answer is dropped
                if connected:
                    client.close.assert_called_once()
                gui.change_connection('usb')
        gui.settings_close()

    def test_a_device_list_error_is_logged_once_not_at_every_rebuild(self):
        gui = self.gui
        error = engine.usbmux.UsbmuxError('usb_err_none')
        gui.usb_listing = 5
        before = gui.log_text.get('1.0', 'end')
        gui._usb_listed([], error, 5)
        gui._usb_listed([], error, 5)
        added = gui.log_text.get('1.0', 'end')[len(before) - 1:]
        self.assertEqual(added.count(gui.t('usb_err_none')), 1)

    def usb_box_after(self, attached):
        """Press Refresh with these devices attached; the window's USB device box afterwards."""
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=attached), \
                mock.patch.object(engine.usbmux, 'describe', side_effect=lambda d: d):
            gui.refresh_usb()
            for _ in range(40):
                gui.update()
                time.sleep(0.02)
        return list(gui.usb_box.cget('values')), gui.var_usb_label.get()

    def test_refresh_follows_the_devices_as_they_come_and_go(self):
        gui = self.gui
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
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
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[]):
            gui.open_settings()
            gui.change_connection('usb')
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
        gui.report_callback_exception = lambda *info: seen.append(info[0])
        gui.post(lambda: 1 / 0)
        gui.post(seen.append, 'later')
        gui._drain_events()
        self.assertEqual(seen, [ZeroDivisionError, 'later'])
        gui.post(seen.append, 'after the pump went on')
        for _ in range(10):
            gui.update()
            time.sleep(0.02)
        self.assertEqual(seen[-1], 'after the pump went on')        # the pump rescheduled itself

    def test_the_ready_line_follows_the_connection_each_time_it_changes(self):
        gui = self.gui

        def lines():
            return gui.log_text.get('1.0', 'end-1c').splitlines()
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

    def test_light_without_sv_ttk_is_not_left_dark_by_an_earlier_theme(self):
        gui = self.gui
        with mock.patch.object(core, 'IS_WINDOWS', False), mock.patch.object(core, 'IS_MACOS', False), \
                mock.patch.dict('sys.modules', {'sv_ttk': None}):      # Linux without sv-ttk: light is clam
            gui.change_theme('dark')
            dark = gui.style.lookup('TFrame', 'background')
            gui.change_theme('light')
            light = gui.style.lookup('TFrame', 'background')
            self.assertEqual(dark, core.PALETTES['dark']['bg'])
            self.assertEqual(light, core.PALETTES['light']['bg'])
            self.assertEqual(gui.style.lookup('TEntry', 'fieldbackground'), core.PALETTES['light']['field'])
            self.assertEqual(gui.cget('background'), core.PALETTES['light']['bg'])
            gui.change_theme('black')
            gui.change_theme('light')
            self.assertEqual(gui.style.lookup('TFrame', 'background'), core.PALETTES['light']['bg'])

    def test_the_usb_device_box_shows_the_name_and_keeps_the_udid(self):
        gui = self.gui
        device = engine.usbmux.Device(1, '00008030-0014394602E0802E')
        device.name, device.model, device.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[device]), \
                mock.patch.object(engine.usbmux, 'describe', side_effect=lambda d: d):
            gui.open_settings()
            gui.change_connection('usb')
            for _ in range(40):
                gui.update()
                if gui.usb_devices:
                    break
                time.sleep(0.05)
        self.assertEqual(gui.usb_devices, [device])
        self.assertEqual(gui.var_usb_device.get(), '00008030-0014394602E0802E')     # kept: the UDID
        self.assertEqual(gui.var_usb_label.get(), device.label())       # the box cuts it; no dots, no padding
        self.assertEqual(list(gui.usb_box.cget('values')), [device.label()])
        gui.settings_close()

    def test_choosing_a_long_device_runs_its_text_through_the_box_once_and_rests(self):
        gui = self.gui
        device = engine.usbmux.Device(1, '00008030-0014394602E0802E')
        device.name, device.model, device.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        with mock.patch.object(engine.usbmux, 'list_devices', return_value=[device]),                 mock.patch.object(engine.usbmux, 'describe', side_effect=lambda d: d):
            gui.open_settings()
            gui.change_connection('usb')
            for _ in range(40):
                gui.update()
                if gui.usb_devices:
                    break
                time.sleep(0.05)
        label = device.label()
        shown = []
        gui.var_usb_label.trace_add('write', lambda *a: shown.append(gui.var_usb_label.get()))
        gui.var_usb_label.set(label)                    # what choosing it in the list does
        gui.usb_chosen()
        end = time.time() + 6
        while gui.usb_marquee is not None and time.time() < end:
            gui.update()
            time.sleep(0.02)
        self.assertTrue(any(text.endswith(label[-5:]) for text in shown))       # the end of the text went by
        self.assertEqual(gui.var_usb_label.get(), label)                        # then it rests on the start
        gui.settings_close()

    def test_the_settings_keep_showing_the_frida_options_with_a_native_helper(self):
        self.gui.open_settings()
        self.select_decryption_tab()
        port = label_with(self.gui, self.gui.t('frida_port'))
        self.assertIsNotNone(port)
        for method in (engine.METHOD_NATIVE, engine.METHOD_FRIDA_DIRECT):
            self.gui.var_dump_method.set(method)
            self.gui.update()
            self.assertTrue(port.master.grid_info(), method)
        self.gui.settings_close()

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
        with mock.patch.object(messagebox, 'showerror') as error:
            gui.start_dump()
        return error, gui._prepare_batch

    def test_file_mapping_on_ios_16_is_explained_and_nothing_starts(self):
        error, prepare = self.dump_with('mremap', 'iOS 16.1.2')
        error.assert_called_once()
        self.assertIn('16.1.2', error.call_args[0][1])
        prepare.assert_not_called()

    def test_an_unreadable_helper_warns_and_nothing_starts(self):
        with mock.patch.object(engine.native_decrypt, 'local_helper',
                               side_effect=engine.native_decrypt.HelperError('x cannot be read')), \
                mock.patch.object(messagebox, 'showwarning') as warning:
            error, prepare = self.dump_with('memory', 'iOS 17.0')
        warning.assert_called_once()
        self.assertIn('x cannot be read', warning.call_args[0][1])
        prepare.assert_not_called()

    def test_a_helper_that_fails_on_the_device_warns_once_per_batch(self):
        gui = self.gui
        gui.helper_warned = False
        with mock.patch.object(messagebox, 'showwarning') as warning:
            gui.helper_problem('would not start')
            gui.helper_problem('would not start')
        warning.assert_called_once()

    def test_file_mapping_on_ios_15_and_the_other_helpers_go_on(self):
        for helper, device_os in (('mremap', 'iOS 15.8'), ('auto', 'iOS 16.1.2'), ('memory', 'iOS 17.0')):
            error, prepare = self.dump_with(helper, device_os)
            error.assert_not_called()
            prepare.assert_called_once()


if __name__ == '__main__':
    unittest.main()
