"""The real window: Settings → Decryption and the refusal of file mapping. Skipped where there is no display."""
import os
import tempfile
import unittest
from tkinter import messagebox, ttk
from unittest import mock

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
