# -*- coding: utf-8 -*-
"""The decryption engine shared by the window and the command line (engine.py)."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.support import ROOT, needs_window


class DumpDirTests(unittest.TestCase):
    def test_status(self):
        import engine
        with tempfile.TemporaryDirectory() as path:
            self.assertEqual(engine.dump_dir_status(''), 'empty')
            self.assertEqual(engine.dump_dir_status(os.path.join(path, 'missing')), 'missing')
            for name in ('dump.py', 'dump.js'):
                open(os.path.join(path, name), 'w').close()
            self.assertEqual(engine.dump_dir_status(path), 'no_bridge')
            os.makedirs(os.path.join(path, 'node_modules', 'frida-objc-bridge'))
            self.assertEqual(engine.dump_dir_status(path), 'ok')


class DecryptMethodTests(unittest.TestCase):
    def test_method_follows_ios_version(self):
        import engine
        self.assertEqual(engine.decrypt_method('iPhone OS 12.4'), 'mremap')
        self.assertEqual(engine.decrypt_method('iPhone OS 15.8.3'), 'mremap')
        self.assertEqual(engine.decrypt_method('iPhone OS 16.1.2'), 'memory')
        self.assertEqual(engine.decrypt_method('iPhone OS 17.0'), 'memory')
        self.assertEqual(engine.decrypt_method(None), 'mremap')

    def test_versions(self):
        import ipa_repair
        self.assertEqual(ipa_repair.version_tuple('iPhone OS 16.1.2'), (16, 1, 2))
        self.assertGreater(ipa_repair.version_tuple('17.0'), ipa_repair.version_tuple('iPhone OS 16.1.2'))
        self.assertLess(ipa_repair.version_tuple('16.1'), ipa_repair.version_tuple('16.1.2'))
        self.assertEqual(ipa_repair.version_tuple(''), ())

    def test_per_slice_copies_only_on_old_ios(self):
        import engine
        copies = lambda ios, method='mremap': engine.per_slice_copies(dict(ios=ios, method=method))
        self.assertTrue(copies('iOS 8.1.1'))
        self.assertFalse(copies('iPhone OS 12.4'))
        self.assertFalse(copies(''))
        self.assertFalse(copies('iOS 8.1.1', 'memory'))

    def test_repair_failures(self):
        import engine
        self.assertEqual(engine.repair_failure('unsupported:watch'), ('repair_unsupported_watch', ''))
        self.assertEqual(engine.repair_failure('mremap_encrypted failed: Cannot allocate memory (errno 12)')[0],
                         'repair_nomem')
        self.assertEqual(engine.repair_failure('TransportError: timeout')[0], 'repair_failed')


class DumpMethodTests(unittest.TestCase):
    def test_setting_falls_back_to_direct(self):
        import engine
        self.assertEqual(engine.DEFAULTS['dump_method'], engine.METHOD_NATIVE)
        for value in engine.DUMP_METHODS:
            self.assertEqual(engine.dump_method_setting(value), value)
        for value in ('direct', 'dump', '', None):  # values of development builds, or none at all
            self.assertEqual(engine.dump_method_setting(value), engine.METHOD_NATIVE)
        # Method names say what they need: Frida for the frida_ ones, the helper programs for the native one.
        self.assertEqual(sorted(engine.DUMP_METHODS), ['frida_direct', 'frida_ios_dump', 'native'])

    def test_frida_method_to_return_to(self):
        import engine
        # the saved one, else the active method when it is a Frida one, else the direct mode
        self.assertEqual(engine.frida_method_setting(engine.METHOD_FRIDA_IOS_DUMP, engine.METHOD_NATIVE), engine.METHOD_FRIDA_IOS_DUMP)
        self.assertEqual(engine.frida_method_setting('', engine.METHOD_FRIDA_IOS_DUMP), engine.METHOD_FRIDA_IOS_DUMP)
        self.assertEqual(engine.frida_method_setting(None, engine.METHOD_NATIVE), engine.METHOD_FRIDA_DIRECT)
        self.assertEqual(engine.frida_method_setting(engine.METHOD_NATIVE, engine.METHOD_NATIVE), engine.METHOD_FRIDA_DIRECT)

    @needs_window
    def test_native_method_needs_no_frida_and_no_frida_ios_dump(self):
        import engine
        from gui.main_window import MainWindow
        from unittest import mock
        for method, direct, native, frida in ((engine.METHOD_FRIDA_DIRECT, True, False, True),
                                              (engine.METHOD_FRIDA_IOS_DUMP, False, False, True),
                                              (engine.METHOD_NATIVE, True, True, False)):
            gui = mock.Mock()
            gui.var_dump_method.get.return_value = method
            self.assertEqual(MainWindow.direct_method(gui), direct, method)
            self.assertEqual(MainWindow.native_method(gui), native, method)
            gui.native_method = lambda g=gui: MainWindow.native_method(g)
            self.assertEqual(MainWindow.needs_frida(gui), frida, method)


class GatedLaunchTests(unittest.TestCase):
    def test_frida_launchd_pids(self):
        import engine
        listing = ('PID\tStatus\tLabel\n19362\t-9\tre.frida.server\n-\t0\tre.frida.helper\n'
                   '88\t0\tcom.apple.backboardd\n')
        self.assertEqual(engine.frida_launchd_pids(listing), [19362])

    def test_gated_launches(self):
        import engine
        ps = ('  20058 T    xpcproxy com.apple.siriinferenced\n'
              '  20071 T    xpcproxy com.adguard.AdguardExtension.SafariWebExtension\n'
              '  20072 Ss   xpcproxy com.adguard.AdguardExtension.Tunnel\n'
              '  20080 T    /private/var/containers/Bundle/Application/X/Adguard.app/Adguard\n')
        self.assertEqual(engine.gated_launches(ps, 'com.adguard.AdguardExtension'), ([20071], [20058]))
        self.assertEqual(engine.gated_launches(ps), ([], [20058, 20071]))

    def test_gated_launches_match_the_app_only(self):
        import engine
        ps = ('  1 T    xpcproxy UIKitApplication:com.foo[8a3c][rb-legacy]\n'  # the app itself
              '  2 T    xpcproxy com.foo.Share(6F2B)\n'
              '  3 T    xpcproxy com.foobar.Widget\n'                         # another app
              '  4 T    xpcproxy UIKitApplication:com.foobar[11aa]\n')
        self.assertEqual(engine.gated_launches(ps, 'com.foo'), ([1, 2], [3, 4]))

    def test_release_gated_resumes_frida_server_and_services(self):
        import engine
        from unittest import mock
        outputs = {'launchctl list': (0, '-\t0\tcom.apple.x\n812\t-9\tre.frida.server\n'),
                   'ps -A -o pid=,stat=,args=': (0, ' 5 T xpcproxy com.foo.Ext\n 6 T xpcproxy com.apple.healthd\n')}
        gui = mock.Mock()
        gui._as_root.side_effect = lambda options, command: outputs.get(command, (0, ''))
        gui._resume_frida_server = lambda options: engine.DumpEngine._resume_frida_server(gui, options)
        engine.DumpEngine._release_gated(gui, {}, 'com.foo')
        commands = [call.args[1] for call in gui._as_root.call_args_list]
        self.assertEqual([c for c in commands if c.startswith('kill')], ['kill -CONT 812', 'kill -9 5', 'kill -CONT 6'])

    def test_release_gated_survives_ssh_errors(self):
        import engine
        from unittest import mock
        gui = mock.Mock()
        gui._as_root.side_effect = OSError('channel closed')
        engine.DumpEngine._resume_frida_server(gui, {})
        engine.DumpEngine._release_gated(gui, {}, 'com.foo')  # neither raises


class RunningPidTests(unittest.TestCase):
    def test_extensions_are_not_the_app(self):
        import device_apps
        from unittest import mock
        app = '/private/var/containers/Bundle/Application/U/Adguard.app'
        tunnel = '10496 /private/var/containers/Bundle/Application/U/Adguard.app/PlugIns/Tunnel.appex/Tunnel\n'
        with mock.patch.object(device_apps.remote, 'run', return_value=(0, tunnel)):
            self.assertEqual(device_apps.running_pid(None, app), 0)  # only the VPN extension runs
        with mock.patch.object(device_apps.remote, 'run',
                               return_value=(0, tunnel + '10500 /var/containers/Bundle/Application/U/Adguard.app/Adguard\n')):
            self.assertEqual(device_apps.running_pid(None, app), 10500)


class SuspendedPidsTests(unittest.TestCase):
    def test_finds_stopped_processes_of_the_bundle(self):
        import device_apps
        from unittest import mock
        ps = ('  10 T    /private/var/containers/Bundle/Application/U/X.app/X\n'
              '  11 T    /var/containers/Bundle/Application/U/X.app/PlugIns/E.appex/E\n'
              '  12 Ss   /private/var/containers/Bundle/Application/U/X.app/PlugIns/F.appex/F\n'
              '  13 T    /private/var/containers/Bundle/Application/U/X.appx/Y\n'
              '  14 T    xpcproxy\n')
        with mock.patch.object(device_apps.remote, 'run', return_value=(0, ps)):
            self.assertEqual(device_apps.suspended_pids(None, '/private/var/containers/Bundle/Application/U/X.app/'),
                             [10, 11])


class ErrorClassificationTests(unittest.TestCase):
    def test_known_errors(self):
        import engine
        cases = {
            'frida.NotSupportedError: unable to launch iOS app via FBS: '
            'The operation couldn’t be completed. Application failed preflight checks': 'preflight',
            'frida.TransportError: timeout was reached': 'timeout',
            'frida.TransportError: the connection is closed': 'closed',
            'frida.InvalidOperationError: session is gone': 'session',
            'frida.NotSupportedError: unexpected error while resuming process: (os/kern) failure': 'resume',
            'frida.ServerNotRunningError: unable to connect to remote frida-server': 'server',
            "FileNotFoundError: [Errno 2] No such file or directory: 'Payload'": 'path',
            'something else': None,
        }
        for message, kind in cases.items():
            self.assertEqual(engine.classify_error(message), kind, message)


class DumpWorkerTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'Windows only')
    @unittest.skipUnless(importlib.util.find_spec('scp'), 'scp is installed by Install Frida dependencies')
    def test_long_paths_keep_scp_directory_target(self):
        code = ('import dump_worker, tempfile, scp\n'
                'dump_worker.use_long_paths()\n'
                'seen = []\n'
                'scp.SCPClient.__bases__[0].get = lambda self, r, l="", *a, **k: seen.append(l)\n'
                'client = scp.SCPClient.__new__(scp.SCPClient)\n'
                'client.get("x", tempfile.gettempdir() + "\\\\Payload/")\n'
                'print(tempfile.gettempdir().startswith(dump_worker.EXTENDED_PREFIX), seen[0].endswith("Payload"))\n')
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        self.assertEqual(output.split(), ['True', 'True'])

    def test_a_password_that_starts_with_a_dash_is_not_taken_for_an_option(self):
        code = ('import dump_worker, runpy, sys\n'
                'dump_worker.use_long_paths = lambda: None      # that needs scp, which this test is not about\n'
                'runpy.run_path = lambda path, run_name: print(sys.argv[1:])\n'
                'dump_worker.main()\n')
        environment = dict(os.environ, FRIDA_DUMP_SSH_PASSWORD='-secret')
        output = subprocess.run([sys.executable, '-c', code, '-H', 'host'], cwd=ROOT, env=environment,
                                capture_output=True, text=True, check=True).stdout
        self.assertEqual(output.strip(), "['-H', 'host', '-P-secret']")      # joined to its option

    def test_an_empty_password_is_still_a_value_of_its_option(self):
        code = ('import dump_worker, runpy, sys\n'
                'dump_worker.use_long_paths = lambda: None      # that needs scp, which this test is not about\n'
                'runpy.run_path = lambda path, run_name: print(sys.argv[1:])\n'
                'dump_worker.main()\n')
        environment = dict(os.environ, FRIDA_DUMP_SSH_PASSWORD='')
        output = subprocess.run([sys.executable, '-c', code, '-H', 'host'], cwd=ROOT, env=environment,
                                capture_output=True, text=True, check=True).stdout
        self.assertEqual(output.strip(), "['-H', 'host', '-P', '']")

    def test_reports_progress_as_json_lines(self):
        code = ('import dump_worker, sys, types\n'
                'bar = dump_worker.ProgressBar(total=10)\n'
                'bar.set_description_str("App resources")\n'
                'bar.update(10)\n'
                'bar.close()\n'
                'dump_worker.ProgressBar.write("hello")\n')
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        events = [json.loads(line[2:]) for line in output.splitlines() if line.startswith('@@')]
        self.assertEqual(events[-2]['n'], 10)
        self.assertTrue(events[-2]['closed'])
        self.assertEqual(events[-1], {'type': 'log', 'text': 'hello'})


if __name__ == '__main__':
    unittest.main()


class AboutTests(unittest.TestCase):
    def test_the_details_name_the_version_the_project_and_the_settings_file(self):
        import engine
        details = dict(engine.about_details())
        self.assertEqual(details['about_version'], engine.__version__)
        self.assertEqual(details['about_project'], engine.PROJECT_URL)
        self.assertEqual(details['about_settings'], engine.CONFIG_PATH)
        self.assertIn('Python ' + engine.platform.python_version(), details['about_system'])

    def test_the_third_party_software_is_listed_with_its_license(self):
        import engine
        details = dict(engine.about_details())
        for name in ('PySide6 / Qt (LGPL-3.0)', 'Paramiko (LGPL-2.1)', 'scp (LGPL-2.1+)'):
            self.assertIn(name, details['about_libraries'])
        self.assertIn('frida-ios-dump (MIT)', details['about_libraries'])      # also the ones that are downloaded when used
        self.assertIn('Frida (wxWindows Library Licence 3.1)', details['about_libraries'])
        self.assertNotIn('about_downloaded', details)                          # one list, not two

    def test_the_helpers_build_date_comes_from_build_info(self):
        import engine
        with tempfile.TemporaryDirectory() as folder:
            os.makedirs(os.path.join(folder, 'helpers', 'bin'))
            path = os.path.join(folder, 'helpers', 'bin', 'BUILD_INFO.txt')
            with mock.patch.object(engine.app_paths, 'APP_DIR', folder):
                self.assertEqual(engine.helpers_built(), '')            # no file
                with open(path, 'w') as handle:
                    handle.write('built: 2026-11-19T08:20:28Z from abc\n')
                self.assertEqual(engine.helpers_built(), '2026-11-19')
                with open(path, 'w') as handle:
                    handle.write('something else\n')
                self.assertEqual(engine.helpers_built(), '')
                self.assertNotIn('about_helpers', dict(engine.about_details()))


class WorkingFilesTests(unittest.TestCase):
    def test_only_a_stale_working_file_is_cleared(self):
        import time
        import engine
        with tempfile.TemporaryDirectory() as folder:
            old = os.path.join(folder, engine.WORKING_PREFIX + 'old.ipa')
            fresh = os.path.join(folder, engine.WORKING_PREFIX + 'fresh.ipa')
            for path in (old, fresh):
                open(path, 'wb').close()
            past = time.time() - engine.STALE_WORKING_SECONDS - 60
            os.utime(old, (past, past))
            engine.DumpEngine._clear_working(folder)             # a second program may be working on the fresh one
            self.assertFalse(os.path.exists(old))
            self.assertTrue(os.path.exists(fresh))
