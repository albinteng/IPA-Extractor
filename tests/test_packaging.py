"""What the released program (built with Nuitka, no Python) needs: where it keeps its files, how it starts its helper
processes, and how it installs Frida without pip."""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import app_paths
import engine
import frida_versions
import workers


class PathTests(unittest.TestCase):
    def test_from_source_everything_is_in_the_tools_folder(self):
        self.assertFalse(app_paths.FROZEN)
        self.assertEqual(app_paths.DATA_DIR, app_paths.APP_DIR)
        self.assertEqual(app_paths.OUTPUT_BASE, app_paths.APP_DIR)

    def test_the_released_program_keeps_its_files_beside_itself_when_it_can(self):
        with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(app_paths, 'writable', return_value=True), \
                mock.patch.object(app_paths.sys, 'platform', 'win32'):
            self.assertEqual(app_paths.data_dir(), app_paths.APP_DIR)
            self.assertEqual(app_paths.output_base(), app_paths.APP_DIR)

    def test_a_read_only_folder_sends_the_settings_to_the_home_folder(self):
        with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(app_paths, 'writable', return_value=False), \
                mock.patch.object(app_paths.sys, 'platform', 'linux'):
            self.assertEqual(app_paths.data_dir(), app_paths.HOME_DIR)

    def test_on_macos_the_app_stays_unmodified(self):
        home = tempfile.mkdtemp(prefix='home-')
        with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(app_paths.sys, 'platform', 'darwin'), \
                mock.patch.object(app_paths.os.path, 'expanduser', side_effect=lambda p: p.replace('~', home)):
            self.assertEqual(app_paths.data_dir(), os.path.join(home, 'Library', 'Application Support', 'IPA Extractor'))
            self.assertFalse(os.path.exists(app_paths.data_dir()))         # not made until something is saved
            self.assertEqual(app_paths.output_base(), os.path.join(home, 'Documents', 'IPA Extractor'))


class WorkerTests(unittest.TestCase):
    def test_from_source_the_script_runs_with_the_versions_python(self):
        with mock.patch.object(frida_versions, 'python', return_value='/py'):
            self.assertEqual(frida_versions.worker_command('16.1.1', '/x/dump_worker.py'), ['/py', '-u', '/x/dump_worker.py'])

    def test_the_released_program_starts_itself_in_worker_mode(self):
        program = os.path.join('x', 'prog')
        with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(sys, 'argv', [program]):
            command = frida_versions.worker_command('16.1.1', os.path.join('x', 'frida_probe.py'))
        self.assertEqual(command, [os.path.abspath(program), '--worker', 'frida_probe'])

    def test_a_program_started_by_its_bare_name_is_found_on_the_path(self):
        found = os.path.join(tempfile.gettempdir(), 'bin', 'IPA-Extractor')
        with mock.patch.object(sys, 'argv', ['IPA-Extractor']), mock.patch.object(app_paths.shutil, 'which', return_value=found):
            self.assertEqual(app_paths.program_path(), os.path.abspath(found))
        with mock.patch.object(sys, 'argv', ['IPA-Extractor']), mock.patch.object(app_paths.shutil, 'which', return_value=None):
            self.assertEqual(app_paths.program_path(), os.path.join(app_paths.APP_DIR, 'IPA-Extractor'))

    def test_the_folder_of_the_settings_is_made_by_the_first_save(self):
        folder = os.path.join(tempfile.mkdtemp(prefix='data-'), 'Application Support', 'IPA Extractor')
        with mock.patch.object(engine, 'CONFIG_PATH', os.path.join(folder, 'settings.json')):
            engine.save_config({})
            self.assertFalse(os.path.exists(folder))
            engine.save_config({'theme': 'dark'})
            self.assertEqual(engine.load_config(), {'theme': 'dark'})

    def test_a_version_with_its_own_python_still_uses_it(self):
        with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(frida_versions, 'python', return_value='/own/python'):
            self.assertEqual(frida_versions.worker_command('12.0.0', 'repair_worker.py'), ['/own/python', '-u', 'repair_worker.py'])

    def test_worker_mode_runs_the_worker_with_its_arguments_and_the_frida_folder(self):
        seen = {}

        def worker():
            seen['argv'], seen['path'] = list(sys.argv), list(sys.path)
            return 3

        folder = os.path.join(tempfile.gettempdir(), 'frida-folder')
        with mock.patch.dict(workers.WORKERS, {'frida_probe': worker}), \
                mock.patch.dict(os.environ, {'PYTHONPATH': folder}), \
                mock.patch.object(sys, 'argv', list(sys.argv)), mock.patch.object(sys, 'path', list(sys.path)), \
                mock.patch.object(sys, 'stdout', mock.Mock()), mock.patch.object(sys, 'stderr', mock.Mock()):
            code = workers.run('frida_probe', ['host:27042', '--deep'])
        self.assertEqual(code, 3)
        self.assertEqual(seen['argv'], ['frida_probe.py', 'host:27042', '--deep'])
        self.assertEqual(seen['path'][0], folder)

    def test_an_unknown_worker_is_refused(self):
        with mock.patch.object(sys, 'stderr', io.StringIO()):
            self.assertEqual(workers.run('nothing', []), 2)


class WheelTests(unittest.TestCase):
    WINDOWS = 'frida-16.5.9-cp37-abi3-win_amd64.whl'
    MAC_ARM = 'frida-16.5.9-cp37-abi3-macosx_11_0_arm64.whl'
    MAC_INTEL = 'frida-16.5.9-cp37-abi3-macosx_10_13_x86_64.whl'
    LINUX = 'frida-16.5.9-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
    LINUX_ARM = 'frida-16.5.9-cp37-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl'

    def test_the_wheel_is_the_one_for_the_computer(self):
        cases = (('win32', 'AMD64', self.WINDOWS), ('darwin', 'arm64', self.MAC_ARM), ('darwin', 'x86_64', self.MAC_INTEL),
                 ('linux', 'x86_64', self.LINUX), ('linux', 'aarch64', self.LINUX_ARM))
        names = [case[2] for case in cases]
        for system, machine, wanted in cases:
            self.assertEqual([n for n in names if frida_versions.wheel_matches(n, system, machine)], [wanted], system + machine)

    def test_what_is_not_an_abi3_wheel_is_not_taken(self):
        self.assertFalse(frida_versions.wheel_matches('frida-16.5.9-cp38-cp38-win_amd64.whl', 'win32', 'AMD64'))
        self.assertFalse(frida_versions.wheel_matches('frida-16.5.9.tar.gz', 'linux', 'x86_64'))
        self.assertFalse(frida_versions.wheel_matches('frida-16.5.9-cp37-abi3-musllinux_1_1_x86_64.whl', 'linux', 'x86_64'))

    def package(self, data, digest=None):
        listing = {'urls': [{'filename': self.LINUX, 'url': 'https://example/wheel', 'digests': {
            'sha256': digest or hashlib.sha256(data).hexdigest()}}]}

        def urlopen(url, timeout=None):
            body = json.dumps(listing).encode() if 'pypi.org' in url else data
            return mock.MagicMock(__enter__=lambda s: io.BytesIO(body), __exit__=lambda *a: False)

        return urlopen

    def test_the_wheel_is_unpacked_into_the_staging_folder(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('frida/__init__.py', '__version__ = "16.5.9"')
        root = tempfile.mkdtemp(prefix='frida-root-')
        with mock.patch.object(frida_versions.urllib.request, 'urlopen', self.package(buffer.getvalue())), \
                mock.patch.object(sys, 'platform', 'linux'), mock.patch.object(frida_versions.platform, 'machine', return_value='x86_64'):
            frida_versions.prepare_install('16.5.9', root)
            frida_versions.install_wheel('16.5.9', lambda text: None, root)
            frida_versions.finish_install('16.5.9', root)
        self.assertEqual(frida_versions.installed(root), ['16.5.9'])
        self.assertTrue(os.path.isfile(os.path.join(root, '16.5.9', 'frida', '__init__.py')))

    def test_a_download_that_does_not_match_its_checksum_is_refused(self):
        root = tempfile.mkdtemp(prefix='frida-root-')
        with mock.patch.object(frida_versions.urllib.request, 'urlopen', self.package(b'data', digest='0' * 64)), \
                mock.patch.object(sys, 'platform', 'linux'), mock.patch.object(frida_versions.platform, 'machine', return_value='x86_64'):
            frida_versions.prepare_install('16.5.9', root)
            with self.assertRaises(RuntimeError):
                frida_versions.install_wheel('16.5.9', lambda text: None, root)


class ProgramNameTests(unittest.TestCase):
    def test_the_released_program_names_itself_not_the_script(self):
        import importlib
        import ipa_cli
        try:
            with mock.patch.object(app_paths, 'FROZEN', True), mock.patch.object(sys, 'argv', [os.path.join('x', 'IPA-Extractor.exe')]):
                importlib.reload(ipa_cli)
                self.assertEqual(ipa_cli.PROG, 'IPA-Extractor.exe')
                self.assertTrue(ipa_cli.build_parser().format_usage().startswith('usage: IPA-Extractor.exe '))
                self.assertEqual(ipa_cli.RUN, 'IPA-Extractor.exe')
        finally:
            importlib.reload(ipa_cli)
        self.assertEqual(ipa_cli.PROG, 'ipa_cli.py')
        self.assertEqual(ipa_cli.RUN, 'python ipa_cli.py')


class ChildProcessTests(unittest.TestCase):
    """The released Windows program is started by a double click, without a console: its standard input is not valid,
    and a child process started without naming stdin fails with "[WinError 6] The handle is invalid". Python tests
    cannot reproduce that, so this checks that every place that starts a process says what its stdin is."""

    def test_every_child_process_is_given_a_stdin(self):
        import ast
        import glob
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        starters = ('run', 'Popen', 'check_output', 'check_call', 'call')
        missing = []
        for path in sorted(glob.glob(os.path.join(root, '*.py'))):
            name = os.path.basename(path)
            if name == 'build.py':          # the developer's build script, not part of the released program
                continue
            with open(path, encoding='utf-8') as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                owner = node.func.value
                if isinstance(owner, ast.Name) and owner.id == 'subprocess' and node.func.attr in starters:
                    if not any(keyword.arg == 'stdin' for keyword in node.keywords):
                        missing.append('{}:{}'.format(name, node.lineno))
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
