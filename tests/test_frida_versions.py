# -*- coding: utf-8 -*-
"""Installing and choosing the frida versions (frida_versions.py)."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import engine
import frida_versions
from tests.support import ROOT, needs_window


class FridaVersionTests(unittest.TestCase):
    def test_pick_prefers_exact_then_newest_of_same_major(self):
        import frida_versions
        versions = ['17.24.3', '17.5.1', '16.6.6', '16.1.0']
        self.assertEqual(frida_versions.pick('17.24.3', versions), '17.24.3')
        self.assertEqual(frida_versions.pick('17.30.0', versions), '17.24.3')
        self.assertEqual(frida_versions.pick('16.7.0', versions), '16.6.6')
        self.assertIsNone(frida_versions.pick('15.2.2', versions))
        self.assertIsNone(frida_versions.pick(None, versions))

    def test_only_complete_installs_are_listed(self):
        import frida_versions
        with tempfile.TemporaryDirectory() as root:
            for name in ('16.6.6', '17.24.3', '17.5.1', '17.9.9.partial', 'notes'):
                os.makedirs(os.path.join(root, name))
            for name in ('16.6.6', '17.24.3', '17.5.1'):
                open(os.path.join(root, name, frida_versions.COMPLETE), 'w').close()
            os.makedirs(os.path.join(root, '18.0.0'))  # pip never finished
            self.assertEqual(frida_versions.installed(root), ['17.24.3', '17.5.1', '16.6.6'])
            frida_versions.remove('17.5.1', root)
            self.assertEqual(frida_versions.installed(root), ['17.24.3', '16.6.6'])

    def test_finish_install_replaces_previous_copy(self):
        import frida_versions
        with tempfile.TemporaryDirectory() as root:
            frida_versions.prepare_install('17.24.3', root)
            open(os.path.join(frida_versions.staging('17.24.3', root), 'new'), 'w').close()
            os.makedirs(os.path.join(root, '17.24.3'))
            open(os.path.join(root, '17.24.3', 'old'), 'w').close()
            frida_versions.finish_install('17.24.3', root)
            self.assertEqual(sorted(os.listdir(os.path.join(root, '17.24.3'))), [frida_versions.COMPLETE, 'new'])
            self.assertFalse(os.path.exists(frida_versions.staging('17.24.3', root)))

    def test_an_install_that_cannot_replace_the_old_copy_leaves_it_whole(self):
        import frida_versions
        with tempfile.TemporaryDirectory() as root:
            frida_versions.prepare_install('17.24.3', root)
            os.makedirs(os.path.join(root, '17.24.3'))
            open(os.path.join(root, '17.24.3', frida_versions.COMPLETE), 'w').close()
            real = os.replace

            def replace(source, target):
                if source == frida_versions.staging('17.24.3', root):
                    raise PermissionError('in use')            # the new copy cannot be moved into place
                return real(source, target)

            with mock.patch.object(frida_versions.os, 'replace', replace), self.assertRaises(PermissionError):
                frida_versions.finish_install('17.24.3', root)
            self.assertEqual(frida_versions.installed(root), ['17.24.3'])      # the old one still works

    def test_env_puts_version_folder_first(self):
        import frida_versions
        env = frida_versions.env('17.24.3', {'PYTHONPATH': 'elsewhere'}, root='versions')
        self.assertEqual(env['PYTHONPATH'].split(os.pathsep),
                         [os.path.join('versions', '17.24.3'), 'elsewhere'])
        self.assertEqual(frida_versions.env('16.6.6', {}, root='v')['PYTHONPATH'], os.path.join('v', '16.6.6'))

    @needs_window
    def test_gui_does_not_import_frida(self):
        code = 'import sys, gui.main_window; print("frida" in sys.modules)'
        output = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                                text=True, check=True).stdout
        self.assertEqual(output.strip(), 'False')


class PlaceholderVersionTests(unittest.TestCase):
    """The install window works out the command for '?' while no version is chosen yet (no device, no list loaded)."""

    def test_a_version_not_chosen_yet_has_an_install_command(self):
        self.assertFalse(frida_versions.is_legacy('?'))
        self.assertTrue(frida_versions.install_command('?'))
        self.assertTrue(engine.DumpEngine._install_commands('?', None))
        self.assertTrue(frida_versions.is_legacy('12.10.2'))
        self.assertFalse(frida_versions.is_legacy('16.6.6'))


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
        with mock.patch.object(frida_versions.net, 'urlopen', self.package(buffer.getvalue())), \
                mock.patch.object(sys, 'platform', 'linux'), mock.patch.object(frida_versions.platform, 'machine', return_value='x86_64'):
            frida_versions.prepare_install('16.5.9', root)
            frida_versions.install_wheel('16.5.9', lambda text: None, root)
            frida_versions.finish_install('16.5.9', root)
        self.assertEqual(frida_versions.installed(root), ['16.5.9'])
        self.assertTrue(os.path.isfile(os.path.join(root, '16.5.9', 'frida', '__init__.py')))

    def test_a_download_that_does_not_match_its_checksum_is_refused(self):
        root = tempfile.mkdtemp(prefix='frida-root-')
        with mock.patch.object(frida_versions.net, 'urlopen', self.package(b'data', digest='0' * 64)), \
                mock.patch.object(sys, 'platform', 'linux'), mock.patch.object(frida_versions.platform, 'machine', return_value='x86_64'):
            frida_versions.prepare_install('16.5.9', root)
            with self.assertRaises(RuntimeError):
                frida_versions.install_wheel('16.5.9', lambda text: None, root)


class LegacyInstallTests(unittest.TestCase):
    def test_an_egg_that_does_not_match_its_checksum_is_refused(self):
        egg = frida_versions.egg_name('12.11.18')
        listing = {'urls': [{'filename': egg, 'url': 'https://example/egg', 'digests': {'sha256': '0' * 64}}]}

        def urlopen(url, timeout=None):
            body = json.dumps(listing).encode() if 'pypi.org' in url else b'not what was published'
            return mock.MagicMock(__enter__=lambda s: io.BytesIO(body), __exit__=lambda *a: False)

        root = tempfile.mkdtemp(prefix='frida-root-')
        with mock.patch.object(frida_versions.net, 'urlopen', urlopen), \
                mock.patch.object(frida_versions, 'legacy_supported', return_value=True):
            frida_versions.prepare_install('12.11.18', root)
            with self.assertRaises(RuntimeError):
                frida_versions.install_legacy('12.11.18', lambda text: None, root)

    def test_a_python_that_does_not_match_its_checksum_is_refused(self):
        import hashlib
        egg_data = io.BytesIO()
        with zipfile.ZipFile(egg_data, 'w') as archive:
            archive.writestr('frida/__init__.py', '')
        egg = frida_versions.egg_name('12.11.18')
        listing = {'urls': [{'filename': egg, 'url': 'https://example/egg',
                             'digests': {'sha256': hashlib.sha256(egg_data.getvalue()).hexdigest()}}]}

        def urlopen(url, timeout=None):
            body = json.dumps(listing).encode() if 'pypi.org' in url else                 egg_data.getvalue() if 'example' in url else b'a Python that was tampered with'
            return mock.MagicMock(__enter__=lambda s: io.BytesIO(body), __exit__=lambda *a: False)

        root = tempfile.mkdtemp(prefix='frida-root-')
        with mock.patch.object(frida_versions.net, 'urlopen', urlopen),                 mock.patch.object(frida_versions, 'legacy_supported', return_value=True):
            frida_versions.prepare_install('12.11.18', root)
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                frida_versions.install_legacy('12.11.18', lambda text: None, root)

    def test_the_ssh_password_is_not_handed_to_pip_npm_or_git(self):
        environment = frida_versions.env('16.6.6', {'IPA_PASSWORD': 'secret', 'PATH': 'x'})
        self.assertNotIn('IPA_PASSWORD', environment)
        self.assertEqual(environment['PATH'], 'x')


class SimulatorTests(unittest.TestCase):
    def test_old_coresimulator_keeps_frida_below_17_4(self):
        import frida_versions
        with mock.patch.object(frida_versions, 'simulator_aborts', return_value=True):
            self.assertEqual(frida_versions.client_version('17.24.3'), '17.3.2')
            self.assertEqual(frida_versions.client_version('16.6.6'), '16.6.6')
            self.assertFalse(frida_versions.usable('17.4.0'))
            self.assertTrue(frida_versions.usable('17.3.2'))
            self.assertEqual(frida_versions.pick('17.24.3', ['17.24.3', '17.3.2']), '17.3.2')
            self.assertIsNone(frida_versions.pick('17.24.3', ['17.24.3']))

    def test_other_computers_use_the_version_of_the_device(self):
        import frida_versions
        with mock.patch.object(frida_versions, 'simulator_aborts', return_value=False):
            self.assertEqual(frida_versions.client_version('17.24.3'), '17.24.3')
            self.assertEqual(frida_versions.pick('17.24.3', ['17.24.3', '17.3.2']), '17.24.3')

    def test_only_macos_is_checked(self):
        import frida_versions
        with mock.patch.object(frida_versions.sys, 'platform', 'win32'):
            self.assertFalse(frida_versions.simulator_aborts())

    def test_the_log_explains_the_substituted_version(self):
        import engine
        import frida_versions
        with mock.patch.object(frida_versions, 'simulator_aborts', return_value=True):
            self.assertEqual(engine.version_note('17.3.2', '17.24.3').key, 'log_frida_substituted')
            self.assertEqual(engine.version_note('16.1.0', '16.6.6').key, 'log_minor')


if __name__ == '__main__':
    unittest.main()
