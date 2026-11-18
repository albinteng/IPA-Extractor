# -*- coding: utf-8 -*-
"""Patching decrypted slices into an IPA (ipa_repair.py) and the repair worker."""

import importlib.util
import io
import json
import os
import tempfile
import unittest

import app_info
from tests.support import IpaMixin, ROOT, fat_macho, thin_macho


class RepairTests(IpaMixin, unittest.TestCase):
    def test_patches_decrypted_slices_into_ipa(self):
        import ipa_repair
        import ipa_verify
        import zipfile
        fat = fat_macho(self.ARMV7 + (thin_macho(*self.ARMV7, 1, is64=False),),
                        self.ARM64 + (thin_macho(*self.ARM64, 1),))
        path = self.ipa({'X': thin_macho(*self.ARM64, 0), 'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                         'PlugIns/F.appex/F': fat})
        with zipfile.ZipFile(path) as archive:
            before = {i.filename: (archive.read(i), i.external_attr, i.date_time) for i in archive.infolist()}
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/var/containers/Bundle/Application/U/X.app')
        self.assertEqual([j.device_path for j in jobs], ['/var/containers/Bundle/Application/U/X.app/PlugIns/E.appex/E',
                                                         '/var/containers/Bundle/Application/U/X.app/PlugIns/F.appex/F'])
        with tempfile.TemporaryDirectory() as work:
            for job in jobs:
                for index, slice_ in enumerate(job.slices):
                    if job.id == '1' and slice_.arch == 'armv7':
                        continue  # this slice failed on the device
                    with open(os.path.join(work, '{}_{}.bin'.format(job.id, index)), 'wb') as handle:
                        handle.write(b'\x1f\x20\x03\xd5' * (slice_.cryptsize // 4))  # nop
                    job.done.add(index)
            self.assertEqual(ipa_repair.apply(path, jobs, work), 2)
        result = ipa_verify.verify_ipa(path)
        self.assertEqual(result.status, ipa_verify.PARTIAL_32BIT)  # only F's armv7 slice is left
        with zipfile.ZipFile(path) as archive:
            after = {i.filename: (archive.read(i), i.external_attr, i.date_time) for i in archive.infolist()}
        self.assertEqual(list(after), list(before))
        for name in ('Payload/X.app/X', 'Payload/X.app/Info.plist', 'Payload/X.app/icon.png'):
            self.assertEqual(after[name], before[name])
        patched = after['Payload/X.app/PlugIns/E.appex/E'][0]
        self.assertEqual(len(patched), len(before['Payload/X.app/PlugIns/E.appex/E'][0]))
        self.assertEqual(patched[0x100:0x104], b'\x1f\x20\x03\xd5')

    def test_plan_knows_executables_and_extension_ids(self):
        import ipa_repair
        import ipa_verify
        import plistlib
        plist = lambda executable, identifier: plistlib.dumps(
            {'CFBundleExecutable': executable, 'CFBundleIdentifier': identifier})
        path = self.ipa({'X': thin_macho(*self.ARM64, 1),
                         'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1),
                         'PlugIns/E.appex/Info.plist': plist('E', 'com.example.app.share'),
                         'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                         'Watch/W.app/W': thin_macho(*self.ARM64, 1),
                         'Data/plugin.bin': thin_macho(*self.ARM64, 1),
                         'Info.plist': plist('X', 'com.example.app')})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/var/containers/Bundle/Application/U/X.app', path)
        found = {ipa_verify.short_name(j.member): (j.kind, j.extension) for j in jobs}
        self.assertEqual(found, {'X': ('main', None), 'PlugIns/E.appex/E': ('appex', 'com.example.app.share'),
                                 'Frameworks/F.framework/F': ('framework', None), 'Watch/W.app/W': ('watch', None),
                                 'Data/plugin.bin': ('other', None)})
        self.assertEqual(jobs[1].to_json()['suffix'], '/X.app/PlugIns/E.appex/E')

    def test_size_mismatch_is_not_repaired(self):
        import ipa_repair
        import ipa_verify
        path = self.ipa({'PlugIns/E.appex/E': thin_macho(*self.ARM64, 1)})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/app/X.app')

        class FakeSFTP:
            def stat(self, path):
                return type('Stat', (), {'st_size': 1})()

        ipa_repair.check_sizes(FakeSFTP(), jobs, path)
        self.assertEqual(jobs[0].error[0], 'mismatch')
        self.assertEqual(ipa_repair.apply(path, jobs, '.'), 0)


class RepairJobTests(IpaMixin, unittest.TestCase):
    def job(self, slices=2):
        import ipa_repair
        import ipa_verify
        return ipa_repair.Job('0', 'Payload/X.app/PlugIns/E.appex/E', '/app/X.app/PlugIns/E.appex/E',
                              [ipa_verify.Slice('arm64', True, *self.ARM64, 0, 0x4000, 0x100, 1, 0)] * slices,
                              kind='appex', extension='com.x.e', min_os='16.0')

    def test_connection_lost_and_reset(self):
        import ipa_repair
        job = self.job()
        job.done.add(0)
        self.assertFalse(job.connection_lost())
        self.assertTrue(job.untried())
        job.slice_errors[1] = 'unsupported:slice'
        self.assertFalse(job.connection_lost())
        self.assertFalse(job.untried())
        for error in ('TransportError: the connection is closed', ipa_repair.STALLED.format(90),
                      'TransportError: timeout was reached',
                      'TransportError: error receiving data: Connection reset by peer',
                      'TransportError: error receiving data: An established connection was aborted',
                      'lost the connection to frida-server'):
            job.slice_errors[1] = error
            self.assertTrue(job.connection_lost(), error)
        job.slice_errors = {}
        job.error = ('frida', 'ServerNotRunningError: unable to connect to remote frida-server')
        self.assertTrue(job.connection_lost())
        job.reset()
        self.assertEqual((job.error, job.slice_errors, job.done), (None, {}, {0}))  # decrypted slices stay
        self.assertTrue(job.untried())

    def test_to_json_tells_the_worker_what_to_launch(self):
        data = self.job(1).to_json()
        self.assertEqual((data['kind'], data['extension'], data['suffix']),
                         ('appex', 'com.x.e', '/X.app/PlugIns/E.appex/E'))
        self.assertEqual(data['slices'][0]['cryptsize'], 0x100)

    def test_framework_with_info_plist_is_a_framework(self):
        import ipa_repair
        # A framework's Info.plist names its executable as well; that must not make it 'other'.
        executables = {'': 'X', 'Frameworks/F.framework': 'F', 'PlugIns/E.appex': 'E', 'Apps/N.app': 'N'}
        self.assertEqual(ipa_repair.kind('Frameworks/F.framework/F', executables), 'framework')
        self.assertEqual(ipa_repair.kind('Frameworks/libz.dylib', executables), 'framework')
        self.assertEqual(ipa_repair.kind('PlugIns/E.appex/Frameworks/G.framework/G', executables), 'framework')
        self.assertEqual(ipa_repair.kind('X', executables), 'main')
        self.assertEqual(ipa_repair.kind('PlugIns/E.appex/E', executables), 'appex')
        self.assertEqual(ipa_repair.kind('Apps/N.app/N', executables), 'other')
        self.assertEqual(ipa_repair.kind('Watch/W.app/W', executables), 'watch')

    def test_plan_reads_minimum_os_versions(self):
        import ipa_repair
        import ipa_verify
        import plistlib
        plist = lambda executable, identifier, minimum: plistlib.dumps(
            {'CFBundleExecutable': executable, 'CFBundleIdentifier': identifier, 'MinimumOSVersion': minimum})
        path = self.ipa({'X': thin_macho(*self.ARM64, 1), 'Info.plist': plist('X', 'com.x', '15.0'),
                         'PlugIns/G.appex/G': thin_macho(*self.ARM64, 1),
                         'PlugIns/G.appex/Info.plist': plist('G', 'com.x.g', '17.0'),
                         'Frameworks/F.framework/F': thin_macho(*self.ARM64, 1),
                         'Frameworks/F.framework/Info.plist': plist('F', 'com.x.f', '12.0')})
        jobs = ipa_repair.plan(ipa_verify.verify_ipa(path), '/app/X.app', path)
        found = {ipa_verify.short_name(j.member): (j.kind, j.min_os) for j in jobs}
        self.assertEqual(found, {'X': ('main', '15.0'), 'PlugIns/G.appex/G': ('appex', '17.0'),
                                 'Frameworks/F.framework/F': ('framework', '12.0')})
        self.assertGreater(ipa_repair.version_tuple('17.0'), ipa_repair.version_tuple('iPhone OS 16.1.2'))


class RepairWorkerHelperTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('repair_worker', ROOT / 'repair_worker.py')
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)  # frida itself is only imported by Worker()

    def test_clean_error(self):
        clean = self.worker.clean
        self.assertEqual(clean('Error: mremap_encrypted failed (errno 1)\n    at decrypt (agent.js:10)'),
                         'mremap_encrypted failed (errno 1)')
        self.assertEqual(clean('TransportError: the connection is closed'), 'TransportError: the connection is closed')
        self.assertEqual(clean(''), '')

    def test_belongs_to(self):
        belongs_to = self.worker.belongs_to
        self.assertTrue(belongs_to('com.foo', 'com.foo'))
        self.assertTrue(belongs_to('com.foo.Share', 'com.foo'))
        self.assertFalse(belongs_to('com.foobar', 'com.foo'))
        self.assertFalse(belongs_to('com.apple.Preferences', 'com.foo'))
        self.assertFalse(belongs_to(None, 'com.foo'))
        self.assertFalse(belongs_to('com.foo', ''))

    def test_same_cpu_ignores_capability_bits(self):
        same_cpu = self.worker.same_cpu
        item = {'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 0}
        self.assertTrue(same_cpu({'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 0x80000000}, item))
        self.assertFalse(same_cpu({'cpu': app_info.CPU_TYPE_ARM64, 'subtype': 2}, item))  # arm64e
        self.assertFalse(same_cpu({'cpu': app_info.CPU_TYPE_ARM, 'subtype': 0}, item))

    def test_extension_hosts_learn_from_each_lookup(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)  # no frida: the lookups are faked
        worker.hosts, worker.app_running = {}, True
        worker.host_order = list(self.worker.EXTENSION_HOSTS)
        self.assertEqual(worker.host_order[-1], 'app')  # asked last: a running app tends to hang
        asked = []

        def catch(host, job):
            asked.append(host)
            if host == 'AuthenticationServicesAgent':
                raise RuntimeError('TransportError: timeout was reached')
            return 42 if host == 'spawn:com.apple.Preferences' else None

        worker.catch_extension = catch
        worker.device = mock.Mock()
        worker.read_image = mock.Mock()
        with mock.patch.object(self.worker, 'load_agent'), mock.patch.object(self.worker, 'emit'):
            worker.extension({'id': '0', 'slices': [{}], 'extension': 'com.x.a'})
            self.assertEqual(asked, ['SpringBoard', 'AuthenticationServicesAgent', 'spawn:com.apple.Preferences'])
            asked.clear()
            worker.extension({'id': '1', 'slices': [{}], 'extension': 'com.x.b'})
        self.assertEqual(asked, ['spawn:com.apple.Preferences'])  # the host that worked first, the hung one dropped
        self.assertEqual(worker.host_order, ['spawn:com.apple.Preferences', 'SpringBoard', 'app'])

    def test_an_extension_that_died_before_attach_is_started_again(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)
        worker.hosts, worker.app_running = {}, False
        worker.host_order = ['spawn:com.apple.Preferences']
        started = []
        worker.catch_extension = lambda host, job: started.append(host) or 40 + len(started)
        attached = []

        def attach(pid):
            attached.append(pid)
            if len(attached) < 3:    # the process was gone: "invalid destination port"
                raise RuntimeError('unexpected error while attaching (invalid destination port)')
            return mock.Mock()

        worker.device = mock.Mock(attach=attach)
        worker.read_image = mock.Mock()
        job = {'id': '0', 'slices': [{}], 'extension': 'com.x.a'}
        with mock.patch.object(self.worker, 'load_agent'), mock.patch.object(self.worker, 'emit'),                 mock.patch.object(self.worker.time, 'sleep'):
            worker.extension(job)
        self.assertEqual(attached, [41, 42, 43])            # each try starts the extension anew
        worker.read_image.assert_called_once()
        # Out of tries: the file fails with what the device said, and the next start is not made.
        started.clear()
        attached.clear()
        worker.fail_all = mock.Mock()
        worker.device = mock.Mock(attach=mock.Mock(side_effect=RuntimeError('invalid destination port')))
        worker.read_image = mock.Mock()
        worker.host_order = ['spawn:com.apple.Preferences']
        with mock.patch.object(self.worker, 'load_agent'), mock.patch.object(self.worker, 'emit'),                 mock.patch.object(self.worker.time, 'sleep'):
            worker.extension(job)
        self.assertEqual(len(started), self.worker.EXTENSION_STARTS)
        self.assertIn('invalid destination port', worker.fail_all.call_args[0][1])

    def test_frameworks_let_the_app_start_once_then_load_each(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)
        worker.app_running, worker.app_pid = False, 7
        worker.device = mock.Mock()
        api = mock.Mock()
        api.hook_app_main.return_value = True
        api.load_image.side_effect = [RuntimeError('dyld busy'), '0x1000', '0x2000']  # first try too early
        worker.app = lambda: api
        worker.read_image = mock.Mock()
        jobs = [{'id': str(i), 'path': '/a/X.app/Frameworks/F%d.framework/F%d' % (i, i), 'slices': [{}]} for i in range(2)]
        events = []
        with mock.patch.object(self.worker, 'emit', side_effect=lambda kind, **data: events.append(kind)), \
                mock.patch.object(self.worker.time, 'sleep'):
            worker.frameworks(jobs)
        api.hook_app_main.assert_called_once()
        worker.device.resume.assert_called_once_with(7)  # before any framework is loaded
        self.assertIn('running_app', events)               # the GUI logs that the app's code runs
        self.assertEqual(api.load_image.call_count, 3)
        self.assertEqual(worker.read_image.call_count, 2)

    def test_frameworks_never_resume_an_app_whose_ui_cannot_be_stopped(self):
        from unittest import mock
        worker = self.worker.Worker.__new__(self.worker.Worker)
        worker.app_running, worker.app_pid = False, 7
        worker.device = mock.Mock()
        api = mock.Mock()
        api.hook_app_main.return_value = False
        worker.app = lambda: api
        failed = []
        worker.fail_all = lambda job, error: failed.append((job['id'], error))
        with mock.patch.object(self.worker, 'emit'):
            worker.frameworks([{'id': '0', 'path': '/a/F', 'slices': [{}]}])
        worker.device.resume.assert_not_called()
        self.assertEqual(failed, [('0', 'RuntimeError: UIApplicationMain not found in the app')])

    def test_alive_is_throttled(self):
        from unittest import mock
        out = io.StringIO()
        with mock.patch.object(self.worker.sys, 'stdout', out), \
                mock.patch.object(self.worker.time, 'monotonic', side_effect=[100.0, 100.0, 105.0, 111.0, 111.0]):
            self.worker._last_emit[0] = 0.0
            self.worker.alive()   # 100: long silence -> emits (and records 100)
            self.worker.alive()   # 105: too soon
            self.worker.alive()   # 111: due again
        events = [json.loads(line[2:])['type'] for line in out.getvalue().splitlines()]
        self.assertEqual(events, ['alive', 'alive'])


if __name__ == '__main__':
    unittest.main()
