import hashlib
import os
import tempfile
import unittest
from unittest import mock

import ipa_repair
import ipa_verify
import native_decrypt


def slice_(cpu=0x0100000C, subtype=0, offset=0, cryptoff=0x4000, cryptsize=0x1000, cryptid=1):
    return ipa_verify.Slice('arm64', True, cpu, subtype, offset, cryptoff, cryptsize, cryptid, 0)


def job(slices, device_path='/var/containers/Bundle/Application/X/App.app/App', **kwargs):
    return ipa_repair.Job('0', 'Payload/App.app/App', device_path, slices, **kwargs)


class ChoiceTests(unittest.TestCase):
    def test_auto_follows_the_ios_version(self):
        self.assertEqual(native_decrypt.choose('auto', 12), native_decrypt.MREMAP)
        self.assertEqual(native_decrypt.choose('auto', 15), native_decrypt.MREMAP)
        self.assertEqual(native_decrypt.choose('auto', 16), native_decrypt.MEMORY)
        self.assertEqual(native_decrypt.choose('auto', 18), native_decrypt.MEMORY)
        self.assertEqual(native_decrypt.choose('auto', None), native_decrypt.MREMAP)

    def test_a_forced_helper_is_used_whatever_the_version(self):
        self.assertEqual(native_decrypt.choose('memory', 12), native_decrypt.MEMORY)
        self.assertEqual(native_decrypt.choose('mremap', 17), native_decrypt.MREMAP)

    def test_file_mapping_is_refused_from_ios_16(self):
        self.assertTrue(native_decrypt.refused('mremap', 16))
        self.assertTrue(native_decrypt.refused('mremap', 18))
        self.assertFalse(native_decrypt.refused('mremap', 15))
        self.assertFalse(native_decrypt.refused('mremap', None))
        self.assertFalse(native_decrypt.refused('auto', 17))
        self.assertFalse(native_decrypt.refused('memory', 17))

    def test_unknown_settings_mean_auto(self):
        for value in ('', None, 'frida', 'MEMORY'):
            self.assertEqual(native_decrypt.setting(value), native_decrypt.AUTO)

    def test_version_text(self):
        self.assertEqual(native_decrypt.version_text('iOS 16.1.2'), '16.1.2')
        self.assertEqual(native_decrypt.version_text('iPhone OS 12.4'), '12.4')
        self.assertEqual(native_decrypt.version_text(None), '')

    def test_ios_major(self):
        self.assertEqual(native_decrypt.ios_major('iOS 16.1.2'), 16)
        self.assertEqual(native_decrypt.ios_major('iPhone OS 12.4'), 12)
        self.assertIsNone(native_decrypt.ios_major(''))


class LocalHelperTests(unittest.TestCase):
    def folder(self, content=b'binary'):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with open(os.path.join(tmp.name, 'mremap_decrypt'), 'wb') as handle:
            handle.write(content)
        return tmp.name

    def test_any_readable_binary_is_used_and_named_by_its_checksum(self):
        for content in (b'binary', b'built by somebody else'):
            path, digest = native_decrypt.local_helper(native_decrypt.MREMAP, self.folder(content))
            self.assertTrue(path.endswith('mremap_decrypt'))
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_a_missing_or_empty_helper_is_reported(self):
        with self.assertRaisesRegex(native_decrypt.HelperError, 'cannot be read'):
            native_decrypt.local_helper(native_decrypt.MEMORY, self.folder())
        with self.assertRaisesRegex(native_decrypt.HelperError, 'cannot be read'):
            native_decrypt.local_helper(native_decrypt.MEMORY, tempfile.gettempdir() + os.sep + 'no-such-folder')
        with self.assertRaisesRegex(native_decrypt.HelperError, 'is empty'):
            native_decrypt.local_helper(native_decrypt.MREMAP, self.folder(content=b''))

    def test_the_shipped_binaries_can_be_read(self):
        for method in (native_decrypt.MREMAP, native_decrypt.MEMORY):
            native_decrypt.local_helper(method)


class OutputTests(unittest.TestCase):
    def test_parse_output(self):
        text = ('OK\tApp\t16777228\t0\t16384\t4096\n'
                'SKIP\tFrameworks/A.framework/A\tcryptid 0\n'
                'FAIL\tPlugIns/E.appex/E\tcould not start the extension\n'
                'OK\tFrameworks/B.framework/B\t16777228\t2\t16384\t8192\n'
                'garbage\n')
        done, failed = native_decrypt.parse_output(text)
        self.assertEqual(done, {'App': [(16777228, 0, 16384, 4096)], 'Frameworks/B.framework/B': [(16777228, 2, 16384, 8192)]})
        self.assertEqual(failed, {'PlugIns/E.appex/E': 'could not start the extension'})

    def test_same_cpu_ignores_capability_bits(self):
        self.assertTrue(native_decrypt.same_cpu(0x0100000C, 0, slice_()))
        self.assertTrue(native_decrypt.same_cpu(0x0100000C, 0x80000000 | 0, slice_(subtype=0)))
        self.assertFalse(native_decrypt.same_cpu(12, 9, slice_(cpu=12, subtype=11)))

    def test_cpu_arguments_are_unsigned(self):
        self.assertEqual(native_decrypt.cpu_arguments(slice_(cpu=-16777212, subtype=-2147483648)),
                         (0xFF000004, 0x80000000))


class FakeDevice:
    """Stands in for native_decrypt.Device; run() answers the helper commands."""

    def __init__(self, responder):
        self.responder = responder
        self.commands = []
        self.helpers = {}

    def upload(self, method):
        return '/var/tmp/helpers/' + native_decrypt.BINARIES[method]

    def run(self, command, timeout=60):
        self.commands.append(command)
        return self.responder(command)


class MremapTests(unittest.TestCase):
    def run_jobs(self, jobs, responder):
        device = FakeDevice(responder)
        reports = []
        with tempfile.TemporaryDirectory() as work:
            native_decrypt.run_mremap(device, jobs, work, lambda j, i, e: reports.append((j.id, i, e)))
            written = {}
            for name in os.listdir(work):
                with open(os.path.join(work, name), 'rb') as handle:
                    written[name] = handle.read()
        return device, reports, written

    def test_one_call_per_slice_with_the_helper_arguments(self):
        device, reports, written = self.run_jobs(
            [job([slice_(offset=0x8000, cryptoff=0x4000, cryptsize=4)])], lambda command: (0, b'abcd', ''))
        self.assertEqual(reports, [('0', 0, None)])
        self.assertEqual(written, {'0_0.bin': b'abcd'})
        self.assertEqual(device.commands, ["/var/tmp/helpers/mremap_decrypt /var/containers/Bundle/Application/X/App.app/App "
                                           "32768 16384 4 1 16777228 0 -"])

    def test_64_bit_slices_go_first(self):
        slices = [slice_(cpu=12, subtype=9, cryptsize=2), slice_(cryptsize=2)]
        device, _, _ = self.run_jobs([job(slices)], lambda command: (0, b'xy', ''))
        self.assertIn(' 16777228 ', device.commands[0])
        self.assertIn(' 12 9 ', device.commands[1])

    def test_a_failing_slice_is_reported_with_the_helper_message(self):
        def responder(command):
            return 1, b'', 'mremap_encrypted failed: Operation not permitted (errno 1)\n'
        _, reports, written = self.run_jobs([job([slice_()])], responder)
        self.assertEqual(reports, [('0', 0, 'mremap_encrypted failed: Operation not permitted (errno 1)')])
        self.assertEqual(written, {})

    def test_a_short_answer_is_not_accepted(self):
        _, reports, written = self.run_jobs([job([slice_(cryptsize=10)])], lambda command: (0, b'short', ''))
        self.assertIn('5 of 10 bytes', reports[0][2])
        self.assertEqual(written, {})

    def test_errno_12_on_a_private_copy_is_tried_again_where_the_file_is_installed(self):
        calls = []

        def responder(command):
            calls.append(command)
            if '/private-copy/' in command:
                return 1, b'', 'mmap failed: Cannot allocate memory (errno 12)'
            return 0, b'abcd', ''
        j = job([slice_(cryptsize=4)])
        j.slice_paths[0] = '/var/tmp/private-copy/App'
        _, reports, _ = self.run_jobs([j], responder)
        self.assertEqual(reports, [('0', 0, None)])
        self.assertEqual(len(calls), 2)

    def test_exceptions_are_reported_per_slice(self):
        def responder(command):
            raise OSError('channel closed')
        _, reports, _ = self.run_jobs([job([slice_()])], responder)
        self.assertEqual(reports, [('0', 0, 'channel closed')])

    def test_cancelling_stops_before_the_next_slice(self):
        device = FakeDevice(lambda command: (0, b'abcd', ''))
        reports = []
        with tempfile.TemporaryDirectory() as work:
            native_decrypt.run_mremap(device, [job([slice_(cryptsize=4)])], work,
                                      lambda j, i, e: reports.append(e), cancelled=lambda: True)
        self.assertEqual((device.commands, reports), ([], []))


class MemoryTests(unittest.TestCase):
    """run_memory() with a device whose helper output is canned and whose range files are in memory."""

    APP = '/var/containers/Bundle/Application/X/App.app'

    def run_jobs(self, jobs, helper_output, files, status=0, helper_error=''):
        device = mock.Mock()
        device.upload.return_value = '/var/tmp/helpers/memory_decrypt'
        device.scratch.return_value = '/var/tmp/helpers/out-1'
        device.run.return_value = (status, helper_output.encode(), helper_error)
        sftp = mock.Mock()
        device.ssh.open_sftp.return_value = sftp

        def open_file(path, mode='r'):
            handle = mock.MagicMock()
            if path.endswith('Info.plist'):
                import plistlib
                handle.__enter__.return_value.read.return_value = plistlib.dumps({'CFBundleExecutable': 'App'})
            elif path in files:
                handle.__enter__.return_value.read.return_value = files[path]
            else:
                raise OSError('no such file ' + path)
            return handle
        sftp.open.side_effect = open_file
        reports, logs = [], []
        with tempfile.TemporaryDirectory() as work:
            native_decrypt.run_memory(device, 'com.x.app', self.APP, jobs, work,
                                      lambda j, i, e: reports.append((j.id, i, e)), log=logs.append)
            written = {}
            for name in os.listdir(work):
                with open(os.path.join(work, name), 'rb') as handle:
                    written[name] = handle.read()
        return device, reports, written, logs

    def test_ranges_are_read_for_the_matching_slices(self):
        files = {'/var/tmp/helpers/out-1/App.range': b'abcd',
                 '/var/tmp/helpers/out-1/Frameworks/F.framework/F.range': b'wxyz'}
        output = ('OK\tApp\t16777228\t0\t16384\t4\n'
                  'OK\tFrameworks/F.framework/F\t16777228\t0\t16384\t4\n')
        jobs = [job([slice_(cryptsize=4)], self.APP + '/App'),
                ipa_repair.Job('1', 'Payload/App.app/Frameworks/F.framework/F', self.APP + '/Frameworks/F.framework/F',
                               [slice_(cryptsize=4)], kind='framework')]
        device, reports, written, _ = self.run_jobs(jobs, output, files)
        self.assertEqual(reports, [('0', 0, None), ('1', 0, None)])
        self.assertEqual(written, {'0_0.bin': b'abcd', '1_0.bin': b'wxyz'})
        self.assertIn('dump --ranges --bundle-id com.x.app', device.run.call_args.args[0])
        device.remove.assert_called_once_with('/var/tmp/helpers/out-1')

    def test_a_file_the_helper_failed_on_or_never_listed_is_reported(self):
        output = 'FAIL\tPlugIns/E.appex/E\tcould not start the extension and get its task port\n'
        jobs = [ipa_repair.Job('0', 'Payload/App.app/PlugIns/E.appex/E', self.APP + '/PlugIns/E.appex/E', [slice_()],
                               kind='appex'),
                ipa_repair.Job('1', 'Payload/App.app/Frameworks/G.framework/G', self.APP + '/Frameworks/G.framework/G',
                               [slice_()], kind='framework')]
        _, reports, written, _ = self.run_jobs(jobs, output, {})
        self.assertEqual(reports[0], ('0', 0, 'could not start the extension and get its task port'))
        self.assertEqual(reports[1], ('1', 0, 'the helper did not load the file'))
        self.assertEqual(written, {})

    def test_an_app_that_died_while_starting_says_so(self):
        output = 'OK\tApp\t16777228\t0\t16384\t4\n'
        frameworks = ipa_repair.Job('1', 'Payload/App.app/Frameworks/G.framework/G', self.APP + '/Frameworks/G.framework/G',
                                    [slice_()], kind='framework')
        _, reports, _, _ = self.run_jobs([frameworks], output, {}, helper_error='# task_info failed kr=268435459\n')
        self.assertIn('exited while it was starting', reports[0][2])

    def test_another_architecture_than_the_loaded_one_is_reported(self):
        output = 'OK\tApp\t16777228\t0\t16384\t4\n'
        _, reports, _, _ = self.run_jobs([job([slice_(cpu=12, subtype=9, cryptsize=4)], self.APP + '/App')], output,
                                         {'/var/tmp/helpers/out-1/App.range': b'abcd'})
        self.assertEqual(reports, [('0', 0, 'this architecture was not loaded')])

    def test_a_helper_that_failed_outright_fails_every_slice_with_its_message(self):
        _, reports, _, _ = self.run_jobs([job([slice_(), slice_(cpu=12)], self.APP + '/App')],
                                         'FAIL\t-\tcould not start the app and get its task port\n', {}, status=1)
        self.assertEqual([r[2] for r in reports], ['could not start the app and get its task port'] * 2)

    def test_helper_notes_are_logged(self):
        _, _, _, logs = self.run_jobs([job([slice_()], self.APP + '/App')], 'FAIL\t-\tx\n', {}, status=1,
                                      helper_error='# SBS: pid 5\nplain line\n')
        self.assertEqual(logs, ['SBS: pid 5'])

    def test_a_short_range_file_is_reported(self):
        output = 'OK\tApp\t16777228\t0\t16384\t4\n'
        _, reports, written, _ = self.run_jobs([job([slice_(cryptsize=4)], self.APP + '/App')], output,
                                               {'/var/tmp/helpers/out-1/App.range': b'ab'})
        self.assertIn('read 2 of 4', reports[0][2])
        self.assertEqual(written, {})


class DeviceTests(unittest.TestCase):
    def test_root_commands_are_run_as_they_are_and_mobile_commands_through_sudo(self):
        for user, expected in (('root', 'true'), ('mobile', "sudo -S -p '' sh -c true")):
            ssh = mock.Mock()
            stdout = mock.Mock()
            stdout.read.return_value = b'out'
            stdout.channel.recv_exit_status.return_value = 0
            stderr = mock.Mock()
            stderr.read.return_value = b''
            ssh.exec_command.return_value = (mock.Mock(), stdout, stderr)
            status, data, error = native_decrypt.Device(ssh, user, 'pw').run('true')
            self.assertEqual(ssh.exec_command.call_args.args[0], expected)
            self.assertEqual((status, data, error), (0, b'out', ''))

    def test_the_sudo_password_goes_to_stdin(self):
        ssh = mock.Mock()
        stdin = mock.Mock()
        stdout = mock.Mock()
        stdout.read.return_value = b''
        stdout.channel.recv_exit_status.return_value = 0
        stderr = mock.Mock()
        stderr.read.return_value = b''
        ssh.exec_command.return_value = (stdin, stdout, stderr)
        native_decrypt.Device(ssh, 'mobile', 'secret').run('true')
        stdin.write.assert_called_once_with('secret\n')


if __name__ == '__main__':
    unittest.main()
