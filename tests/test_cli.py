import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import ipa_cli
import engine as core
from engine import Indented, Text


def parse(*argv):
    return ipa_cli.build_parser().parse_args(list(argv))


def app(bundle, name=None, path='/private/var/containers/Bundle/Application/X/{}.app', **extra):
    result = dict(name=name or bundle, bundle=bundle, version='1.0', build='1', path=path.format(name or bundle))
    result.update(extra)
    return result


def make_cli(*argv, settings=None):
    """A Cli on an empty settings file, with a few apps instead of a device."""
    args = parse(*argv)
    folder = tempfile.mkdtemp(prefix='cli-test-')
    patcher = mock.patch.object(core, 'CONFIG_PATH', os.path.join(folder, 'settings.json'))
    patcher.start()
    if settings is not None:
        with open(core.CONFIG_PATH, 'w', encoding='utf-8') as handle:
            json.dump(settings, handle)
    cli = ipa_cli.Cli(args)
    patcher.stop()
    cli.folder = folder
    cli.say = lambda message: None
    cli.apps = {a['bundle']: a for a in (
        app('com.z.zeta', 'Zeta'), app('com.a.alpha', 'Alpha'),
        app('com.apple.calculator', 'Calculator'),
        app('com.sys.thing', 'Thing', path='/Applications/Thing.app'),
        app('com.off.loaded', 'Off', offloaded=True))}
    return cli


class ParserTests(unittest.TestCase):
    def test_commands_and_options(self):
        self.assertTrue(parse('apps', '-q', '--lang', 'ja').quiet)
        self.assertTrue(parse('-q', 'apps').quiet)
        self.assertEqual(parse('--lang', 'ja', 'apps').lang, 'ja')
        self.assertFalse(parse('apps').quiet)
        args = parse('decrypt', '-H', '10.0.0.2', '-u', 'mobile', '--mode', 'native', '--helper', 'memory',
                     '--no-repair', '--keep-open', 'com.a', 'com.b')
        self.assertEqual((args.host, args.user, args.mode, args.helper), ('10.0.0.2', 'mobile', 'native', 'memory'))
        self.assertEqual((args.repair, args.close_after, args.restart_frida), (False, False, None))
        self.assertEqual(args.bundles, ['com.a', 'com.b'])

    def test_unset_flags_stay_unset_so_the_settings_decide(self):
        args = parse('extract', '--all')
        self.assertIsNone(args.user_only)
        self.assertIsNone(args.non_apple)
        self.assertIsNone(args.encrypted_only)
        self.assertFalse(parse('extract', '--include-system', '--all').user_only)

    def test_a_command_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse()


class SelectionTests(unittest.TestCase):
    def test_all_means_the_filtered_list_in_name_order(self):
        cli = make_cli('extract', '--all')
        self.assertEqual([a['bundle'] for a in cli.select('extract')],
                         ['com.a.alpha', 'com.apple.calculator', 'com.z.zeta'])  # not system, not offloaded

    def test_filters_follow_the_settings_and_the_options(self):
        cli = make_cli('extract', '--all', settings=dict(non_apple=True))
        self.assertEqual([a['bundle'] for a in cli.select('extract')], ['com.a.alpha', 'com.z.zeta'])
        cli = make_cli('extract', '--all', '--include-system')
        self.assertIn('com.sys.thing', [a['bundle'] for a in cli.select('extract')])

    def test_search(self):
        cli = make_cli('extract', '--search', 'ZET')
        self.assertEqual([a['bundle'] for a in cli.select('extract')], ['com.z.zeta'])

    def test_named_apps_ignore_the_filters(self):
        cli = make_cli('extract', 'com.sys.thing')
        self.assertEqual([a['bundle'] for a in cli.select('extract')], ['com.sys.thing'])

    def test_unknown_offloaded_and_nothing(self):
        for argv, text in ((('extract', 'nope'), 'no app with the bundle ID'),
                           (('extract', 'com.off.loaded'), 'offloaded'),
                           (('extract',), 'no apps selected')):
            with self.assertRaises(ipa_cli.CliError) as context:
                make_cli(*argv).select('extract')
            self.assertIn(text, str(context.exception))

    def test_unextracted_and_partial_look_at_the_output_folders(self):
        cli = make_cli('decrypt', '--all')
        out = os.path.join(cli.folder, 'out')
        os.makedirs(out)
        cli.settings.update(outdir=out, extract_dir=out)
        done = cli.ipa_name(cli.apps['com.a.alpha'], 'dump', 'decrypted')
        partial = cli.ipa_name(cli.apps['com.z.zeta'], 'dump', 'partial-decrypted')
        for name in (done, partial):
            open(os.path.join(out, name + '.ipa'), 'w').close()
        cli.args = parse('decrypt', '--unextracted')
        self.assertEqual([a['bundle'] for a in cli.select('dump')], ['com.apple.calculator'])
        cli.args = parse('decrypt', '--partial')
        self.assertEqual([a['bundle'] for a in cli.select('dump')], ['com.z.zeta'])

    def test_an_original_ipa_counts_whether_or_not_the_app_was_read(self):
        cli = make_cli('extract', '--unextracted')
        out = os.path.join(cli.folder, 'out')
        os.makedirs(out)
        cli.settings.update(outdir=out, extract_dir=out, separate_dirs=False)
        alpha = cli.apps['com.a.alpha']
        # the app is not read yet (it would be named "encrypted"), the file on disk says "original"
        open(os.path.join(out, cli.ipa_name(alpha, 'extract', 'original') + '.ipa'), 'w').close()
        self.assertFalse(cli.is_unextracted(alpha))
        self.assertTrue(cli.is_unextracted(cli.apps['com.z.zeta']))


class NameAndOutputTests(unittest.TestCase):
    def test_two_apps_with_one_name_are_refused(self):
        cli = make_cli('extract', '--all', '--name', 'same')
        with self.assertRaises(ipa_cli.CliError) as context:
            cli.jobs('dump', cli.select('dump'))
        self.assertIn('same file name', str(context.exception))

    def test_a_bad_template_is_refused(self):
        cli = make_cli('extract', '--all', '--name', '{nope}')
        with self.assertRaises(ipa_cli.CliError) as context:
            cli.jobs('dump', cli.select('dump'))
        self.assertIn('template', str(context.exception))

    def test_existing_files_need_a_decision_when_not_interactive(self):
        cli = make_cli('decrypt', 'com.a.alpha', '-o', os.path.join(self.id() and tempfile.mkdtemp(), 'out'))
        jobs = cli.jobs('dump', [cli.apps['com.a.alpha']])
        outdir, remaining = cli.prepare_output('dump', jobs)
        open(os.path.join(outdir, jobs[0][1] + '.ipa'), 'w').close()
        with mock.patch('sys.stdin') as stdin:
            stdin.isatty.return_value = False
            with self.assertRaises(ipa_cli.CliError) as context:
                cli.prepare_output('dump', jobs)
        self.assertIn('--overwrite', str(context.exception))
        cli.args = parse('decrypt', 'com.a.alpha', '--overwrite', '-o', outdir)
        self.assertEqual(cli.prepare_output('dump', jobs)[1], jobs)
        cli.args = parse('decrypt', 'com.a.alpha', '--skip-existing', '-o', outdir)
        self.assertEqual(cli.prepare_output('dump', jobs)[1], [])

    def test_output_folder_defaults(self):
        cli = make_cli('extract', 'com.a.alpha')
        self.assertFalse(core.DEFAULTS['separate_dirs'])                # one folder unless Settings separate them
        self.assertEqual(cli.output_dir('extract'), core.DEFAULTS['outdir'])
        self.assertEqual(cli.output_dir('dump'), core.DEFAULTS['outdir'])
        cli.settings['separate_dirs'] = True
        self.assertEqual(cli.output_dir('extract'), core.DEFAULTS['extract_dir'])
        self.assertEqual(make_cli('extract', 'a', '-o', 'x').output_dir('extract'), 'x')


class ConnectionTests(unittest.TestCase):
    def test_options_beat_the_settings_and_the_environment_beats_a_saved_password(self):
        cli = make_cli('apps', '-H', '1.2.3.4', settings=dict(host='9.9.9.9', user='root', port=2222, password='saved'))
        with mock.patch.dict(os.environ, {'IPA_PASSWORD': 'env'}):
            self.assertEqual(cli.connection(), ('1.2.3.4', 2222, 'root', 'env'))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('IPA_PASSWORD', None)
            self.assertEqual(cli.connection()[3], 'saved')
            cli.args = parse('apps', '-p', 'given', '-H', 'h', '-u', 'u')
            self.assertEqual(cli.connection(), ('h', 2222, 'u', 'given'))

    def test_missing_pieces_are_explained(self):
        for argv, text in ((('apps',), 'no device address'), (('apps', '-H', 'h'), 'no SSH account')):
            with self.assertRaises(ipa_cli.CliError) as context:
                make_cli(*argv).connection()
            self.assertIn(text, str(context.exception))


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), 'settings.json')
        patcher = mock.patch.object(core, 'CONFIG_PATH', self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_values_are_converted_and_checked(self):
        self.assertEqual(ipa_cli.convert_setting('port', '2200'), 2200)
        self.assertIs(ipa_cli.convert_setting('non_apple', 'yes'), True)
        self.assertEqual(ipa_cli.convert_setting('theme', 'black'), 'black')
        self.assertEqual(ipa_cli.convert_setting('dump_method', 'native'), 'native')
        for key, bad in (('port', 'x'), ('non_apple', 'maybe'), ('theme', 'pink'), ('dump_method', 'magic'),
                         ('native_helper', 'x'), ('lang', 'xx'), ('name_decrypted', '{nope}'), ('frida_method', 'native')):
            with self.assertRaises(ipa_cli.CliError, msg=key):
                ipa_cli.convert_setting(key, bad)

    def test_only_values_that_differ_from_the_default_are_kept(self):
        ipa_cli.update_settings({'theme': 'dark', 'port': 22, 'host': '10.0.0.5'})
        with open(self.path, encoding='utf-8') as handle:
            self.assertEqual(json.load(handle), dict(theme='dark', host='10.0.0.5'))
        ipa_cli.update_settings({'theme': 'system'}, reset=['host'])
        with open(self.path, encoding='utf-8') as handle:
            self.assertEqual(json.load(handle), {})

    def test_other_saved_keys_such_as_the_password_are_kept(self):
        with open(self.path, 'w', encoding='utf-8') as handle:
            json.dump(dict(password='secret', theme='dark'), handle)
        ipa_cli.update_settings({'host': 'h'})
        with open(self.path, encoding='utf-8') as handle:
            self.assertEqual(json.load(handle), dict(password='secret', theme='dark', host='h'))

    def test_config_command(self):
        for argv in (('config', 'set', 'theme', 'black'), ('config', 'set', 'theme', 'pink')):
            cli = ipa_cli.Cli(parse(*argv))
            try:
                ipa_cli.cmd_config(cli)
            except ipa_cli.CliError:
                self.assertEqual(argv[-1], 'pink')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ipa_cli.cmd_config(ipa_cli.Cli(parse('config', 'show', '--json')))
        shown = json.loads(out.getvalue())
        self.assertEqual(shown['theme'], 'black')
        self.assertNotIn('password', shown)


class OutputTests(unittest.TestCase):
    def test_messages_are_rendered_in_the_chosen_language(self):
        cli = make_cli('apps', '--lang', 'zh-TW')
        self.assertIn('已連線', cli.render(Text('log_ssh_ok')))
        self.assertTrue(cli.render(Indented(Text('log_ssh_ok'))).startswith('    '))

    def test_progress_is_throttled_but_outcomes_are_not(self):
        cli = make_cli('apps')
        lines = []
        cli.say = lines.append
        for _ in range(5):
            cli.set_status('com.a.alpha', Text('st_running', pct='5', stage='x'), 'running')
        self.assertEqual(len(lines), 1)
        cli.set_status('com.a.alpha', Text('st_done'), 'done')
        self.assertEqual(len(lines), 2)

    def test_results_and_exit_status(self):
        cli = make_cli('decrypt', '--all')
        out = os.path.join(cli.folder, 'o')
        names = {'com.a.alpha': {'decrypted': 'A_dec', 'partial': 'A_part'}, 'com.z.zeta': {'decrypted': 'Z_dec'}}
        cli.set_status('com.a.alpha', Text('st_done'), 'done')
        cli.set_status('com.z.zeta', Text('st_failed', msg='boom'), 'failed')
        cli._set_verify('com.a.alpha', 'decrypted', 3, [], 'decrypted')
        jobs = [('com.a.alpha', 'A_dec'), ('com.z.zeta', 'Z_dec')]
        records = cli.results('dump', jobs, out, names)
        self.assertEqual([r['ok'] for r in records], [True, False])
        self.assertEqual(records[0]['path'], os.path.join(out, 'A_dec.ipa'))
        self.assertIsNone(records[1]['path'])
        self.assertIn('boom', records[1]['message'])
        cli.args.json = False
        with contextlib.redirect_stdout(io.StringIO()):
            cli.finished = dict(partial=0)
            self.assertEqual(ipa_cli.finish(cli, 'dump', jobs, out, names), ipa_cli.EXIT_FAILED)
            cli.set_status('com.z.zeta', Text('st_done'), 'done')
            self.assertEqual(ipa_cli.finish(cli, 'dump', jobs, out, names), ipa_cli.EXIT_OK)
            cli.finished = dict(partial=1)
            self.assertEqual(ipa_cli.finish(cli, 'dump', jobs, out, names), ipa_cli.EXIT_PARTIAL)
            cli.cancel_requested.set()
            self.assertEqual(ipa_cli.finish(cli, 'dump', jobs, out, names), ipa_cli.EXIT_CANCELLED)

    def test_the_second_interrupt_is_not_swallowed(self):
        cli = make_cli('apps', '-q')
        cli.working = True
        cli.cancel()
        self.assertTrue(cli.cancel_requested.is_set())
        with self.assertRaises(KeyboardInterrupt):
            cli.cancel()

    def test_the_first_interrupt_outside_a_batch_stops_at_once(self):
        cli = make_cli('apps', '-q')       # at a prompt or while connecting there is no file to finish
        with self.assertRaises(KeyboardInterrupt):
            cli.cancel()
        self.assertFalse(cli.cancel_requested.is_set())


class EngineTests(unittest.TestCase):
    def test_the_window_and_the_command_line_share_the_engine(self):
        try:
            import ipa_extractor
        except ImportError:
            self.skipTest('no tkinter')
        for name in ('_extract_worker', '_dump_worker', '_finish_dump', '_repair', 'install_frida', 'ssh_alive'):
            self.assertTrue(hasattr(core.DumpEngine, name), name)
            self.assertFalse(name in vars(ipa_extractor.DumpGUI), name)
        self.assertTrue(issubclass(ipa_cli.Cli, core.DumpEngine))
        self.assertTrue(issubclass(ipa_extractor.DumpGUI, core.DumpEngine))

    def test_the_launcher_script_runs_the_command_line_without_tkinter(self):
        code = ("import sys, runpy; sys.modules['tkinter'] = None; sys.argv = ['ipa_extractor.py', 'config', 'path']; "
                "runpy.run_path('ipa_extractor.py', run_name='__main__')")      # as `python ipa_extractor.py config path`
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        done = subprocess.run([sys.executable, '-c', code], cwd=here, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.strip().endswith('.json'))

    def test_the_command_line_runs_without_tkinter(self):
        code = ("import sys; sys.modules['tkinter'] = None; import ipa_cli; "
                "sys.exit(ipa_cli.main(['config', 'path']))")      # an import of tkinter would raise ImportError
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        done = subprocess.run([sys.executable, '-c', code], cwd=here, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.strip().endswith('.json'))
        self.assertNotIn('tkinter', sys.modules.get('engine').__dict__)

    def test_file_mapping_is_refused_on_ios_16_before_anything_runs(self):
        for argv in (['--helper', 'mremap'], []):
            cli = make_cli('decrypt', '--mode', 'native', *argv, 'com.a.alpha',
                           settings={} if argv else {'native_helper': 'mremap'})
            cli.user, cli.password, cli.ssh = 'mobile', 'pw', mock.Mock()
            cli.prepare_output = lambda kind, jobs, names: (cli.folder, jobs)
            cli._dump_worker = mock.Mock()
            with mock.patch.object(ipa_cli.native_decrypt, 'Device') as device:
                device.return_value.ios_version.return_value = '16.1.2'
                with self.assertRaises(ipa_cli.CliError) as caught:
                    cli.run_decrypt([cli.apps['com.a.alpha']])
            self.assertIn('--helper memory', str(caught.exception))
            self.assertIn('16.1.2', str(caught.exception))
            cli._dump_worker.assert_not_called()

    def test_file_mapping_on_ios_15_and_the_other_helpers_run(self):
        for ios, helper in (('15.8', 'mremap'), ('16.1.2', 'auto'), ('17.0', 'memory')):
            cli = make_cli('decrypt', '--mode', 'native', '--helper', helper, 'com.a.alpha')
            cli.user, cli.password, cli.ssh = 'mobile', 'pw', mock.Mock()
            cli.settings.update(host='10.0.0.2', user='mobile', password='pw')
            cli.prepare_output = lambda kind, jobs, names: (cli.folder, jobs)
            cli._dump_worker = mock.Mock()
            with mock.patch.object(ipa_cli.native_decrypt, 'Device') as device:
                device.return_value.ios_version.return_value = ios
                cli.run_decrypt([cli.apps['com.a.alpha']])
            cli._dump_worker.assert_called_once()

    def test_extract_runs_the_engine_on_the_calling_thread(self):
        cli = make_cli('extract', 'com.a.alpha')
        calls = []

        def fake_extract(ssh, path, target, progress, cancelled, **kwargs):
            calls.append((path, target))
            progress(1, 1)
            open(target, 'w').close()

        cli.ssh = mock.Mock()
        cli.ssh.get_transport.return_value.is_active.return_value = True
        out = os.path.join(cli.folder, 'x')
        os.makedirs(out)
        with mock.patch.object(core.ipa_extract, 'extract_ipa', fake_extract):
            cli._extract_worker([('com.a.alpha', 'Alpha')], out)
        self.assertEqual(calls[0][1], os.path.join(out, 'Alpha.ipa'))
        self.assertEqual(cli.status['com.a.alpha'][1], 'done')
        self.assertEqual(cli.finished['succeeded'], 1)


if __name__ == '__main__':
    unittest.main()
