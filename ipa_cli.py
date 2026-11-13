#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPA Extractor on the command line: what the window does, without the window.

    python ipa_cli.py apps                           list the apps on the device
    python ipa_cli.py extract com.example.app        original IPAs
    python ipa_cli.py decrypt --all --mode native    decrypted IPAs
    python ipa_cli.py verify some.ipa                is it really decrypted?
    python ipa_cli.py config show                    the settings the window shares

The device and the settings come from settings.json, the file the window saves; options override it.
Messages from the extraction itself are in the language of the settings (or --lang); the command line's own
messages and help are English. Output that is meant for scripts goes to stdout (--json), progress to stderr.
"""

import argparse
import getpass
import json
import os
import signal
import sys
import threading
import time

import app_info
import device_apps
import frida_versions
import i18n
import ipa_verify
import native_decrypt
import remote
import usbmux

# The engine needs no window and no tkinter: the command line runs on a server without Tk.
import engine as core
from engine import Text, Indented

# How the command is typed: the released program is the file that was started, from source it is the script.
PROG = os.path.basename(sys.argv[0]) if core.app_paths.FROZEN and sys.argv and sys.argv[0] else 'ipa_cli.py'
RUN = PROG if core.app_paths.FROZEN else 'python ipa_cli.py'

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_PARTIAL, EXIT_CANCELLED = 0, 1, 2, 3, 130
MODES = {'native': core.METHOD_NATIVE, 'frida-direct': core.METHOD_FRIDA_DIRECT,
         'frida-ios-dump': core.METHOD_FRIDA_IOS_DUMP}
STATUS_INTERVAL = 5   # seconds between two progress lines of one app


class CliError(Exception):
    """Something the user can fix; the message is printed and the exit status is EXIT_USAGE."""


def yes_no(value):
    text = str(value).strip().lower()
    if text in ('1', 'true', 'yes', 'on', 'y'):
        return True
    if text in ('0', 'false', 'no', 'off', 'n'):
        return False
    raise argparse.ArgumentTypeError('expected true or false, not ' + repr(value))


class Cli(core.DumpEngine):
    """A DumpEngine whose output is text on the terminal. Everything runs on the calling thread."""

    def __init__(self, args):
        self.args = args
        self.settings = dict(core.DEFAULTS)
        self.settings.update(core.load_config())
        self.locales = i18n.load_locales()
        self.lang = i18n.resolve(self.locales, getattr(args, 'lang', None) or self.settings['lang'])
        self.quiet = getattr(args, 'quiet', False)
        self.ssh = self.tunnel = self.frida_version = self.device_os = None
        self.usb_tunnel = None     # the USB connection's local end, when the device is reached by cable
        self.host, self.port, self.user, self.password = '', 22, '', ''
        self.working = False       # a batch is running: only then does Ctrl-C mean "finish this file and stop"
        self.generation = 0
        self.cancel_requested = threading.Event()
        self.current_process = None
        self.apps, self.status = {}, {}
        self.overall = (0, '')
        self.finished = None
        self.printed = {}

    # ---------------------------------------------------------- engine callbacks
    def t(self, key, **params):
        template = self.locales[self.lang].get(key) or self.locales[i18n.FALLBACK].get(key, key)
        return template.format(**params)

    def render(self, text):
        if isinstance(text, Indented):
            return '    ' + self.render(text.text)
        if isinstance(text, Text):
            return self.t(text.key, **{k: self.render(v) for k, v in text.params.items()})
        return str(text)

    def post(self, func, *args):
        func(*args)

    def say(self, message):
        print(message, file=sys.stderr, flush=True)

    def log(self, text):
        if not self.quiet:
            self.say(time.strftime('[%H:%M:%S] ') + self.render(text))

    def set_status(self, bundle, text, tag=''):
        self.status[bundle] = (text, tag)
        if self.quiet:
            return
        # Progress is throttled; the outcome of an app is always shown.
        now = time.monotonic()
        if tag in ('running', 'queued') and now - self.printed.get(bundle, -STATUS_INTERVAL) < STATUS_INTERVAL:
            return
        self.printed[bundle] = now
        self.say('  {}: {}'.format(bundle, self.render(text)))

    def _set_overall(self, value, text):
        self.overall = (value, text)

    def _set_verify(self, bundle, status, total, files, type_=None):
        if bundle in self.apps:
            self.apps[bundle]['verify'] = dict(status=status, total=total, files=files, type=type_ or status)

    def _batch_finished(self, mode, outdir, succeeded, total, paused, partial=0):
        self.finished = dict(mode=mode, outdir=outdir, succeeded=succeeded, total=total, paused=paused, partial=partial)
        self.log(Text('log_extract_finished' if mode == 'extract' else 'log_finished',
                      ok=succeeded, total=total, dir=outdir))
        if partial:
            self.log(Text('log_partial_summary', n=partial))
        if paused:
            self.say(self.t('m_paused', n=core.MAX_CONSECUTIVE_FRIDA_ERRORS))

    def helper_problem(self, error):
        """A helper could not be used on the device (the apps of the batch fail with the same reason)."""
        self.say('warning: ' + self.t('m_helper', error=error).split('\n\n')[0] + ' ' + error)

    def cancel(self):
        """Stop the batch after the file in progress: the first Ctrl-C asks, the second one kills."""
        if self.cancel_requested.is_set() or not self.working:
            raise KeyboardInterrupt     # a prompt, the connection or an install: nothing to finish first
        self.cancel_requested.set()
        process = self.current_process
        if process is not None and process.poll() is None:
            process.terminate()
        self.log(Text('log_cancel'))

    # ------------------------------------------------------------- connection
    def connection_mode(self):
        """(core.CONNECTION_SSH or CONNECTION_USB, the USB device's serial or ''), from the options or the settings."""
        args, c = self.args, self.settings
        if getattr(args, 'ssh', False):
            return core.CONNECTION_SSH, ''
        if getattr(args, 'usb', False) or getattr(args, 'udid', None):
            return core.CONNECTION_USB, (args.udid or c['usb_device']).strip()
        return core.connection_setting(c['connection']), c['usb_device'].strip()

    def connection(self):
        """(host, port, user, password) from the options, falling back to the window's settings."""
        args, c = self.args, self.settings
        usb = self.connection_mode()[0] == core.CONNECTION_USB
        host = (args.host or c['host']).strip()
        user = (args.user or c['user']).strip()
        try:
            port = int(args.port or c['port'])
        except (TypeError, ValueError):
            raise CliError('the SSH port must be a number')
        if not host and not usb:
            raise CliError('no device address: use --host, or set it with "config set host ADDRESS"; '
                           'or use --usb to reach the device by cable')
        if not user:
            raise CliError('no SSH account: use --user (root, or mobile on rootless jailbreaks)')
        password = args.password
        if password is None:
            password = os.environ.get('IPA_PASSWORD')
        if password is None and c.get('password') not in (None, ''):
            password = c['password']
        if password is None:
            if not sys.stdin.isatty():
                raise CliError('no SSH password: use --password, the IPA_PASSWORD variable, or run in a terminal')
            password = getpass.getpass('SSH password for {}@{}: '.format(user, host or 'USB'))
        return host, port, user, password

    def connect(self):
        host, port, self.user, self.password = self.connection()
        mode, serial = self.connection_mode()
        label = ('USB ' + serial).strip() if mode == core.CONNECTION_USB else host
        self.log(Text('log_ssh_connecting', user=self.user, host=label, port=port))
        try:
            self.ssh, address, self.usb_tunnel = core.open_device(
                mode, host, port, self.user, self.password, self.log, usb_device=serial)
        except Exception as error:
            raise CliError(self.render(Text('log_ssh_failed', error=core.error_text(error))))
        self.host, self.port = address      # what SSH really connects to: the local end of the USB tunnel, or the device
        self.log(Text('log_ssh_ok'))

    def close(self):
        if self.tunnel is not None:
            self.tunnel.close()
        if self.ssh is not None:
            self.ssh.close()
        if self.usb_tunnel is not None:
            self.usb_tunnel.close()

    # ------------------------------------------------------------------- apps
    def load_apps(self):
        self.log(Text('log_loading'))
        try:
            self.apps = device_apps.list_apps(self.ssh)
        except Exception as error:
            raise CliError(self.render(Text('log_load_failed', error=error)))
        user_count = sum(1 for app in self.apps.values() if core.is_user_app(app['path']))
        self.log(Text('log_loaded', total=len(self.apps), user=user_count))

    def read_info(self, apps):
        """Signature details (encryption, signer, ...) of the apps that have none yet; they need SFTP reads."""
        todo = [app for app in apps if 'info' not in app and app['path'] and not app.get('offloaded')]
        if not todo:
            return
        try:
            sftp = self.ssh.open_sftp()
        except Exception as error:
            self.log(Text('log_sftp_failed', error=error))
            return
        try:
            for app in todo:
                try:
                    app['info'] = app_info.read_app_info(sftp, app['path'])
                except Exception as error:
                    app['info'] = dict(error=str(error))
        finally:
            sftp.close()

    def filters(self):
        args, c = self.args, self.settings
        return dict(user_only=c['user_only'] if args.user_only is None else args.user_only,
                    non_apple=args.non_apple if args.non_apple is not None else c['non_apple'],
                    encrypted_only=args.encrypted_only if args.encrypted_only is not None else c['encrypted_only'],
                    search=(args.search or '').strip().lower())

    def visible(self, filters=None):
        """The apps the window would show with these filters."""
        f = filters or self.filters()
        apps = list(self.apps.values())
        if f['encrypted_only']:
            self.read_info([app for app in apps if (not f['user_only'] or core.is_user_app(app['path']))])
        result = []
        for app in apps:
            if f['user_only'] and not core.is_user_app(app['path']):
                continue
            if f['non_apple'] and core.is_apple_app(app['bundle']):
                continue
            if f['encrypted_only'] and app.get('info', {}).get('encrypted') is False:
                continue
            if f['search'] and f['search'] not in app['name'].lower() and f['search'] not in app['bundle'].lower():
                continue
            result.append(app)
        return sorted(result, key=lambda app: core.natural_key(app['name']))

    # ------------------------------------------------------------ file names
    def template(self, mode):
        args, c = self.args, self.settings
        if mode == 'dump':
            return getattr(args, 'name', None) or c['name_decrypted']
        return getattr(args, 'name', None) or c['name_original']

    def output_dir(self, mode):
        output = getattr(self.args, 'output', None)
        if output:
            return output
        c = self.settings
        return (c['extract_dir'] if mode == 'extract' and c['separate_dirs'] else c['outdir']).strip()

    def ipa_name(self, app, mode, kind=None, template=None):
        template = template or self.template(mode)
        if mode == 'dump':
            kind = kind or ipa_verify.DECRYPTED
        else:
            kind = kind or ('encrypted' if app.get('info', {}).get('encrypted') is not False else 'original')
        return app_info.format_ipa_name(template, app['name'], app['bundle'], app['version'], app['build'], kind)

    def name_error(self, error):
        return self.t(error.args[0], **error.args[1])

    def select(self, mode):
        """The apps a batch is for, in the order of the window's list."""
        args = self.args
        chosen = {}
        for bundle in args.bundles:
            if bundle not in self.apps:
                raise CliError('no app with the bundle ID {} on the device (see: {} apps)'.format(bundle, PROG))
            chosen[bundle] = self.apps[bundle]
        flagged = args.all or args.unextracted or args.partial or args.search
        if flagged:
            shown = self.visible()
            try:
                if args.unextracted:
                    shown = [app for app in shown if self.is_unextracted(app)]
                if args.partial:
                    shown = [app for app in shown if self.is_partial(app)]
            except app_info.NameTemplateError as error:
                raise CliError('the file name template cannot be used: ' + self.name_error(error))
            for app in shown:
                chosen.setdefault(app['bundle'], app)
        for bundle in [b for b, app in chosen.items() if app.get('offloaded')]:
            if bundle in args.bundles:
                raise CliError('{} is offloaded: its files are not on the device'.format(bundle))
            del chosen[bundle]
        if not chosen:
            raise CliError('no apps selected: name bundle IDs, or use --all, --search, --unextracted or --partial')
        return sorted(chosen.values(), key=lambda app: core.natural_key(app['name']))

    def is_unextracted(self, app):
        """Neither a decrypted nor an original IPA under the current file names (a partial one counts)."""
        paths = []
        for mode, kinds in (('dump', core.DUMP_KINDS), ('extract', ('encrypted', 'original'))):
            paths += [os.path.join(self.output_dir(mode), self.ipa_name(app, mode, kind) + '.ipa') for kind in kinds]
        return not any(os.path.exists(path) for path in paths)

    def is_partial(self, app):
        """The decrypted IPA in the output folder is there only under a partially decrypted name."""
        exists = {kind: os.path.exists(os.path.join(self.output_dir('dump'), self.ipa_name(app, 'dump', kind) + '.ipa'))
                  for kind in core.DUMP_KINDS}
        return not exists[ipa_verify.DECRYPTED] and any(exists[kind] for kind in core.DUMP_KINDS[1:])

    # ----------------------------------------------------------------- batches
    def jobs(self, mode, apps):
        """[(bundle, IPA base name)]; fails on a bad template or two apps with one name."""
        try:
            template = self.template(mode)
            app_info.check_name_template(template)
            if mode == 'extract':
                self.read_info(apps)  # {type} of an original IPA says whether it is encrypted
            jobs = [(app['bundle'], self.ipa_name(app, mode)) for app in apps]
        except app_info.NameTemplateError as error:
            raise CliError('the file name template cannot be used: ' + self.name_error(error))
        owners = {}
        for bundle, name in jobs:
            owners.setdefault(name.lower(), (name, []))[1].append(bundle)
        clashes = ['{}.ipa: {}'.format(name, ', '.join(b)) for name, b in owners.values() if len(b) > 1]
        if clashes:
            raise CliError('these apps would get the same file name (change --name):\n  ' + '\n  '.join(clashes))
        return jobs

    def prepare_output(self, mode, jobs, names=None):
        """Make the folder and settle files that exist: ask, replace (--overwrite) or leave the app out (--skip-existing).

        Returns the jobs that remain.
        """
        outdir = self.output_dir(mode)
        try:
            os.makedirs(outdir, exist_ok=True)
        except OSError as error:
            raise CliError('cannot use the output folder {}: {}'.format(outdir, error))
        args = self.args
        remaining = []
        existing = []
        for bundle, name in jobs:
            candidates = list(dict.fromkeys(names[bundle].values() if names else [name]))
            present = [n + '.ipa' for n in candidates if os.path.exists(os.path.join(outdir, n + '.ipa'))]
            if present and args.skip_existing:
                self.log('Skipping {}: {} already exists'.format(bundle, present[0]))
                continue
            existing += present
            remaining.append((bundle, name))
        if existing and not args.overwrite:
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                raise CliError('these files exist (use --overwrite to replace them, --skip-existing to leave '
                               'those apps out):\n  ' + '\n  '.join(existing[:15]))
            self.say('These files will be replaced:\n  ' + '\n  '.join(existing[:15]))
            if input('Continue? [y/N] ').strip().lower() not in ('y', 'yes'):
                raise CliError('cancelled')
        return outdir, remaining

    def run_extract(self, apps):
        jobs = self.jobs('extract', apps)
        outdir, jobs = self.prepare_output('extract', jobs)
        if not jobs:
            self.finished = dict(mode='extract', outdir=outdir, succeeded=0, total=0, paused=False, partial=0)
            return jobs, outdir, None
        self.log(Text('log_extract_start', n=len(jobs)))
        self.working = True
        try:
            self._extract_worker(jobs, outdir)
        finally:
            self.working = False
        return jobs, outdir, None

    # -------------------------------------------------------------------- Frida
    def connect_frida(self, direct):
        """Frida through an SSH tunnel, the way the window does; raises CliError when it cannot be had."""
        args, c = self.args, self.settings
        try:
            port = int(args.frida_port or c['frida_port'])
        except (TypeError, ValueError):
            raise CliError('the Frida port must be a number')
        self.log(Text('log_frida_connecting'))
        try:
            device_version, running = core.frida_server_status(self.ssh)
        except Exception as error:
            raise CliError(self.render(Text('log_frida_failed', error=error)))
        versions = frida_versions.installed()
        self.log(Text('log_frida_versions', device=device_version or Text('not_installed'),
                      state=Text('running' if running else 'not_running'),
                      local=', '.join(versions) or Text('not_installed')))
        if not device_version or not running:
            raise CliError(self.render(Text('log_no_server')))
        version = frida_versions.pick(device_version, versions)
        if version is None:
            if not args.install_frida:
                raise CliError('no installed frida fits frida-server {} on the device. Install it with:\n  {}\n'
                               'or add --install-frida'.format(device_version, RUN + ' install-frida --version '
                                                               + device_version))
            dump_dir = None if direct else (args.dump_dir or c['dump_dir'])
            if not self.install_frida(device_version, dump_dir):
                raise CliError('installing frida {} failed'.format(device_version))
            version = frida_versions.pick(device_version, frida_versions.installed())
            if version is None:
                raise CliError('frida {} was installed but cannot be used'.format(device_version))
        if version != device_version:
            self.log(Text('log_minor', local=version, device=device_version))
        tunnel = None
        try:
            tunnel = core.SSHTunnel(self.ssh.get_transport(), port)
            ok, detail = core.probe_frida(version, '127.0.0.1:{}'.format(tunnel.local_port))
        except Exception as error:
            ok, detail = False, error
        if not ok:
            if tunnel is not None:
                tunnel.close()
            raise CliError(self.render(Text('log_frida_failed', error=detail)))
        if not detail:
            try:
                detail = 'iOS ' + remote.run(self.ssh, 'sw_vers -productVersion')[1].strip()
            except Exception:
                detail = ''
        self.tunnel, self.frida_version, self.device_os = tunnel, version, detail
        self.log(Text('log_frida_ok', local=tunnel.local_port, remote=port))
        self.log(Text('log_frida_using', version=version))

    def run_decrypt(self, apps):
        args, c = self.args, self.settings
        method = MODES[args.mode] if args.mode else core.dump_method_setting(c['dump_method'])
        direct = method in (core.METHOD_FRIDA_DIRECT, core.METHOD_NATIVE)
        native = method == core.METHOD_NATIVE
        dump_dir = (args.dump_dir or c['dump_dir']).strip()
        if not direct and core.dump_dir_status(dump_dir) != 'ok':
            raise CliError('frida-ios-dump is not set up in {!r}: run "{} install-frida-ios-dump" '
                           'or use --dump-dir, or choose another --mode'.format(dump_dir, RUN))
        try:
            names = {app['bundle']: {kind: self.ipa_name(app, 'dump', kind) for kind in core.DUMP_KINDS}
                     for app in apps}
            jobs = self.jobs('dump', apps)
        except app_info.NameTemplateError as error:
            raise CliError('the file name template cannot be used: ' + self.name_error(error))
        outdir, jobs = self.prepare_output('dump', jobs, names)
        if not jobs:
            self.finished = dict(mode='dump', outdir=outdir, succeeded=0, total=0, paused=False, partial=0)
            return jobs, outdir, names
        if native:
            try:
                version = native_decrypt.Device(self.ssh, self.user, self.password).ios_version()
            except Exception:
                version = ''
            self.device_os = 'iOS ' + version if version else None
        else:
            self.connect_frida(direct)
            if not direct and int(core.major(self.frida_version) or 0) < 16:
                raise CliError(self.t('m_dump_old_frida', version=self.frida_version))
        if native:
            try:
                native_decrypt.local_helper(native_decrypt.choose(args.helper or c['native_helper'],
                                                                  core.ios_major(self.device_os)))
            except native_decrypt.HelperError as error:
                raise CliError(self.t('m_helper', error=error).split('\n\n')[0] + ' ' + str(error))
        if native and native_decrypt.refused(args.helper or c['native_helper'], core.ios_major(self.device_os)):
            # The first paragraph says why; the choice it ends with is named by option here.
            raise CliError(self.t('m_mremap', version=native_decrypt.version_text(self.device_os)).split('\n\n')[0]
                           + ' Use --helper auto or --helper memory.')
        helper = native_decrypt.choose(args.helper or c['native_helper'], core.ios_major(self.device_os)) if native else None
        if not self.host:
            self.host, self.port, _, _ = self.connection()
        host, port = self.host, self.port
        options = dict(direct=direct, native=helper, method=helper or core.decrypt_method(self.device_os),
                       host=host, port=str(port), user=self.user, password=self.password,
                       frida='127.0.0.1:{}'.format(self.tunnel.local_port) if self.tunnel else None,
                       frida_version=self.frida_version, outdir=outdir, dump_dir=dump_dir,
                       close_after=c['close_after'] if args.close_after is None else args.close_after,
                       restart_frida=c['restart_frida'] if args.restart_frida is None else args.restart_frida,
                       generation=self.generation, names=names,
                       repair=direct or (c['repair'] if args.repair is None else args.repair), ios=self.device_os or '')
        self.log(Text('log_start_native' if native else 'log_start_direct' if direct else 'log_start', n=len(jobs)))
        self.working = True
        try:
            self._dump_worker(jobs, options)
        finally:
            self.working = False
        return jobs, outdir, names

    def results(self, mode, jobs, outdir, names):
        """One record per app of the batch, for --json and the exit status."""
        records = []
        for bundle, name in jobs:
            text, tag = self.status.get(bundle, ('', ''))
            path = None
            if tag in ('done', 'partial'):
                if mode == 'extract':
                    path = os.path.join(outdir, name + '.ipa')
                else:
                    kind = self.apps[bundle].get('verify', {}).get('type', ipa_verify.DECRYPTED)
                    path = os.path.join(outdir, names[bundle][kind] + '.ipa')
            verify = self.apps[bundle].get('verify')
            records.append(dict(bundle=bundle, ok=tag in ('done', 'partial'), status=tag or 'failed',
                                message=self.render(text), path=path,
                                verification=verify['status'] if verify else None))
        return records


# --------------------------------------------------------------------- commands
def table(rows, headers):
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    lines = ['  '.join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip() for row in [headers] + rows]
    return '\n'.join(lines)


def cmd_apps(cli):
    args = cli.args
    cli.connect()
    cli.load_apps()
    shown = cli.visible()
    if not args.no_info:
        cli.read_info(shown)
    records = []
    for app in shown:
        info = app.get('info', {})
        records.append(dict(name=app['name'], bundle=app['bundle'], version=app['version'], build=app['build'],
                            path=app['path'], user_app=core.is_user_app(app['path']), offloaded=bool(app.get('offloaded')),
                            encrypted=info.get('encrypted'), team_id=info.get('team_id', ''),
                            signer=info.get('signer', ''), developer=info.get('developer', '') or info.get('profile_team', '')))
    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return EXIT_OK
    rows = []
    for r in records:
        version = r['version']
        if r['build'] and r['build'] != version:
            version = '{} ({})'.format(version, r['build']) if version else r['build']
        rows.append((r['name'], r['bundle'], version, '' if r['encrypted'] is None else ('yes' if r['encrypted'] else 'no'),
                     r['team_id'], r['signer'], r['developer']))
    print(table(rows, ('NAME', 'BUNDLE ID', 'VERSION', 'ENCRYPTED', 'TEAM ID', 'SIGNER', 'DEVELOPER')))
    print('{} of {} apps'.format(len(records), len(cli.apps)), file=sys.stderr)
    return EXIT_OK


def finish(cli, mode, jobs, outdir, names):
    records = cli.results(mode, jobs, outdir, names)
    if cli.args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    elif not cli.quiet:
        for record in records:
            print('{}\t{}\t{}'.format('ok' if record['ok'] else 'failed', record['bundle'], record['path'] or record['message']))
    info = cli.finished or {}
    if cli.cancel_requested.is_set():
        return EXIT_CANCELLED
    if any(not r['ok'] for r in records):
        return EXIT_FAILED
    if info.get('partial'):
        return EXIT_PARTIAL
    return EXIT_OK


def cmd_devices(cli):
    try:
        devices = [usbmux.describe(device) for device in usbmux.list_devices()]
    except usbmux.UsbmuxError as error:
        raise CliError(str(error))
    if cli.args.json:
        print(json.dumps([dict(udid=d.serial, name=d.name, model=d.model, model_name=d.model_name, ios=d.version)
                          for d in devices], ensure_ascii=False, indent=2))
    else:
        for device in devices:      # tab separated, the UDID first: `cut -f1` gives what --udid takes
            print('\t'.join((device.serial, device.name, device.model_name,
                             device.version and 'iOS ' + device.version)).rstrip('\t'))
    if not devices:
        print('no device on USB', file=sys.stderr)
    return EXIT_OK if devices else EXIT_FAILED


def cmd_extract(cli):
    cli.connect()
    cli.load_apps()
    apps = cli.select('extract')
    jobs, outdir, names = cli.run_extract(apps)
    return finish(cli, 'extract', jobs, outdir, names)


def cmd_decrypt(cli):
    cli.connect()
    cli.load_apps()
    apps = cli.select('dump')
    jobs, outdir, names = cli.run_decrypt(apps)
    return finish(cli, 'dump', jobs, outdir, names)


def cmd_verify(cli):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    return ipa_verify.main(cli.args.files)


def cmd_install_frida(cli):
    args = cli.args
    version = args.version
    if args.list:
        for installed in frida_versions.installed():
            print(installed)
        return EXIT_OK
    if not version:
        cli.connect()
        version, running = core.frida_server_status(cli.ssh)
        if not version:
            raise CliError('frida-server is not installed on the device: name a version with --version')
    dump_dir = args.dump_dir
    if dump_dir:
        if core.dump_dir_status(dump_dir) not in ('ok', 'no_bridge'):
            raise CliError('{} is not a frida-ios-dump folder (see: install-frida-ios-dump)'.format(dump_dir))
    ok = cli.install_frida(version, dump_dir)
    if ok:
        cli.log(Text('log_frida_installed', version=version))
    return EXIT_OK if ok else EXIT_FAILED


def cmd_install_frida_ios_dump(cli):
    target = os.path.abspath(cli.args.folder or cli.settings['dump_dir'])
    if os.path.isdir(target) and os.listdir(target):
        if core.dump_dir_status(target) != 'missing':
            print('{} is already set up'.format(target), file=sys.stderr)
            return EXIT_OK
        raise CliError('{} is not empty and is not a frida-ios-dump folder'.format(target))
    cli.log(Text('log_downloading', path=target))
    try:
        core.download_frida_ios_dump(target, lambda line: cli.say('  ' + line))
    except Exception as error:
        raise CliError(cli.render(Text('log_download_failed', error=error)))
    cli.log(Text('log_download_done'))
    if cli.args.save:
        update_settings(dict(dump_dir=target))
    return EXIT_OK


# ----------------------------------------------------------------------- config
def convert_setting(key, text):
    """The value for a settings key from text; raises CliError when it is not valid for that key."""
    default = core.DEFAULTS[key]
    if isinstance(default, bool):
        try:
            return yes_no(text)
        except argparse.ArgumentTypeError as error:
            raise CliError('{}: {}'.format(key, error))
    if isinstance(default, int):
        try:
            return int(text)
        except ValueError:
            raise CliError('{} must be a number'.format(key))
    if key == 'dump_method':
        if text not in MODES.values():
            raise CliError('dump_method must be one of: ' + ', '.join(MODES.values()))
    elif key == 'frida_method':
        if text not in (core.METHOD_FRIDA_DIRECT, core.METHOD_FRIDA_IOS_DUMP):
            raise CliError('frida_method must be {} or {}'.format(core.METHOD_FRIDA_DIRECT, core.METHOD_FRIDA_IOS_DUMP))
    elif key == 'native_helper':
        if text not in (native_decrypt.AUTO, native_decrypt.MREMAP, native_decrypt.MEMORY):
            raise CliError('native_helper must be auto, mremap or memory')
    elif key == 'theme':
        if text not in core.THEMES:
            raise CliError('theme must be one of: ' + ', '.join(core.THEMES))
    elif key == 'connection':
        if text not in core.CONNECTIONS:
            raise CliError('connection must be one of: ' + ', '.join(core.CONNECTIONS))
    elif key == 'lang':
        if text != i18n.AUTO and text not in i18n.load_locales():
            raise CliError('lang must be auto or one of: ' + ', '.join(sorted(i18n.load_locales())))
    elif key in ('name_decrypted', 'name_original'):
        try:
            app_info.check_name_template(text)
        except app_info.NameTemplateError as error:
            raise CliError('{}: {} ({})'.format(key, error.args[0], error.args[1]))
    return text


def update_settings(changes, reset=()):
    """Write changes into the settings file the window uses. Keys that equal the default are not kept, like the window."""
    data = core.load_config()
    for key in reset:
        data.pop(key, None)
    for key, value in changes.items():
        if str(value) == str(core.DEFAULTS[key]):
            data.pop(key, None)
        else:
            data[key] = value
    core.save_config(data)


def cmd_config(cli):
    args = cli.args
    keys = sorted(core.DEFAULTS)
    if args.action == 'path':
        print(core.CONFIG_PATH)
    elif args.action == 'show':
        effective = dict(core.DEFAULTS)
        effective.update({k: v for k, v in core.load_config().items() if k in core.DEFAULTS})
        if args.json:
            print(json.dumps(effective, ensure_ascii=False, indent=2))
        else:
            saved = core.load_config()
            for key in keys:
                print('{} = {}{}'.format(key, json.dumps(effective[key], ensure_ascii=False),
                                         '' if key in saved else '   (default)'))
            if 'password' in saved:
                print('password = (saved)')
    elif args.action == 'keys':
        for key in keys:
            print('{}  (default {})'.format(key, json.dumps(core.DEFAULTS[key], ensure_ascii=False)))
    elif args.action == 'set':
        if len(args.items) != 2 or args.items[0] not in core.DEFAULTS:
            raise CliError('usage: config set KEY VALUE  (keys: config keys)')
        update_settings({args.items[0]: convert_setting(args.items[0], args.items[1])})
    elif args.action == 'reset':
        for key in args.items:
            if key not in core.DEFAULTS:
                raise CliError('unknown setting: ' + key)
        update_settings({}, reset=args.items)
    return EXIT_OK


# ------------------------------------------------------------------------ parser
def build_parser():
    parser = argparse.ArgumentParser(prog=PROG, description='Extract original or decrypted IPAs from a '
                                     'jailbroken iOS device over SSH. Shares settings.json with the window.')

    def common(p, after_command):
        # Accepted before and after the command; the one after must not overwrite what came before with a default.
        default = argparse.SUPPRESS if after_command else None
        p.add_argument('--settings', metavar='FILE', default=default,
                       help='settings file to use instead of the default one')
        p.add_argument('--lang', default=default,
                       help='language of the extraction messages (e.g. en, zh-TW); default: the setting')
        p.add_argument('-q', '--quiet', action='store_true', default=argparse.SUPPRESS if after_command else False,
                       help='print only errors and the result')

    common(parser, False)
    sub = parser.add_subparsers(dest='command', required=True, metavar='command')
    add_parser = sub.add_parser

    def add_command(*args, **kwargs):
        p = add_parser(*args, **kwargs)
        common(p, True)
        return p

    sub.add_parser = add_command

    def device(p):
        g = p.add_argument_group('device')
        g.add_argument('-H', '--host', help='device address (default: the setting)')
        g.add_argument('--usb', action='store_true', help='reach the device through the USB cable instead of the network '
                       '(default: the connection setting)')
        g.add_argument('--udid', metavar='UDID', help='the USB device (--usb is implied); with none, the attached one')
        g.add_argument('--ssh', action='store_true', help='reach the device over the network, whatever the setting says')
        g.add_argument('-P', '--port', help='SSH port (default: the setting, 22)')
        g.add_argument('-u', '--user', help='SSH account: root, or mobile on rootless jailbreaks (default: the setting)')
        g.add_argument('-p', '--password', help='SSH password; or set IPA_PASSWORD; or you are asked; or the saved one')

    def filters(p):
        g = p.add_argument_group('which apps count (defaults come from the settings)')
        g.add_argument('--user-only', dest='user_only', action='store_true', default=None, help='only apps installed by the user')
        g.add_argument('--include-system', dest='user_only', action='store_false', help='also system apps')
        g.add_argument('--non-apple', action='store_true', default=None, help='leave Apple apps out')
        g.add_argument('--encrypted-only', action='store_true', default=None, help='only apps that are FairPlay-encrypted')
        g.add_argument('--search', metavar='TEXT', help='apps whose name or bundle ID contains TEXT')

    p = sub.add_parser('apps', help='list the apps on the device')
    device(p)
    filters(p)
    p.add_argument('--no-info', action='store_true', help='skip reading signatures (faster; no encryption column)')
    p.add_argument('--json', action='store_true', help='print JSON')
    p.set_defaults(run=cmd_apps)

    def batch(p):
        device(p)
        filters(p)
        p.add_argument('bundles', nargs='*', metavar='BUNDLE_ID', help='apps to process')
        g = p.add_argument_group('more ways to pick apps (add to the bundle IDs given)')
        g.add_argument('--all', action='store_true', help='every app the filters let through')
        g.add_argument('--unextracted', action='store_true', help='apps with no IPA yet in the output folders')
        g.add_argument('--partial', action='store_true', help='apps whose decrypted IPA is still partly encrypted')
        g = p.add_argument_group('output')
        g.add_argument('-o', '--output', metavar='DIR', help='output folder (default: the settings)')
        g.add_argument('--name', metavar='TEMPLATE', help='file name template: {name} {bundle} {version} {build} {type}')
        g.add_argument('--overwrite', action='store_true', help='replace IPAs that exist')
        g.add_argument('--skip-existing', action='store_true', help='leave apps out whose IPA exists')
        g.add_argument('--json', action='store_true', help='print the results as JSON')

    p = sub.add_parser('devices', help='list the devices attached by USB (their UDIDs, for --udid)')
    p.add_argument('--json', action='store_true')
    p.set_defaults(run=cmd_devices)

    p = sub.add_parser('extract', help='extract original IPAs (no decryption)')
    batch(p)
    p.set_defaults(run=cmd_extract)

    p = sub.add_parser('decrypt', help='extract decrypted IPAs')
    batch(p)
    g = p.add_argument_group('decryption')
    g.add_argument('--mode', choices=sorted(MODES), help='native (no Frida), frida-direct or frida-ios-dump '
                   '(default: the setting; native)')
    g.add_argument('--helper', choices=['auto', 'mremap', 'memory'], help='native helper: auto picks by iOS version')
    g.add_argument('--frida-port', help='frida-server port on the device')
    g.add_argument('--dump-dir', metavar='DIR', help='frida-ios-dump folder')
    g.add_argument('--install-frida', action='store_true', help='install the matching frida when none is installed')
    g.add_argument('--repair', dest='repair', action='store_true', default=None,
                   help='frida-ios-dump: decrypt files it left encrypted (default: the setting)')
    g.add_argument('--no-repair', dest='repair', action='store_false')
    g.add_argument('--close-after', dest='close_after', action='store_true', default=None,
                   help='frida-ios-dump: close each app after decrypting it (default: the setting)')
    g.add_argument('--keep-open', dest='close_after', action='store_false')
    g.add_argument('--restart-frida', dest='restart_frida', action='store_true', default=None,
                   help='restart frida-server and retry on its errors (default: the setting)')
    g.add_argument('--no-restart-frida', dest='restart_frida', action='store_false')
    p.set_defaults(run=cmd_decrypt)

    p = sub.add_parser('verify', help='check IPAs: decrypted, partly encrypted ...')
    p.add_argument('files', nargs='+', metavar='IPA')
    p.set_defaults(run=cmd_verify)

    p = sub.add_parser('install-frida', help='install a frida version for the decrypt modes that use Frida')
    device(p)
    p.add_argument('--version', help='frida version (default: the one of the frida-server on the device)')
    p.add_argument('--dump-dir', metavar='DIR', help='also install what frida-ios-dump needs into this folder')
    p.add_argument('--list', action='store_true', help='list the installed versions')
    p.set_defaults(run=cmd_install_frida)

    p = sub.add_parser('install-frida-ios-dump', help='download frida-ios-dump')
    p.add_argument('folder', nargs='?', help='where to put it (default: the setting)')
    p.add_argument('--save', action='store_true', help='remember the folder in the settings')
    p.set_defaults(run=cmd_install_frida_ios_dump)

    p = sub.add_parser('config', help='show or change the settings the window shares')
    p.add_argument('action', choices=['show', 'set', 'reset', 'keys', 'path'])
    p.add_argument('items', nargs='*', metavar='KEY [VALUE]')
    p.add_argument('--json', action='store_true')
    p.set_defaults(run=cmd_config)
    return parser


def main(argv=None):
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.settings:
        core.CONFIG_PATH = os.path.abspath(args.settings)
    if core.paramiko is None and args.command in ('apps', 'extract', 'decrypt', 'install-frida'):
        print('paramiko is not installed: pip install "paramiko>=3" cryptography', file=sys.stderr)
        return EXIT_USAGE
    cli = Cli(args)
    previous = signal.signal(signal.SIGINT, lambda signum, frame: cli.cancel())
    try:
        return args.run(cli)
    except CliError as error:
        print('error: {}'.format(error), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print('interrupted', file=sys.stderr)
        return EXIT_CANCELLED
    finally:
        signal.signal(signal.SIGINT, previous)
        cli.close()


if __name__ == '__main__':
    sys.exit(main())
