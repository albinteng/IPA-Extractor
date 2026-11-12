"""The usbmuxd client against a fake usbmuxd, and the USB connection around it."""
import json
import os
import plistlib
import re
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

import engine
import ipa_cli
import usbmux

UDID = '00008030-0014394602E0802E'


class FakeUsbmuxd:
    """Answers ListDevices and Connect like usbmuxd. A Connect to a port in `ports` becomes an echo of the device."""

    def __init__(self, devices, ports=(22,)):
        self.devices, self.ports = devices, ports
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(8)
        self.address = '127.0.0.1:{}'.format(self.server.getsockname()[1])
        self.connects = []
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                client, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def read(self, client, size):
        data = b''
        while len(data) < size:
            chunk = client.recv(size - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def reply(self, client, message):
        body = plistlib.dumps(message)
        client.sendall(struct.pack('<IIII', 16 + len(body), 1, 8, 1) + body)

    def serve(self, client):
        try:
            length, version, kind, _ = struct.unpack('<IIII', self.read(client, 16))
            assert (version, kind) == (1, 8)
            message = plistlib.loads(self.read(client, length - 16))
            if message['MessageType'] == 'ListDevices':
                self.reply(client, {'DeviceList': self.devices})
                client.close()
                return
            port = socket.ntohs(message['PortNumber'])
            self.connects.append((message['DeviceID'], port))
            known = any(d['DeviceID'] == message['DeviceID'] for d in self.devices)
            self.reply(client, {'MessageType': 'Result', 'Number': 0 if known and port in self.ports else 3 if known else 2})
            if known and port in self.ports and port == usbmux.LOCKDOWN_PORT and hasattr(self, 'lockdown_answers'):
                while True:
                    size = struct.unpack('>I', self.read(client, 4))[0]
                    request = plistlib.loads(self.read(client, size))
                    body = plistlib.dumps({'Request': 'GetValue', 'Key': request['Key'],
                                           'Value': self.lockdown_answers[request['Key']]})
                    client.sendall(struct.pack('>I', len(body)) + body)
            elif known and port in self.ports:
                while True:
                    data = client.recv(4096)
                    if not data:
                        break
                    client.sendall(data)
            client.close()
        except (EOFError, OSError):
            client.close()

    def close(self):
        self.server.close()


def entry(device_id, serial, kind='USB'):
    return {'DeviceID': device_id, 'MessageType': 'Attached',
            'Properties': {'DeviceID': device_id, 'SerialNumber': serial, 'ConnectionType': kind, 'ProductID': 4776}}


class UsbmuxTests(unittest.TestCase):
    def start(self, devices, **kwargs):
        fake = FakeUsbmuxd(devices, **kwargs)
        self.addCleanup(fake.close)
        patcher = mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': fake.address})
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    def test_only_usb_devices_are_listed(self):
        self.start([entry(1, UDID), entry(2, 'WIFI-ONLY', 'Network')])
        self.assertEqual([d.serial for d in usbmux.list_devices()], [UDID])

    def test_find_takes_the_one_device_or_the_serial_asked_for(self):
        self.start([entry(1, UDID)])
        self.assertEqual(usbmux.find().id, 1)
        self.assertEqual(usbmux.find(UDID).serial, UDID)
        with self.assertRaisesRegex(usbmux.UsbmuxError, 'No USB device OTHER'):
            usbmux.find('OTHER')

    def test_find_says_when_there_is_none_or_several(self):
        self.start([])
        with self.assertRaisesRegex(usbmux.UsbmuxError, 'No device on USB'):
            usbmux.find()
        self.start([entry(1, 'A'), entry(2, 'B')])
        with self.assertRaisesRegex(usbmux.UsbmuxError, 'Several devices'):
            usbmux.find()
        self.assertEqual(usbmux.find('B').id, 2)

    def test_a_missing_usbmuxd_says_how_to_get_one(self):
        free = socket.socket()
        free.bind(('127.0.0.1', 0))
        port = free.getsockname()[1]
        free.close()
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': '127.0.0.1:{}'.format(port)}):
            with self.assertRaisesRegex(usbmux.UsbmuxError, 'Cannot reach usbmuxd'):
                usbmux.list_devices()

    def test_the_address_comes_from_the_variable_else_from_the_platform(self):
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'UNIX:/tmp/x.sock'}):
            self.assertEqual(usbmux._address(), '/tmp/x.sock')
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': '10.0.0.2:5555'}):
            self.assertEqual(usbmux._address(), ('10.0.0.2', 5555))
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': ':5555'}):
            self.assertEqual(usbmux._address(), ('127.0.0.1', 5555))
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': 'nonsense'}):
            with mock.patch.object(usbmux.sys, 'platform', 'win32'):
                self.assertEqual(usbmux._address(), ('127.0.0.1', 27015))
            with mock.patch.object(usbmux.sys, 'platform', 'darwin'):
                self.assertEqual(usbmux._address(), '/var/run/usbmuxd')
            with mock.patch.object(usbmux.sys, 'platform', 'linux'):
                self.assertEqual(usbmux._address(), '/var/run/usbmuxd')

    def test_the_hint_for_a_missing_usbmuxd_is_the_one_of_the_platform(self):
        for platform, key in (('win32', 'usb_hint_win'), ('darwin', 'usb_hint_mac'), ('linux', 'usb_hint_linux')):
            with mock.patch.object(usbmux.sys, 'platform', platform):
                self.assertEqual(usbmux._hint().key, key)

    @unittest.skipUnless(os.environ.get('IPA_REAL_USBMUXD'), 'set IPA_REAL_USBMUXD=1 where usbmuxd runs (see the workflow)')
    def test_the_real_usbmuxd_answers_the_device_list(self):
        """Against the daemon of this system (macOS always has one; Linux with the usbmuxd package running): the list
        has no device on a build machine, but the framing must be one the real daemon accepts."""
        for variable in ('USBMUXD_SOCKET_ADDRESS',):
            os.environ.pop(variable, None)
        devices = usbmux.list_devices()
        self.assertIsInstance(devices, list)

    def test_connect_carries_bytes_to_the_port_and_refuses_a_closed_one(self):
        fake = self.start([entry(7, UDID)], ports=(22,))
        device = usbmux.find()
        sock = usbmux.connect(device, 22)
        sock.sendall(b'SSH-2.0-test')
        self.assertEqual(sock.recv(64), b'SSH-2.0-test')
        sock.close()
        with self.assertRaisesRegex(usbmux.UsbmuxError, 'port 2222.*nothing listens'):
            usbmux.connect(device, 2222)
        self.assertEqual(fake.connects, [(7, 22), (7, 2222)])      # the port goes over the wire in network byte order

    def test_the_tunnel_is_a_local_port_that_reaches_the_device(self):
        fake = self.start([entry(7, UDID)], ports=(22,))
        tunnel = usbmux.UsbTunnel('', 22)
        self.addCleanup(tunnel.close)
        client = socket.create_connection(('127.0.0.1', tunnel.local_port), 5)
        client.sendall(b'hello over usb')
        self.assertEqual(client.recv(64), b'hello over usb')
        client.close()
        self.assertEqual(fake.connects[-1], (7, 22))

    def test_the_tunnel_refuses_to_start_without_a_device(self):
        self.start([])
        with self.assertRaises(usbmux.UsbmuxError):
            usbmux.UsbTunnel('', 22)

    def test_closing_the_tunnel_ends_its_connections(self):
        self.start([entry(7, UDID)])
        tunnel = usbmux.UsbTunnel(UDID, 22)
        client = socket.create_connection(('127.0.0.1', tunnel.local_port), 5)
        client.sendall(b'x')
        client.recv(8)
        tunnel.close()
        client.settimeout(5)
        try:
            self.assertEqual(client.recv(8), b'')       # the far end is gone: end of data, or a reset on Windows
        except ConnectionResetError:
            pass
        client.close()
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', tunnel.local_port), 1)


class NamesTests(unittest.TestCase):
    """lockdownd answers GetValue for the name, model and version before the device is paired."""

    def test_the_label_names_the_device_and_ends_with_the_whole_udid(self):
        device = usbmux.Device(1, UDID)
        self.assertEqual(device.label(), UDID)      # nothing known: the UDID itself
        device.name, device.model, device.version = 'Didi iPhone 11', 'iPhone12,1', '16.1.2'
        self.assertEqual(device.model_name, 'iPhone 11')
        self.assertEqual(device.label(), 'Didi iPhone 11 - iPhone 11, iOS 16.1.2 (00008030-0014394602E0802E)')
        device.model = 'iPad99,9'       # a model that is not in the table (yet): the identifier is shown
        self.assertEqual(device.model_name, 'iPad99,9')
        device.name = ''
        self.assertEqual(device.label(), 'iPad99,9, iOS 16.1.2 (00008030-0014394602E0802E)')
        for char in ('\u2014', '\u2026', '\uff08', '\uff09'):       # em dash, ellipsis, full-width parentheses
            self.assertNotIn(char, device.label())

    def test_a_missing_or_broken_model_file_leaves_the_identifiers(self):
        with mock.patch('builtins.open', side_effect=OSError('gone')):
            self.assertEqual(usbmux.load_models(), {})
        with mock.patch('json.load', side_effect=ValueError('broken')):
            self.assertEqual(usbmux.load_models(), {})
        with mock.patch('json.load', return_value=['not', 'a', 'dict']):
            self.assertEqual(usbmux.load_models(), {})
        with mock.patch.object(usbmux, 'MODELS', {}):
            device = usbmux.Device(1, UDID)
            device.model = 'iPhone12,1'
            self.assertEqual(device.model_name, 'iPhone12,1')

    def test_the_model_table_names_current_iphones_and_ipads_and_falls_back_to_the_identifier(self):
        MODELS = usbmux.MODELS
        for identifier, name in (('iPhone8,1', 'iPhone 6s'), ('iPhone12,1', 'iPhone 11'), ('iPhone17,3', 'iPhone 16'),
                                 ('iPhone18,3', 'iPhone 17'), ('iPhone18,4', 'iPhone Air'), ('iPhone19,2', 'iPhone 18 Pro'),
                                 ('iPhone19,4', 'iPhone Duo'), ('iPad7,1', 'iPad Pro 2 (12.9-inch)'),
                                 ('iPad13,18', 'iPad (10th generation)'), ('iPad17,3', 'iPad Pro 13-inch (M5)')):
            self.assertEqual(MODELS[identifier], name)
        # one name for the variants of a model: no radio or region words
        for name in MODELS.values():
            for word in ('WiFi', 'Cellular', 'GSM', 'CDMA', 'Global'):
                self.assertNotIn(word, name)
        device = usbmux.Device(1, UDID)
        device.model = 'iPhone99,1'
        self.assertEqual(device.model_name, 'iPhone99,1')       # not known: the identifier, as the device reports it

    def test_describe_reads_name_model_and_version_from_lockdownd(self):
        answers = {'DeviceName': 'Didi iPhone 11', 'ProductType': 'iPhone12,1', 'ProductVersion': '16.1.2'}
        fake = FakeUsbmuxd([entry(7, UDID)], ports=(usbmux.LOCKDOWN_PORT,))
        self.addCleanup(fake.close)
        fake.lockdown_answers = answers
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': fake.address}):
            device = usbmux.describe(usbmux.find())
        self.assertEqual((device.name, device.model, device.version), ('Didi iPhone 11', 'iPhone12,1', '16.1.2'))

    def test_a_device_that_will_not_say_stays_unnamed(self):
        fake = FakeUsbmuxd([entry(7, UDID)], ports=())       # nothing listens on the lockdown port
        self.addCleanup(fake.close)
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': fake.address}):
            device = usbmux.describe(usbmux.find())
        self.assertEqual((device.name, device.model, device.version), ('', '', ''))
        self.assertEqual(device.label(), UDID)


class ConnectionTests(unittest.TestCase):
    def test_ssh_is_the_default_and_unknown_values_mean_ssh(self):
        self.assertEqual(engine.DEFAULTS['connection'], 'ssh')
        self.assertEqual(engine.DEFAULTS['usb_device'], '')
        for value in ('ssh', 'usb'):
            self.assertEqual(engine.connection_setting(value), value)
        for bad in ('', 'wifi', None, 3):
            self.assertEqual(engine.connection_setting(bad), 'ssh')

    def test_the_network_goes_to_the_host_and_usb_to_the_local_end_of_the_tunnel(self):
        client = object()
        with mock.patch.object(engine, 'open_ssh', return_value=client) as ssh, \
                mock.patch.object(engine.usbmux, 'UsbTunnel') as tunnel:
            self.assertEqual(engine.open_device('ssh', '10.0.0.5', 22, 'root', 'pw', print), (client, ('10.0.0.5', 22), None))
            tunnel.assert_not_called()
            tunnel.return_value.local_port = 5555
            result = engine.open_device('usb', '', 22, 'mobile', 'pw', print, usb_device=UDID)
            tunnel.assert_called_once_with(UDID, 22)
            self.assertEqual(result, (client, ('127.0.0.1', 5555), tunnel.return_value))
            ssh.assert_called_with('127.0.0.1', 5555, 'mobile', 'pw', print)

    def test_when_the_device_port_is_closed_the_error_says_why_not_that_ssh_got_no_banner(self):
        fake = FakeUsbmuxd([entry(1, UDID)], ports=())          # the device answers, nothing listens on its SSH port
        self.addCleanup(fake.close)

        def login(host, port, *rest):
            sock = socket.create_connection((host, port))       # what SSH does: it finds the connection closed
            sock.settimeout(5)
            sock.recv(16)
            sock.close()
            raise RuntimeError('Error reading SSH protocol banner')
        with mock.patch.dict(os.environ, {'USBMUXD_SOCKET_ADDRESS': fake.address}),                 mock.patch.object(engine, 'open_ssh', side_effect=login):
            with self.assertRaises(usbmux.UsbmuxError) as caught:
                engine.open_device('usb', '', 22, 'mobile', 'pw', print, usb_device=UDID)
        self.assertEqual(caught.exception.key, 'usb_err_port')
        self.assertEqual(caught.exception.params['reason'].key, 'usb_reason_noport')

    def test_a_failed_login_over_usb_closes_the_tunnel(self):
        with mock.patch.object(engine, 'open_ssh', side_effect=RuntimeError('no')), \
                mock.patch.object(engine.usbmux, 'UsbTunnel') as tunnel:
            with self.assertRaises(RuntimeError):
                engine.open_device('usb', '', 22, 'mobile', 'pw', print)
            tunnel.return_value.close.assert_called_once()


def make_cli(*argv, settings=None):
    folder = tempfile.mkdtemp(prefix='usb-test-')
    path = os.path.join(folder, 'settings.json')
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(settings or {}, handle)
    with mock.patch.object(engine, 'CONFIG_PATH', path):
        return ipa_cli.Cli(ipa_cli.build_parser().parse_args(list(argv)))


class CommandLineTests(unittest.TestCase):
    def test_the_connection_comes_from_the_options_then_the_settings(self):
        self.assertEqual(make_cli('apps').connection_mode(), ('ssh', ''))
        self.assertEqual(make_cli('apps', '--usb').connection_mode(), ('usb', ''))
        self.assertEqual(make_cli('apps', '--udid', UDID).connection_mode(), ('usb', UDID))
        saved = dict(connection='usb', usb_device=UDID)
        self.assertEqual(make_cli('apps', settings=saved).connection_mode(), ('usb', UDID))
        self.assertEqual(make_cli('apps', '--ssh', settings=saved).connection_mode(), ('ssh', ''))
        self.assertEqual(make_cli('apps', '--udid', 'OTHER', settings=saved).connection_mode(), ('usb', 'OTHER'))

    def test_usb_needs_no_host(self):
        cli = make_cli('apps', '--usb', '-u', 'mobile', '-p', 'x')
        self.assertEqual(cli.connection()[2:], ('mobile', 'x'))
        with self.assertRaisesRegex(ipa_cli.CliError, 'no device address'):
            make_cli('apps', '-u', 'mobile', '-p', 'x').connection()

    def test_connect_over_usb_records_where_ssh_really_goes(self):
        cli = make_cli('apps', '--udid', UDID, '-u', 'mobile', '-p', 'x')
        cli.say = lambda message: None
        tunnel = mock.Mock()
        with mock.patch.object(engine, 'open_device', return_value=(mock.Mock(), ('127.0.0.1', 4321), tunnel)) as opened:
            cli.connect()
        self.assertEqual((cli.host, cli.port), ('127.0.0.1', 4321))     # frida-ios-dump connects there
        self.assertEqual(opened.call_args[0][0], 'usb')
        self.assertEqual(opened.call_args[1]['usb_device'], UDID)
        cli.close()
        tunnel.close.assert_called_once()

    def test_the_devices_command_lists_the_udids(self):
        import contextlib
        import io
        out = io.StringIO()
        with mock.patch.object(usbmux, 'list_devices', return_value=[usbmux.Device(1, UDID)]), \
                contextlib.redirect_stdout(out):
            self.assertEqual(ipa_cli.cmd_devices(make_cli('devices')), 0)
        self.assertEqual(out.getvalue().split(), [UDID])
        with mock.patch.object(usbmux, 'list_devices', return_value=[]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ipa_cli.cmd_devices(make_cli('devices')), 1)

    def test_the_connection_setting_takes_ssh_or_usb(self):
        self.assertEqual(ipa_cli.convert_setting('connection', 'usb'), 'usb')
        with self.assertRaises(ipa_cli.CliError):
            ipa_cli.convert_setting('connection', 'wifi')


class MessageTests(unittest.TestCase):
    def test_every_message_is_in_every_language_and_english_matches_the_locale_file(self):
        import i18n
        locales = i18n.load_locales()
        for key, english in usbmux.MESSAGES.items():
            self.assertEqual(locales['en'][key], english, key)          # the text the command line prints
            for code, strings in locales.items():
                self.assertTrue(strings.get(key), (code, key))
                self.assertEqual(sorted(re.findall(r'\{(\w+)\}', strings[key])),
                                 sorted(re.findall(r'\{(\w+)\}', english)), (code, key))

    def test_an_error_becomes_a_translatable_text_with_its_parts(self):
        error = usbmux.UsbmuxError('usb_err_port', port=22, reason=usbmux.UsbmuxError('usb_reason_noport', port=22, code=3))
        text = engine.error_text(error)
        self.assertEqual((text.key, text.params['port']), ('usb_err_port', 22))
        self.assertEqual((text.params['reason'].key, text.params['reason'].params['port']), ('usb_reason_noport', 22))
        self.assertEqual(str(error), 'Cannot connect to port 22 over USB: nothing listens on port 22 of the device (is SSH running?).')
        other = ValueError('x')
        self.assertIs(engine.error_text(other), other)

    def test_the_window_logs_an_usb_error_in_its_language(self):
        import i18n
        locales = i18n.load_locales()
        error = usbmux.UsbmuxError('usb_err_none')
        cli = make_cli('apps', '--lang', 'zh-TW')
        self.assertEqual(cli.render(engine.error_text(error)), locales['zh-TW']['usb_err_none'])


class LanguageTests(unittest.TestCase):
    def test_every_language_names_the_connection_choices(self):
        import i18n
        for code, strings in i18n.load_locales().items():
            for key in ('connection', 'conn_ssh', 'conn_usb', 'usb_device', 'usb_refresh', 'tab_connection',
                        'connection_help', 'log_ready_usb', 'usb_none', 'conn_ssh_tip', 'conn_usb_tip'):
                self.assertTrue(strings.get(key), (code, key))
            self.assertNotEqual(strings['conn_ssh'], strings['conn_usb'], code)


if __name__ == '__main__':
    unittest.main()
