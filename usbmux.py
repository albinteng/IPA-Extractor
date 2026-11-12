#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A small usbmuxd client: lists the iOS devices on USB and carries a TCP connection to a port on one of them.

usbmuxd is the service that already talks to iOS devices over USB: Apple's own on macOS and on Windows (installed
with iTunes or the Apple Devices app), the usbmuxd package on Linux. It is the same service iproxy uses. SSH over USB
is an ordinary SSH connection whose bytes travel through a usbmuxd Connect instead of the network, so a UsbTunnel
makes a local port that does that, and the rest of the tool connects to the local port as if it were the device.
Needs no window and no package outside the standard library.
"""

import json
import os
import plistlib
import socket
import struct
import sys
import threading


def load_models():
    """Marketing names by model identifier (iPhone12,1 -> iPhone 11) from device_models.json. Without the file, or
    when it cannot be read, no model has a name and the identifier is shown instead."""
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'device_models.json'), encoding='utf-8') as handle:
            names = json.load(handle)
    except (OSError, ValueError):
        return {}
    return {str(key): str(value) for key, value in names.items()} if isinstance(names, dict) else {}


MODELS = load_models()      # a model that is not listed shows its identifier: a newer device works without a change

PROGRAM = 'IPA Extractor'
WINDOWS_ADDRESS = ('127.0.0.1', 27015)
UNIX_ADDRESS = '/var/run/usbmuxd'
PLIST_VERSION = 1       # the protocol with plist messages
PLIST_MESSAGE = 8
TIMEOUT = 5
ASK_TIMEOUT = 2          # a device that does not answer lockdownd must not hold the device list up
LOCKDOWN_PORT = 62078       # lockdownd answers a few questions (name, model, version) before the device is paired



# The messages, English, by the key they have in the locale files (a test keeps the two the same): the window shows
# them in its language, the command line as they are.
MESSAGES = {
    'usb_err_unreachable': 'Cannot reach usbmuxd ({error}). {hint}',
    'usb_hint_win': 'Install iTunes or the Apple Devices app: they provide the Apple Mobile Device Service.',
    'usb_hint_mac': 'macOS provides usbmuxd; reconnect the device.',
    'usb_hint_linux': 'Install the usbmuxd package (for example "sudo apt install usbmuxd") and reconnect the device.',
    'usb_err_closed': 'usbmuxd closed the connection.',
    'usb_err_list': 'usbmuxd gave no device list ({error}).',
    'usb_err_absent': 'No USB device {serial}. Attached: {attached}.',
    'usb_err_absent_none': 'No USB device {serial}: none is attached.',
    'usb_err_none': 'No device on USB. Connect it with a cable, unlock it and tap Trust if it asks.',
    'usb_err_several': 'Several devices on USB ({devices}): choose one.',
    'usb_err_connect': 'usbmuxd could not connect ({error}).',
    'usb_err_port': 'Cannot connect to port {port} over USB: {reason}.',
    'usb_reason_gone': 'the device is gone',
    'usb_reason_noport': 'nothing listens on port {port} of the device (is SSH running?)',
    'usb_reason_refused': 'the device refused it',
    'usb_reason_other': 'usbmuxd answered {code}',
}


class UsbmuxError(Exception):
    """usbmuxd is not there, or refused. key names the message; params fill it (a param may be an UsbmuxError: a part
    of the message that has its own translation)."""

    def __init__(self, key, **params):
        self.key, self.params = key, params
        super().__init__(MESSAGES[key].format(**{name: str(value) for name, value in params.items()}))


def _hint():
    if sys.platform == 'win32':
        return UsbmuxError('usb_hint_win')
    if sys.platform == 'darwin':
        return UsbmuxError('usb_hint_mac')
    return UsbmuxError('usb_hint_linux')


def _address():
    """The usbmuxd address: USBMUXD_SOCKET_ADDRESS (as libusbmuxd reads it), else the platform's."""
    value = os.environ.get('USBMUXD_SOCKET_ADDRESS', '').strip()
    if value.upper().startswith('UNIX:'):
        return value[5:]
    if value and ':' in value:
        host, _, port = value.rpartition(':')
        if port.isdigit():
            return (host or '127.0.0.1', int(port))
    return WINDOWS_ADDRESS if sys.platform == 'win32' else UNIX_ADDRESS


def _open():
    address = _address()
    try:
        if isinstance(address, str):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect(address)
        else:
            sock = socket.create_connection(address, TIMEOUT)
    except (OSError, AttributeError) as error:      # AttributeError: no AF_UNIX
        raise UsbmuxError('usb_err_unreachable', error=error, hint=_hint())
    return sock


def _read(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise UsbmuxError('usb_err_closed')
        data += chunk
    return data


def _exchange(sock, message):
    """Send one plist message and return the plist usbmuxd answers with."""
    message = dict(message, ClientVersionString=PROGRAM, ProgName=PROGRAM)
    body = plistlib.dumps(message)
    sock.sendall(struct.pack('<IIII', 16 + len(body), PLIST_VERSION, PLIST_MESSAGE, 1) + body)
    length = struct.unpack('<IIII', _read(sock, 16))[0]
    return plistlib.loads(_read(sock, length - 16))


class Device:
    """A device usbmuxd lists: id (this plug-in's number) and serial (the UDID). describe() adds what it is called."""

    def __init__(self, device_id, serial, product=None):
        self.id, self.serial, self.product = device_id, serial, product
        self.name = self.model = self.version = ''      # the name the owner gave it, e.g. "iPhone12,1", "16.1.2"

    def __repr__(self):
        return 'Device({}, {})'.format(self.id, self.serial)

    @property
    def model_name(self):
        """"iPhone 11" for iPhone12,1; the identifier itself when it is not one we know."""
        return MODELS.get(self.model, self.model)

    def label(self):
        """What to show a person: "Didi iPhone 11 - iPhone 11, iOS 16.1.2 (00008030-0014394602E0802E)", as much of
        it as is known, the UDID last."""
        what = ', '.join(part for part in (self.model_name, 'iOS ' + self.version if self.version else '') if part)
        text = ' - '.join(part for part in (self.name, what) if part)
        return '{} ({})'.format(text, self.serial) if text else self.serial


def list_devices():
    """The devices attached by USB (usbmuxd also lists the ones it only knows from Wi-Fi sync)."""
    sock = _open()
    try:
        answer = _exchange(sock, {'MessageType': 'ListDevices'})
    except (OSError, plistlib.InvalidFileException, struct.error, ValueError) as error:
        raise UsbmuxError('usb_err_list', error=error)
    finally:
        sock.close()
    devices = []
    for entry in answer.get('DeviceList', []):
        properties = entry.get('Properties', {})
        if properties.get('ConnectionType', 'USB') == 'USB' and properties.get('SerialNumber'):
            devices.append(Device(entry.get('DeviceID'), properties['SerialNumber'], properties.get('ProductID')))
    return devices


def describe(device):
    """Fill in the device's name, model and iOS version from lockdownd; quietly leaves them empty when it will not say
    (a locked or untrusted device, an old iOS). Returns the device."""
    try:
        sock = connect(device, LOCKDOWN_PORT)
    except UsbmuxError:
        return device
    try:
        sock.settimeout(ASK_TIMEOUT)
        for key, attribute in (('DeviceName', 'name'), ('ProductType', 'model'), ('ProductVersion', 'version')):
            body = plistlib.dumps({'Label': PROGRAM, 'Request': 'GetValue', 'Key': key})
            sock.sendall(struct.pack('>I', len(body)) + body)
            answer = plistlib.loads(_read(sock, struct.unpack('>I', _read(sock, 4))[0]))
            value = answer.get('Value')
            if isinstance(value, str):
                setattr(device, attribute, value)
    except (OSError, UsbmuxError, plistlib.InvalidFileException, struct.error, ValueError):
        pass
    finally:
        sock.close()
    return device


def find(serial=''):
    """The device with this serial (UDID); with no serial, the one attached device."""
    devices = list_devices()
    if serial:
        for device in devices:
            if device.serial == serial:
                return device
        if devices:
            raise UsbmuxError('usb_err_absent', serial=serial, attached=', '.join(d.serial for d in devices))
        raise UsbmuxError('usb_err_absent_none', serial=serial)
    if not devices:
        raise UsbmuxError('usb_err_none')
    if len(devices) > 1:
        raise UsbmuxError('usb_err_several', devices=', '.join(d.serial for d in devices))
    return devices[0]


def connect(device, port):
    """A socket that is a TCP connection to port on the device; raises UsbmuxError when it refuses."""
    sock = _open()
    try:
        answer = _exchange(sock, {'MessageType': 'Connect', 'DeviceID': device.id,
                                  'PortNumber': socket.htons(port)})
    except (OSError, plistlib.InvalidFileException, struct.error, ValueError) as error:
        sock.close()
        raise UsbmuxError('usb_err_connect', error=error)
    result = answer.get('Number', -1)
    if result != 0:
        sock.close()
        reason = {2: 'usb_reason_gone', 3: 'usb_reason_noport', 5: 'usb_reason_refused'}.get(result, 'usb_reason_other')
        raise UsbmuxError('usb_err_port', port=port, reason=UsbmuxError(reason, port=port, code=result))
    sock.settimeout(None)
    return sock


def _pump(source, target):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (source, target):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class UsbTunnel:
    """127.0.0.1:local_port carries each connection to it through usbmuxd to device_port of the device (by serial)."""

    def __init__(self, serial, device_port):
        self.serial, self.device_port = serial, device_port
        self.device = find(serial)      # fails early, with the reason, when there is nothing to connect to
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(8)
        self.server.settimeout(0.2)     # accept() must not hold the port after close(): Linux keeps it open meanwhile
        self.local_port = self.server.getsockname()[1]
        self.sockets = set()
        self.lock = threading.Lock()
        self.closed = False
        self.last_error = None          # why the device could not be reached, for the one who sees SSH fail
        self.acceptor = threading.Thread(target=self._accept, daemon=True)
        self.acceptor.start()

    def _accept(self):
        try:
            while not self.closed:
                try:
                    client, _ = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                client.settimeout(None)
                threading.Thread(target=self._serve, args=(client,), daemon=True).start()
        finally:
            self.server.close()

    def _serve(self, client):
        try:
            try:
                remote = connect(self.device, self.device_port)
            except UsbmuxError:
                self.device = find(self.serial)     # re-plugged: the device has a new number
                remote = connect(self.device, self.device_port)
        except UsbmuxError as error:
            self.last_error = error     # SSH only sees a closed connection; this says why (no sshd, a locked device...)
            client.close()
            return
        self.last_error = None
        with self.lock:
            if self.closed:
                client.close()
                remote.close()
                return
            self.sockets.update((client, remote))
        threading.Thread(target=_pump, args=(remote, client), daemon=True).start()
        _pump(client, remote)
        with self.lock:
            self.sockets.difference_update((client, remote))
        client.close()
        remote.close()

    def close(self):
        self.closed = True
        if threading.current_thread() is not self.acceptor:
            self.acceptor.join(2)       # it closes the listening socket
        with self.lock:
            sockets, self.sockets = list(self.sockets), set()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)     # close() alone leaves a connection a thread is reading from open
            except OSError:
                pass
            sock.close()
