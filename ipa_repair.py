# -*- coding: utf-8 -*-
"""Replace still-encrypted files of an IPA with copies decrypted on the device.

Used to finish frida-ios-dump IPAs (R2) and to decrypt a copied bundle without launching the
app (R4). The device side runs in repair_worker.py (child process with the matching frida); this
module plans which ranges to decrypt and writes the results back into the IPA. It never loads frida.
"""

import os
import plistlib
import posixpath
import re
import shutil
import struct
import zipfile

import ipa_verify

CHUNK = 1024 * 1024
STALLED = 'no response from the device for {} s'
# Errors after which frida-server was gone rather than the file undecryptable.
# Any frida TransportError (closed, reset, aborted, timed out: worded differently on each OS) is one.
CONNECTION_ERRORS = ('transporterror', 'connection is closed', 'connection was forcibly closed', 'connection reset',
                     'connection was aborted', 'lost the connection', 'unable to connect', 'connection refused',
                     'timeout was reached', STALLED.split('{')[0])


class Job:
    """One still-encrypted file: its IPA member, its path on the device and the slices to decrypt."""

    def __init__(self, index, member, device_path, slices, kind='other', extension=None, min_os=''):
        self.id = str(index)
        self.member = member
        self.device_path = device_path
        self.slices = slices  # ipa_verify.Slice, encrypted ones only
        self.kind = kind      # main, appex, framework, watch or other (see kind())
        self.extension = extension  # bundle ID of the app extension whose executable this is
        self.min_os = min_os        # MinimumOSVersion of the bundle the file belongs to
        self.error = None     # why the file was not repaired, once known
        self.done = set()     # indexes of decrypted slices
        self.slice_errors = {}  # index -> error text from the device
        self.slice_paths = {}   # index -> private copy of the file on the device (see Job.to_json)

    def to_json(self):
        # suffix finds the image in a process, whichever form (/var or /private/var) the path takes there.
        app_dir = '/' + self.member.split('/')[1]
        return dict(id=self.id, path=self.device_path, kind=self.kind, extension=self.extension,
                    suffix=app_dir + '/' + ipa_verify.short_name(self.member),
                    slices=[dict(offset=s.offset, cryptoff=s.cryptoff, cryptsize=s.cryptsize, cryptid=s.cryptid,
                                 cpu=s.cpu, subtype=s.subtype,
                                 **({'path': self.slice_paths[i]} if i in self.slice_paths else {}))
                            for i, s in enumerate(self.slices)])

    @property
    def repaired(self):
        return self.error is None and len(self.done) == len(self.slices)

    def untried(self):
        """Whether some slice has neither been decrypted nor failed."""
        return len(self.done) + len(self.slice_errors) < len(self.slices)

    def connection_lost(self):
        texts = list(self.slice_errors.values()) + ([self.error[1]] if self.error else [])
        return any(needle in text.lower() for text in texts for needle in CONNECTION_ERRORS)

    def reset(self):
        """Forget the failures (not the decrypted slices) before trying again."""
        self.error = None
        self.slice_errors = {}


def version_tuple(version):
    """(16, 1, 2) for '16.1.2' or 'iPhone OS 16.1.2'; () when there is no version."""
    match = re.search(r'(\d+(?:\.\d+)*)\s*$', version or '')
    return tuple(int(part) for part in match.group(1).split('.')) if match else ()


def kind(inner, executables):
    """What a file inside the .app is: main (the app's executable), appex (an app extension's
    executable), framework (framework or dylib), watch (anything in the Watch app) or other.
    executables maps bundle folders inside the .app ('' for the app itself) to their executable."""
    if inner.startswith('Watch/'):
        return 'watch'
    # Before the executables: a framework's Info.plist names its executable too.
    if '.framework/' in inner or inner.endswith('.dylib'):
        return 'framework'
    folder, name = posixpath.split(inner)
    if executables.get(folder) == name:
        return 'main' if folder == '' else ('appex' if folder.endswith('.appex') else 'other')
    return 'other'


def _bundles(archive, app_prefix):
    """{folder inside the .app: (CFBundleExecutable, CFBundleIdentifier, MinimumOSVersion)} from the IPA's
    Info.plists."""
    bundles = {}
    for name in archive.namelist():
        if not (name.startswith(app_prefix) and name.endswith('/Info.plist') or name == app_prefix + 'Info.plist'):
            continue
        folder = posixpath.dirname(name[len(app_prefix):])
        if folder and not folder.endswith(('.appex', '.app', '.framework')):
            continue
        try:
            info = plistlib.loads(archive.read(name))
        except Exception:
            continue
        if isinstance(info, dict):
            bundles[folder] = (info.get('CFBundleExecutable'), info.get('CFBundleIdentifier'),
                               str(info.get('MinimumOSVersion') or ''))
    return bundles


def plan(result, app_path, archive_path=None):
    """Jobs for every encrypted file in an ipa_verify.Result; app_path is the .app on the device.
    archive_path (the IPA) tells executables apart from other Mach-O files."""
    bundles = {}
    if archive_path and result.files:
        app_prefix = '/'.join(result.files[0].name.split('/')[:2]) + '/'
        with zipfile.ZipFile(archive_path) as archive:
            bundles = _bundles(archive, app_prefix)
    executables = {folder: executable for folder, (executable, _, _) in bundles.items()}
    jobs = []
    for file_result in result.encrypted:
        if file_result.error:
            continue  # unreadable in the IPA, so there is nothing to patch
        inner = ipa_verify.short_name(file_result.name)
        if inner == file_result.name:
            continue  # outside Payload/X.app (e.g. iTunesMetadata): not part of the installed bundle
        slices = [s for s in file_result.slices if s.encrypted]
        what = kind(inner, executables)
        _, identifier, min_os = bundles.get(posixpath.dirname(inner), (None, None, ''))
        jobs.append(Job(len(jobs), file_result.name, posixpath.join(app_path.rstrip('/'), inner), slices,
                        what, identifier if what == 'appex' else None, min_os))
    return jobs


def check_sizes(sftp, jobs, archive_path):
    """R5: the file on the device must be the very file in the IPA; mark jobs whose size differs."""
    with zipfile.ZipFile(archive_path) as archive:
        for job in jobs:
            size = archive.getinfo(job.member).file_size
            try:
                device_size = sftp.stat(job.device_path).st_size
            except OSError as error:
                job.error = ('missing', str(error))
                continue
            if device_size != size:
                job.error = ('mismatch', '{} != {}'.format(device_size, size))


def _patched(data, job, results_dir):
    data = bytearray(data)
    for index, slice_ in enumerate(job.slices):
        if index not in job.done:
            continue
        with open(os.path.join(results_dir, '{}_{}.bin'.format(job.id, index)), 'rb') as handle:
            decrypted = handle.read()
        start = slice_.offset + slice_.cryptoff
        if len(decrypted) != slice_.cryptsize or start + slice_.cryptsize > len(data):
            raise ValueError('decrypted range does not fit {}'.format(job.member))
        data[start:start + slice_.cryptsize] = decrypted
        struct.pack_into('<I', data, slice_.cryptid_at, 0)
    return bytes(data)


def apply(ipa_path, jobs, results_dir):
    """Rewrite the IPA with every decrypted slice patched in (cryptid set to 0).

    Members keep their order, names, dates, permissions and compression. Returns the number of
    files changed; the IPA is replaced only once the new one is complete.
    """
    changed = {job.member: job for job in jobs if job.done and job.error is None}
    if not changed:
        return 0
    part = ipa_path + '.repair.part'
    try:
        with zipfile.ZipFile(ipa_path) as source, zipfile.ZipFile(part, 'w', allowZip64=True) as target:
            for info in source.infolist():
                out = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                out.external_attr, out.create_system = info.external_attr, info.create_system
                out.compress_type = info.compress_type
                if info.filename in changed:
                    target.writestr(out, _patched(source.read(info), changed[info.filename], results_dir))
                    continue
                with source.open(info) as reader, target.open(out, 'w', force_zip64=info.file_size > 0x7FFFFFFF) as writer:
                    shutil.copyfileobj(reader, writer, CHUNK)
        os.replace(part, ipa_path)
    except BaseException:
        try:
            os.remove(part)
        except OSError:
            pass
        raise
    return len(changed)
