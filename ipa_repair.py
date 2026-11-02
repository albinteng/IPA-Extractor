# -*- coding: utf-8 -*-
"""Replace still-encrypted files of a decrypted IPA with copies decrypted on the device (R2).

The device side runs in repair_worker.py (child process with the matching frida); this module
plans which ranges to decrypt and writes the results back into the IPA. It never loads frida.
"""

import os
import posixpath
import shutil
import struct
import zipfile

import ipa_verify

CHUNK = 1024 * 1024


class Job:
    """One still-encrypted file: its IPA member, its path on the device and the slices to decrypt."""

    def __init__(self, index, member, device_path, slices):
        self.id = str(index)
        self.member = member
        self.device_path = device_path
        self.slices = slices  # ipa_verify.Slice, encrypted ones only
        self.error = None     # why the file was not repaired, once known
        self.done = set()     # indexes of decrypted slices
        self.slice_errors = {}  # index -> error text from the device

    def to_json(self):
        return dict(id=self.id, path=self.device_path,
                    slices=[dict(offset=s.offset, cryptoff=s.cryptoff, cryptsize=s.cryptsize, cryptid=s.cryptid,
                                 cpu=s.cpu, subtype=s.subtype) for s in self.slices])

    @property
    def repaired(self):
        return self.error is None and len(self.done) == len(self.slices)


def plan(result, app_path):
    """Jobs for every encrypted file in an ipa_verify.Result; app_path is the .app on the device."""
    jobs = []
    for file_result in result.encrypted:
        if file_result.error:
            continue  # unreadable in the IPA, so there is nothing to patch
        inner = ipa_verify.short_name(file_result.name)
        if inner == file_result.name:
            continue  # outside Payload/X.app (e.g. iTunesMetadata): not part of the installed bundle
        slices = [s for s in file_result.slices if s.encrypted]
        jobs.append(Job(len(jobs), file_result.name, posixpath.join(app_path.rstrip('/'), inner), slices))
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
