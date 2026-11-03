#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copy an installed app off a jailbroken device as an IPA without decrypting it.

The bundle is streamed with tar over SSH and repacked into the IPA zip on this computer,
so nothing is written on the device and deep bundle paths never touch the Windows file system.
App Store binaries stay FairPlay-encrypted: the IPA keeps its SC_Info and iTunesMetadata.plist,
so it reinstalls on devices signed in with the purchasing Apple ID (or with AppSync).
"""

import os
import posixpath
import shlex
import shutil
import stat
import tarfile
import time
import zipfile

import remote

CHUNK = 1024 * 1024
# Stored next to the .app in the bundle container and at the root of an App Store IPA.
METADATA_FILES = ('iTunesMetadata.plist', 'iTunesArtwork')


class Cancelled(Exception):
    pass


class _CountingReader:
    """File-like wrapper over the SSH stream that reports bytes read and honours cancel."""

    def __init__(self, stream, on_read, cancelled):
        self.stream = stream
        self.on_read = on_read
        self.cancelled = cancelled
        self.count = 0

    def read(self, size=-1):
        if self.cancelled():
            raise Cancelled()
        data = self.stream.read(size)
        self.count += len(data)
        self.on_read(self.count)
        return data


def _zip_info(name, member):
    info = zipfile.ZipInfo(name, date_time=_date_time(member.mtime))
    info.create_system = 3  # Unix, so permissions and symlinks survive
    mode = member.mode & 0o7777
    if member.isdir():
        info.external_attr = ((stat.S_IFDIR | mode) << 16) | 0x10
    elif member.issym():
        info.external_attr = (stat.S_IFLNK | 0o755) << 16
    else:
        info.external_attr = (stat.S_IFREG | mode) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _date_time(mtime):
    t = time.localtime(max(mtime, 315532800))  # zip cannot store dates before 1980
    return t[:6]


def extract_ipa(client, app_path, dest, progress=None, cancelled=None, metadata=True):
    """Write the bundle at app_path (…/Bundle/Application/<UUID>/X.app) to dest as an IPA.

    progress(done_bytes, total_bytes) is called while streaming; cancelled() aborts with Cancelled.
    metadata False leaves out iTunesMetadata.plist (it names the purchasing Apple ID) and iTunesArtwork,
    as decrypted IPAs do.
    """
    progress = progress or (lambda done, total: None)
    cancelled = cancelled or (lambda: False)
    container, app_dir = posixpath.split(app_path.rstrip('/'))
    q = shlex.quote
    names = [app_dir]
    _, output = remote.run(client, 'cd {} && ls -d {} 2>/dev/null; du -sk {}'.format(
        q(container), ' '.join(q(n) for n in METADATA_FILES), q(app_dir)), timeout=60)
    for line in output.splitlines():
        if metadata and line.strip() in METADATA_FILES:
            names.append(line.strip())
    try:
        total = int(output.splitlines()[-1].split()[0]) * 1024
    except (IndexError, ValueError):
        raise RuntimeError('cannot read app bundle {}: {}'.format(app_path, output.strip()))

    part = dest + '.part'
    _, stdout, stderr = client.exec_command(remote.sh('tar -C {} -cf - {}'.format(q(container), ' '.join(q(n) for n in names))))
    stdout.channel.settimeout(120)
    reader = _CountingReader(stdout, lambda done: progress(min(done, total), total), cancelled)
    try:
        with zipfile.ZipFile(part, 'w', allowZip64=True) as ipa, tarfile.open(fileobj=reader, mode='r|') as tar:
            for member in tar:
                name = member.name.removeprefix('./')
                if name == app_dir or name.startswith(app_dir + '/'):
                    name = 'Payload/' + name
                if member.isdir():
                    ipa.writestr(_zip_info(name.rstrip('/') + '/', member), b'')
                elif member.issym():
                    ipa.writestr(_zip_info(name, member), member.linkname)
                elif member.isfile():
                    source = tar.extractfile(member)
                    with ipa.open(_zip_info(name, member), 'w', force_zip64=member.size > 0x7FFFFFFF) as target:
                        shutil.copyfileobj(source, target, CHUNK)
                else:
                    # Hard links and device files never occur in app bundles; fail rather than drop a file.
                    raise RuntimeError('unsupported entry in app bundle: {}'.format(member.name))
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise RuntimeError('tar exited with {}: {}'.format(status, stderr.read().decode('utf-8', 'replace').strip()))
        os.replace(part, dest)
    except BaseException:
        stdout.channel.close()
        try:
            os.remove(part)
        except OSError:
            pass
        raise
    progress(total, total)
    return dest
