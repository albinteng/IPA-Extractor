# -*- coding: utf-8 -*-
"""Extracting the installed app into an IPA over SSH (ipa_extract.py)."""

import io
import os
import tempfile
import unittest


class FakeSSH:
    """Just enough of paramiko's SSHClient, Transport and Channel for ipa_extract."""

    def __init__(self, tar_data):
        self.stream = io.BytesIO(tar_data)
        self.channel = self

    def get_transport(self):
        return self

    def open_session(self, timeout=None):
        return self

    def exec_command(self, command, timeout=None):
        self.commands = getattr(self, 'commands', []) + [command]
        if 'tar ' in command:
            return None, self, io.BytesIO()
        return None

    def settimeout(self, timeout):
        pass

    def set_combine_stderr(self, combine):
        pass

    def makefile(self, mode):
        return io.BytesIO(b'iTunesMetadata.plist\n12\tX.app\n')  # ls and du output

    def read(self, size=-1):
        return self.stream.read(size)

    def recv_exit_status(self):
        return 0

    def close(self):
        pass


class ExtractTests(unittest.TestCase):
    @staticmethod
    def tar(extra=None):
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            for name, data in (('X.app/Info.plist', b'plist'), ('X.app/X', b'exe'), ('iTunesMetadata.plist', b'meta')):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o755
                tar.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo('X.app/Current')
            link.type, link.linkname = tarfile.SYMTYPE, 'X'
            tar.addfile(link)
            if extra is not None:
                tar.addfile(extra)
        return buffer.getvalue()

    def test_streams_bundle_into_ipa(self):
        import ipa_extract
        import zipfile
        with tempfile.TemporaryDirectory() as folder:
            dest = os.path.join(folder, 'x.ipa')
            ipa_extract.extract_ipa(FakeSSH(self.tar()), '/var/containers/Bundle/Application/U/X.app', dest)
            with zipfile.ZipFile(dest) as ipa:
                self.assertEqual(ipa.read('Payload/X.app/X'), b'exe')
                self.assertEqual(ipa.read('iTunesMetadata.plist'), b'meta')
                self.assertEqual(ipa.read('Payload/X.app/Current'), b'X')  # symlink target
                self.assertEqual(ipa.getinfo('Payload/X.app/X').external_attr >> 16 & 0o777, 0o755)
            self.assertEqual(os.listdir(folder), ['x.ipa'])

    def test_direct_method_leaves_out_purchase_metadata(self):
        import ipa_extract
        import zipfile
        for metadata in (True, False):
            client = FakeSSH(self.tar())
            with tempfile.TemporaryDirectory() as folder:
                dest = os.path.join(folder, 'x.ipa')
                ipa_extract.extract_ipa(client, '/var/containers/Bundle/Application/U/X.app', dest,
                                        metadata=metadata)
                with zipfile.ZipFile(dest) as ipa:
                    self.assertEqual(ipa.read('Payload/X.app/X'), b'exe')
            # The device lists iTunesMetadata.plist (see FakeSSH.makefile); only tar decides what is copied.
            tar = next(command for command in client.commands if 'tar ' in command)
            self.assertEqual('iTunesMetadata.plist' in tar, metadata, tar)

    def test_hard_links_are_not_dropped_silently(self):
        import ipa_extract
        import tarfile
        link = tarfile.TarInfo('X.app/Copy')
        link.type, link.linkname = tarfile.LNKTYPE, 'X.app/X'
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(RuntimeError):
                ipa_extract.extract_ipa(FakeSSH(self.tar(link)), '/c/U/X.app', os.path.join(folder, 'x.ipa'))
            self.assertEqual(os.listdir(folder), [])  # no partial IPA left behind


if __name__ == '__main__':
    unittest.main()
