# -*- coding: utf-8 -*-
"""Decrypt on the device with the two helper programs in helpers/bin, no Frida involved.

Same job as repair_worker.py (which does it with Frida): for every still-encrypted slice of the planned jobs
(ipa_repair.Job) get the decrypted bytes of its encrypted range and write them to <work>/<job id>_<slice index>.bin,
where ipa_repair.apply() picks them up.

Two helpers, both arm64 programs run as root over SSH (sources in helpers/src, see helpers/README.md):

* mremap_decrypt (iOS 15 and earlier): asks the kernel to decrypt the range of one slice of the installed file with
  mremap_encrypted(); no app is started. One call per slice.
* memory_decrypt (any iOS that lets a root process get a task port; needed from iOS 16 on): starts the app the way the
  system does, suspended, and reads the decrypted code from its memory; app extensions are started stopped at exec,
  frameworks the app did not link are loaded into it with dlopen. One call per app.

This module never imports frida.
"""

import hashlib
import os
import plistlib
import posixpath
import re
import shlex
import threading
import uuid

AUTO, MREMAP, MEMORY = 'auto', 'mremap', 'memory'
CHOICES = (AUTO, MREMAP, MEMORY)
BINARIES = {MREMAP: 'mremap_decrypt', MEMORY: 'memory_decrypt'}
MEMORY_FROM_IOS = 16      # mremap_encrypted is refused from iOS 16 on
HELPER_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'helpers', 'bin')
# Where the helpers are put on the device: the first folder a helper can be run from.
REMOTE_DIRS = ('/var/tmp/ipa_extractor_helpers', '/var/mobile/Media/ipa_extractor_helpers')
STAGE_DIRS = ('/var/tmp', '/var/mobile/Media')   # where the login user uploads before root moves a file
CHUNK = 1024 * 1024
RUN_TIMEOUT = 900         # memory_decrypt has the app start and load frameworks; seconds
SLICE_TIMEOUT = 600
USAGE_STATUS = 2          # what a helper exits with when run without arguments


class HelperError(Exception):
    """The helper cannot be used (missing, altered, would not run): the message says why."""


def setting(value):
    return value if value in CHOICES else AUTO


def choose(value, ios_major):
    """Which helper to use: the user's choice, or for 'auto' the one that works on this iOS."""
    value = setting(value)
    if value != AUTO:
        return value
    return MEMORY if ios_major is not None and ios_major >= MEMORY_FROM_IOS else MREMAP


def refused(value, ios_major):
    """True when the user picked file mapping on an iOS that refuses it (16 and later)."""
    return setting(value) == MREMAP and ios_major is not None and ios_major >= MEMORY_FROM_IOS


def local_helper(method, directory=HELPER_DIR):
    """(path, sha256) of a helper's binary. The checksum only names the file on the device, nothing is compared
    with it: any binary in helpers/bin is used, so one built by somebody else works. The file must be readable."""
    path = os.path.join(directory, BINARIES[method])
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError as error:
        raise HelperError('{} cannot be read ({})'.format(path, error))
    if not data:
        raise HelperError('{} is empty'.format(path))
    return path, hashlib.sha256(data).hexdigest()


def cpu_arguments(slice_):
    """cputype and subtype as the unsigned numbers the helpers take."""
    return slice_.cpu & 0xFFFFFFFF, slice_.subtype & 0xFFFFFFFF


def same_cpu(cpu, subtype, slice_):
    """Whether a slice is the one for cpu/subtype (the capability bits of a subtype are not part of it)."""
    return (cpu & 0xFFFFFFFF) == (slice_.cpu & 0xFFFFFFFF) and (subtype & 0xFFFFFF) == (slice_.subtype & 0xFFFFFF)


class Device:
    """Runs commands on the device as root over an open paramiko connection."""

    def __init__(self, ssh, user, password):
        self.ssh = ssh
        self.user = user
        self.password = password
        self.folder = None      # where the helpers were put, once uploaded
        self.helpers = {}       # method -> path on the device

    def run(self, command, timeout=60):
        """(exit status, stdout bytes, stderr text) of a shell command run as root."""
        if self.user != 'root':
            # Rootless jailbreaks log in as mobile; sudo takes the same password.
            command = "sudo -S -p '' sh -c {}".format(shlex.quote(command))
        stdin, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)
        if self.user != 'root':
            stdin.write(self.password + '\n')
            stdin.flush()
        # Both streams are read at once: a helper that logs a lot to stderr would otherwise block on a full window.
        errors = []
        reader = threading.Thread(target=lambda: errors.append(stderr.read()), daemon=True)
        reader.start()
        data = stdout.read()
        reader.join()
        error = (errors[0] if errors else b'').decode('utf-8', 'replace')
        return stdout.channel.recv_exit_status(), data, error

    def text(self, command, timeout=60):
        status, data, error = self.run(command, timeout)
        return status, data.decode('utf-8', 'replace') + error

    def ios_version(self):
        """'12.4' and the like, or '' when the device does not say."""
        status, output = self.text('sw_vers -productVersion')
        return output.strip() if status == 0 else ''

    # ------------------------------------------------------------ the helpers on the device
    def upload(self, method, directory=HELPER_DIR):
        """Put a helper on the device and return its path there.

        The file is named after its checksum and is never written over: a helper already there is used as is, a
        new version gets a new name. (Replacing a program in place can make a jailbreak kill it, or worse; some
        jailbreaks keep what they know about a file by path.) Files of other versions are deleted.
        """
        if method in self.helpers:
            return self.helpers[method]
        local, digest = local_helper(method, directory)
        name = '{}-{}'.format(BINARIES[method], digest[:12])
        size = os.path.getsize(local)
        problems = []
        for folder in ([self.folder] if self.folder else list(REMOTE_DIRS)):
            remote = posixpath.join(folder, name)
            try:
                self.text('mkdir -p {0} && chmod 755 {0}'.format(shlex.quote(folder)))
                sftp = self.ssh.open_sftp()
                try:
                    try:
                        present = sftp.stat(remote).st_size == size
                    except OSError:
                        present = False
                    if not present:
                        # The login user (mobile on a rootless jailbreak) may not write where root runs programs
                        # from: upload where it can, then let root move the file into place and own it.
                        temporary = self._stage(sftp, local, name)
                        status, output = self.text('chown root:wheel {t} && chmod 755 {t} && mv {t} {r}'.format(
                            t=shlex.quote(temporary), r=shlex.quote(remote)))
                        if status != 0:
                            self.text('rm -f ' + shlex.quote(temporary))
                            raise OSError(output.strip() or 'mv failed')
                finally:
                    sftp.close()
                status, output = self.text('{} 2>&1 >/dev/null'.format(shlex.quote(remote)))
                if status != USAGE_STATUS:
                    raise OSError('the helper would not start ({})'.format(output.strip() or 'exit status {}'.format(status)))
            except Exception as error:
                problems.append('{}: {}'.format(folder, error))
                continue
            self.folder = folder
            self.helpers[method] = remote
            # Other versions of this helper, and the output folders of runs that were cut short.
            self.text('cd {} && for f in {}-*; do [ "$f" = {} ] || rm -f "$f"; done; rm -rf out-*'.format(
                shlex.quote(folder), BINARIES[method], shlex.quote(name)))
            return remote
        raise HelperError('cannot run {} on the device ({})'.format(BINARIES[method], '; '.join(problems)))

    @staticmethod
    def _stage(sftp, local, name):
        """Upload a file under a name nothing else has, to the first folder the login user can write to."""
        problem = None
        for folder in STAGE_DIRS:
            temporary = '{}/{}.{}.part'.format(folder, name, uuid.uuid4().hex[:8])
            try:
                sftp.put(local, temporary)
                return temporary
            except OSError as error:
                problem = error
        raise OSError(problem or 'no folder to upload to')

    def scratch(self):
        """A new empty folder on the device for helper output; remove it with remove()."""
        folder = posixpath.join(self.folder or REMOTE_DIRS[0], 'out-' + uuid.uuid4().hex[:10])
        self.text('mkdir -p {0} && chmod 755 {0}'.format(shlex.quote(folder)))
        return folder

    def remove(self, folder):
        self.text('rm -rf ' + shlex.quote(folder), timeout=120)


# ---------------------------------------------------------------- mremap_decrypt
def run_mremap(device, jobs, work, report, cancelled=lambda: False):
    """Decrypt every slice of the jobs with mremap_decrypt, one call each.

    report(job, index, error) is called for every slice: error None when work/<id>_<index>.bin was written.
    """
    helper = device.upload(MREMAP)
    for job in jobs:
        # 64-bit slices first: on iOS 8 the original path of a file serves one cputype only (the first to ask),
        # and the 64-bit one is what a 64-bit device runs.
        order = sorted(range(len(job.slices)), key=lambda i: not job.slices[i].cpu & 0x01000000)
        for index in order:
            if cancelled():
                return
            slice_ = job.slices[index]
            error = None
            data = b''
            try:
                path = job.slice_paths.get(index, job.device_path)
                status, data, error = _mremap_call(device, helper, path, slice_)
                if status != 0 and '(errno 12)' in error and path != job.device_path:
                    # Some files (some app extensions) cannot be decrypted from a private copy but can from
                    # where they are installed.
                    status, data, error = _mremap_call(device, helper, job.device_path, slice_)
                if status == 0 and len(data) != slice_.cryptsize:
                    status, error = 1, 'the helper returned {} of {} bytes'.format(len(data), slice_.cryptsize)
                if status != 0:
                    report(job, index, error.strip() or 'exit status {}'.format(status))
                    continue
                with open(os.path.join(work, '{}_{}.bin'.format(job.id, index)), 'wb') as handle:
                    handle.write(data)
            except Exception as exception:
                report(job, index, str(exception) or type(exception).__name__)
                continue
            report(job, index, None)


def _mremap_call(device, helper, path, slice_):
    cpu, subtype = cpu_arguments(slice_)
    command = '{} {} {} {} {} {} {} {} -'.format(shlex.quote(helper), shlex.quote(path), slice_.offset, slice_.cryptoff,
                                                  slice_.cryptsize, slice_.cryptid, cpu, subtype)
    return device.run(command, timeout=SLICE_TIMEOUT)


# ---------------------------------------------------------------- memory_decrypt
def parse_output(text):
    """{path inside the app: [(cputype, subtype, cryptoff, cryptsize)]} and {path: failure text} from the helper's
    standard output (one line per image: OK/FAIL/SKIP, tab separated)."""
    done, failed = {}, {}
    for line in text.splitlines():
        parts = line.rstrip('\r').split('\t')
        if parts[0] == 'OK' and len(parts) == 6:
            try:
                cpu, subtype, cryptoff, cryptsize = (int(part) for part in parts[2:6])
            except ValueError:
                continue
            done.setdefault(parts[1], []).append((cpu & 0xFFFFFFFF, subtype, cryptoff, cryptsize))
        elif parts[0] == 'FAIL' and len(parts) >= 3:
            failed[parts[1]] = parts[2]
    return done, failed


def app_executable(sftp, app_path):
    """CFBundleExecutable of the .app on the device."""
    with sftp.open(posixpath.join(app_path, 'Info.plist')) as handle:
        info = plistlib.loads(handle.read())
    name = info.get('CFBundleExecutable')
    if not name:
        raise HelperError('Info.plist of the app names no executable')
    return name


def run_memory(device, bundle, app_path, jobs, work, report, log=lambda text: None, cancelled=lambda: False):
    """Decrypt the jobs' slices with memory_decrypt: one call for the whole app and its extensions.

    report(job, index, error) is called for every slice, like run_mremap().
    """
    helper = device.upload(MEMORY)
    sftp = device.ssh.open_sftp()
    out = None
    try:
        executable = posixpath.join(app_path, app_executable(sftp, app_path))
        out = device.scratch()
        command = '{} dump --ranges --bundle-id {} {} {} {}'.format(shlex.quote(helper), shlex.quote(bundle),
                                                                   shlex.quote(executable), shlex.quote(app_path),
                                                                   shlex.quote(out))
        status, data, error = device.run(command, timeout=RUN_TIMEOUT)
        text = data.decode('utf-8', 'replace')
        for line in error.splitlines():
            if line.startswith('# '):
                log(line[2:])
        done, failed = parse_output(text)
        # The helper notes it when the process it started is gone before its frameworks were read.
        exited = 'task_info failed' in error or 'inject: task_threads failed' in error
        if status != 0 and not done:
            lines = [line for line in error.strip().splitlines() if line.strip()]
            reason = failed.get('-') or (lines[-1] if lines else 'exit status {}'.format(status))
            for job in jobs:
                for index in range(len(job.slices)):
                    report(job, index, reason)
            return
        prefix = app_path.rstrip('/') + '/'
        for job in jobs:
            rel = job.device_path[len(prefix):] if job.device_path.startswith(prefix) else job.device_path
            for index, slice_ in enumerate(job.slices):
                if cancelled():
                    return
                match = next((entry for entry in done.get(rel, ())
                              if same_cpu(entry[0], entry[1], slice_) and entry[2] == slice_.cryptoff
                              and entry[3] == slice_.cryptsize), None)
                if match is None:
                    reason = failed.get(rel) or ('this architecture was not loaded' if rel in done else
                                                 'the app exited while it was starting, so the file was never loaded'
                                                 if exited else 'the helper did not load the file')
                    report(job, index, reason)
                    continue
                try:
                    with sftp.open(posixpath.join(out, rel + '.range'), 'rb') as handle:
                        handle.prefetch()
                        data = handle.read()
                    if len(data) != slice_.cryptsize:
                        raise OSError('read {} of {} bytes'.format(len(data), slice_.cryptsize))
                    with open(os.path.join(work, '{}_{}.bin'.format(job.id, index)), 'wb') as handle:
                        handle.write(data)
                except Exception as exception:
                    report(job, index, str(exception) or type(exception).__name__)
                    continue
                report(job, index, None)
    finally:
        sftp.close()
        if out:
            device.remove(out)


def run(device, method, bundle, app_path, jobs, work, report, log=lambda text: None, cancelled=lambda: False):
    """Decrypt jobs with the chosen helper (MREMAP or MEMORY)."""
    if method == MREMAP:
        run_mremap(device, jobs, work, report, cancelled)
    else:
        run_memory(device, bundle, app_path, jobs, work, report, log, cancelled)


def version_text(device_os):
    """'16.1.2' for 'iOS 16.1.2' or 'iPhone OS 16.1.2'; '' when there is no version."""
    match = re.search(r'(\d+(?:\.\d+)*)\s*$', device_os or '')
    return match.group(1) if match else ''


def ios_major(version):
    """16 for '16.1.2' or 'iPhone OS 16.1.2', None when there is no version."""
    match = re.search(r'(\d+)(?:\.\d+)*\s*$', version or '')
    return int(match.group(1)) if match else None
