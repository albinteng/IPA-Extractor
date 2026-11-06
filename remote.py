# -*- coding: utf-8 -*-
"""Run shell commands on the device over SSH, whatever its login shell is."""

import shlex


def sh(command):
    """Wrap a command for sh: Dopamine's mobile user logs in to zsh, which aborts on unmatched globs."""
    return 'sh -c ' + shlex.quote(command)


def run(client, command, timeout=15, stdin=None):
    """Run command under sh; return (exit status, stdout and stderr interleaved as text)."""
    channel = client.get_transport().open_session(timeout=timeout)
    try:
        channel.settimeout(timeout)
        channel.set_combine_stderr(True)  # one stream, so a chatty stderr cannot block stdout
        channel.exec_command(sh(command))
        if stdin is not None:
            channel.sendall(stdin.encode('utf-8'))
            channel.shutdown_write()
        output = channel.makefile('rb').read().decode('utf-8', 'replace')
        return channel.recv_exit_status(), output
    finally:
        channel.close()


def enable_legacy_host_key():
    """Let paramiko verify ssh-rsa (SHA-1) host keys, the only kind iOS 8-era SSH servers offer.

    paramiko 4 and later dropped it. It is added as the last choice, so a server that also offers
    anything newer still gets that. True when it was enabled now, False when it already was.
    """
    import paramiko
    from cryptography.hazmat.primitives import hashes

    transport = paramiko.Transport
    # These are paramiko internals: a version without them cannot be adapted.
    if not hasattr(transport, '_key_info') or not hasattr(transport, '_preferred_keys'):
        return False
    if 'ssh-rsa' in transport._key_info:
        return False

    class LegacyRSAKey(paramiko.RSAKey):
        HASHES = dict(paramiko.RSAKey.HASHES, **{'ssh-rsa': hashes.SHA1})

    transport._key_info['ssh-rsa'] = LegacyRSAKey
    transport._preferred_keys = tuple(transport._preferred_keys) + ('ssh-rsa',)
    return True
