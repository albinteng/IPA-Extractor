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
