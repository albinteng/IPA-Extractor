#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPA Extractor: pulls original or decrypted IPAs off a jailbroken device over SSH. The window is in gui/ (PySide6); the
command line is ipa_cli.py. This file only decides which of them to start."""

import sys

if __name__ == '__main__' and len(sys.argv) > 2 and sys.argv[1] == '--worker':
    # The released program runs its own helper processes (Frida, repair) by starting itself again (workers.py).
    import workers
    sys.exit(workers.run(sys.argv[2], sys.argv[3:]))

if __name__ == '__main__' and len(sys.argv) > 1:
    # Any argument means the command line (ipa_cli.py), so ./ipa_extractor.sh apps works too. Decided before the window
    # toolkit is imported: a server without it must still get here.
    import ipa_cli
    sys.exit(ipa_cli.main())


def missing_qt():
    """PySide6 is not installed: say how to get it (a message box on Windows, where a double click has no console)."""
    text = ('IPA Extractor needs PySide6 for its window.\n\nInstall it with:\n    {} -m pip install PySide6-Essentials\n\n'
            'The command line (ipa_extractor with arguments) does not need it.'.format(sys.executable or 'python'))
    print(text, file=sys.stderr)
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text, 'IPA Extractor', 0x10)
        except (AttributeError, OSError):
            pass


def main():
    try:
        from gui import app
    except ImportError as error:
        if 'PySide6' not in str(error) and getattr(error, 'name', '') != 'PySide6':
            raise
        missing_qt()
        return 1
    return app.main()


if __name__ == '__main__':
    sys.exit(main())
