#!/bin/sh
# Launch IPA Extractor on Linux or macOS.
# Packages go into ./.venv (created on first run), so the system Python is never modified.
cd "$(dirname "$0")" || exit 1

if [ ! -x .venv/bin/python ]; then
    PYTHON=$(command -v python3 || command -v python)
    if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        echo "IPA Extractor needs Python 3.9 or later: https://www.python.org/downloads/" >&2
        exit 1
    fi
    if ! "$PYTHON" -c 'import tkinter' 2>/dev/null; then
        echo "Python's Tk support (tkinter) is missing. Install it, for example:" >&2
        echo "  Debian/Ubuntu:    sudo apt install python3-tk" >&2
        echo "  Fedora:           sudo dnf install python3-tkinter" >&2
        echo "  macOS (Homebrew): brew install python-tk" >&2
        exit 1
    fi
    echo "Creating .venv for IPA Extractor's Python packages..."
    if ! "$PYTHON" -m venv .venv; then
        echo "Could not create .venv. On Debian/Ubuntu: sudo apt install python3-venv" >&2
        exit 1
    fi
fi

exec .venv/bin/python ipa_extractor.py "$@"
