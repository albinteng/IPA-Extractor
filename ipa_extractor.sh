#!/bin/sh
# Launch IPA Extractor on Linux or macOS.
# Packages go into ./.venv (created on first run), so the system Python is never modified.
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
cd "$HERE" || exit 1

if [ ! -x .venv/bin/python ]; then
    PYTHON=$(command -v python3 || command -v python)
    if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        echo "IPA Extractor needs Python 3.9 or later: https://www.python.org/downloads/" >&2
        exit 1
    fi
    # Only the window needs Tk; the command line (any argument) runs on a server without it.
    if [ $# -eq 0 ] && ! "$PYTHON" -c 'import tkinter' 2>/dev/null; then
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

# The window runs from the tool's folder; the command line runs where it was called from, so that relative
# paths in its arguments (-o out, verify app.ipa) mean what the caller meant.
if [ $# -gt 0 ]; then
    cd "$OLDPWD" || exit 1
fi
exec "$HERE/.venv/bin/python" "$HERE/ipa_extractor.py" "$@"
