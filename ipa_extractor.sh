#!/bin/sh
# Launch IPA Extractor on Linux or macOS.
# Python packages go into ./.venv (created on first run), so the system Python is never modified. What only the
# system can provide (venv, tkinter) is offered through the package manager, with your say-so.
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
cd "$HERE" || exit 1

# offer WHAT APT DNF PACMAN ZYPPER BREW: WHAT is missing; install it with the system's package manager when asked
# in a terminal (a "-" means the manager has no such package), otherwise say which command does. 0 when installed.
offer() {
    what=$1
    if command -v apt-get >/dev/null 2>&1; then manager="apt-get install -y"; package=$2
    elif command -v dnf >/dev/null 2>&1; then manager="dnf install -y"; package=$3
    elif command -v pacman >/dev/null 2>&1; then manager="pacman -S --needed"; package=$4
    elif command -v zypper >/dev/null 2>&1; then manager="zypper install -y"; package=$5
    elif command -v brew >/dev/null 2>&1; then manager="brew install"; package=$6
    else manager=""; package=""
    fi
    echo "$what is missing." >&2
    if [ -z "$package" ] || [ "$package" = "-" ]; then
        echo "Install it with your system's package manager." >&2
        return 1
    fi
    command="$manager $package"
    if [ "$manager" != "brew install" ] && [ "$(id -u)" != 0 ]; then
        command="sudo $command"
    fi
    if [ -t 0 ] && [ -t 2 ]; then
        printf 'Install it now with "%s"? [y/N] ' "$command" >&2
        read answer
        case $answer in
            y|Y|yes|YES) $command && return 0 ;;
        esac
    else
        echo "Install it with: $command" >&2
    fi
    return 1
}

if [ ! -x .venv/bin/python ]; then
    PYTHON=$(command -v python3 || command -v python)
    if [ -z "$PYTHON" ] || ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        echo "IPA Extractor needs Python 3.9 or later: https://www.python.org/downloads/" >&2
        exit 1
    fi
    echo "Creating .venv for IPA Extractor's Python packages..." >&2
    if ! "$PYTHON" -m venv .venv >/dev/null 2>&1; then
        rm -rf .venv
        offer "Python's venv module" python3-venv - - - - || exit 1
        "$PYTHON" -m venv .venv || { echo "Could not create .venv." >&2; exit 1; }
    fi
fi
VPY="$HERE/.venv/bin/python"

# Only the window needs Tk, and every start checks it (a venv made earlier may predate a removed package).
# The command line (any argument) runs on a server without it.
if [ $# -eq 0 ] && ! "$VPY" -c 'import tkinter' 2>/dev/null; then
    offer "Python's Tk support (tkinter)" python3-tk python3-tkinter tk python3-tk python-tk || exit 1
    "$VPY" -c 'import tkinter' 2>/dev/null || { echo "tkinter still cannot be imported." >&2; exit 1; }
fi

# The command line has no window to ask in: it gets its packages here. (The window asks for them itself.)
if [ $# -gt 0 ] && ! "$VPY" -c 'import paramiko, cryptography' 2>/dev/null; then
    echo "Installing the Python packages (paramiko, cryptography) into .venv..." >&2
    "$VPY" -m pip --version >/dev/null 2>&1 || "$VPY" -m ensurepip --upgrade >/dev/null 2>&1
    "$VPY" -m pip install -q 'paramiko>=3' cryptography || { echo "Could not install the Python packages." >&2; exit 1; }
fi

# The window runs from the tool's folder; the command line runs where it was called from, so that relative
# paths in its arguments (-o out, verify app.ipa) mean what the caller meant.
if [ $# -gt 0 ]; then
    cd "$OLDPWD" || exit 1
fi
exec "$VPY" "$HERE/ipa_extractor.py" "$@"
