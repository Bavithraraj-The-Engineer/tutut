#!/bin/sh
# tutut one-command installer (Linux).
#
#   ./install.sh              install (or upgrade) and start guarding Claude Desktop
#   ./install.sh --uninstall  stop guarding, restore Claude Desktop's config, remove tutut
#
# Installs into ~/.local/share/tutut (override with TUTUT_HOME) using a Python
# that has tkinter (override with TUTUT_PYTHON), then runs `tutut install`.
set -eu

SRC_DIR=$(cd "$(dirname "$0")" && pwd)
PREFIX=${TUTUT_HOME:-"$HOME/.local/share/tutut"}
VENV="$PREFIX/venv"
BIN_LINK="$HOME/.local/bin/tutut"

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    if [ -x "$VENV/bin/tutut" ]; then
        "$VENV/bin/tutut" uninstall
    fi
    if [ -L "$BIN_LINK" ] && [ "$(readlink "$BIN_LINK")" = "$VENV/bin/tutut" ]; then
        rm -f "$BIN_LINK"
    fi
    rm -rf "$PREFIX"
    say "tutut removed. Your rules and log are kept in ~/.config/tutut."
    exit 0
fi

[ "$(uname -s)" = "Linux" ] || die "this installer supports Linux only."

# Find a Python >= 3.9 that has tkinter (for the popup) and venv/ensurepip.
find_python() {
    for py in ${TUTUT_PYTHON:-} python3 python3.13 python3.12 python3.11 python3.10 python3.9 /usr/bin/python3; do
        command -v "$py" >/dev/null 2>&1 || continue
        if "$py" -c 'import sys, tkinter, venv, ensurepip; sys.exit(sys.version_info < (3, 9))' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PY=$(find_python) || die "no Python 3.9+ with tkinter and venv found.
  On Ubuntu/Debian: sudo apt install python3-tk python3-venv
  Or point TUTUT_PYTHON at a suitable interpreter."
say "Using $PY ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"

if [ ! -x "$VENV/bin/python" ]; then
    "$PY" -m venv "$VENV"
fi
PIP_LOG="$PREFIX/pip.log"
# tutut itself is always reinstalled (picks up local changes); aiohttp is
# needed by `tutut web` / `tutut http` (the claude.ai path).
if ! { "$VENV/bin/python" -m pip install --upgrade pip &&
       "$VENV/bin/python" -m pip install --force-reinstall --no-deps "$SRC_DIR" &&
       "$VENV/bin/python" -m pip install "aiohttp>=3.9"; } >"$PIP_LOG" 2>&1; then
    cat "$PIP_LOG" >&2
    die "pip install failed (log: $PIP_LOG)"
fi
say "Installed tutut into $VENV"

mkdir -p "$(dirname "$BIN_LINK")"
if [ ! -e "$BIN_LINK" ] || [ -L "$BIN_LINK" ]; then
    ln -sf "$VENV/bin/tutut" "$BIN_LINK"
fi

"$VENV/bin/tutut" install

say ""
say "Done. Every MCP server in Claude Desktop now asks before running a tool,"
say "including servers you add later. Restart Claude Desktop once to apply."
say "Check status any time:  $VENV/bin/tutut status"
