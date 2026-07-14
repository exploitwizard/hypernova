#!/usr/bin/env bash
#
# Hypernova installer — gives you global `hypernova` (terminal) and
# `hypernova-web` (browser) commands, with the mitmproxy capture engine
# bundled, on modern (PEP 668 "externally-managed") Python setups where a bare
# `pip install` is blocked. Both commands share one SQLite database.
#
# Usage:
#   ./install.sh            # install / upgrade (terminal + web + capture)
#   ./install.sh --no-capture   # skip mitmproxy (smaller, no live proxy)
#   ./install.sh --no-web       # skip the browser frontend (no Flask)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WITH_CAPTURE=1
WITH_WEB=1
for arg in "$@"; do
    case "$arg" in
        --no-capture) WITH_CAPTURE=0 ;;
        --no-web)     WITH_WEB=0 ;;
    esac
done

say()  { printf '\033[1;36m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.9+ first."
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
say "Using Python $PYV"

# ---------------------------------------------------------------------------
# Preferred path: pipx. It builds an isolated venv and drops `hypernova` on
# your PATH — a true global command with zero PEP 668 headaches.
# ---------------------------------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
    say "Installing with pipx (isolated + global)…"
    pipx install --force "$HERE"
    if [ "$WITH_CAPTURE" = "1" ]; then
        say "Adding the mitmproxy capture engine…"
        pipx inject hypernova "mitmproxy>=10.0" || \
            warn "mitmproxy inject failed — /paste still works; retry with: pipx inject hypernova mitmproxy"
    fi
    if [ "$WITH_WEB" = "1" ]; then
        say "Adding the Flask web frontend…"
        pipx inject hypernova "flask>=2.2" || \
            warn "flask inject failed — retry with: pipx inject hypernova flask"
    fi
    pipx ensurepath >/dev/null 2>&1 || true
    ok "Installed. Open a new terminal (or 'source ~/.zshrc'), then run:"
    ok "  hypernova       (terminal)   ·   hypernova-web   (browser)"
    exit 0
fi

# ---------------------------------------------------------------------------
# Fallback: a dedicated venv under ~/.hypernova/venv, with a launcher symlink
# placed on your PATH.
# ---------------------------------------------------------------------------
warn "pipx not found — using a private venv fallback."
warn "  (For the cleanest install:  brew install pipx  — or  python3 -m pip install --user pipx)"

VENV="$HOME/.hypernova/venv"
say "Creating venv at $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
# Assemble the optional-extras string, e.g. [capture,web].
EXTRAS=""
[ "$WITH_CAPTURE" = "1" ] && EXTRAS="capture"
[ "$WITH_WEB" = "1" ] && EXTRAS="${EXTRAS:+$EXTRAS,}web"
say "Installing Hypernova${EXTRAS:+ [$EXTRAS]}…"
if [ -n "$EXTRAS" ]; then
    "$VENV/bin/pip" install --quiet "$HERE""[$EXTRAS]"
else
    "$VENV/bin/pip" install --quiet "$HERE"
fi

# Pick a bin dir already on PATH.
for d in "$HOME/.local/bin" "/usr/local/bin"; do
    case ":$PATH:" in *":$d:"*) BIN="$d"; break;; esac
done
BIN="${BIN:-$HOME/.local/bin}"
mkdir -p "$BIN"
ln -sf "$VENV/bin/hypernova" "$BIN/hypernova"
ok "Linked $BIN/hypernova"
if [ "$WITH_WEB" = "1" ] && [ -x "$VENV/bin/hypernova-web" ]; then
    ln -sf "$VENV/bin/hypernova-web" "$BIN/hypernova-web"
    ok "Linked $BIN/hypernova-web"
fi
RUNHINT="hypernova$([ "$WITH_WEB" = 1 ] && echo '   ·   hypernova-web')"
case ":$PATH:" in
    *":$BIN:"*) ok "Installed. Run:  $RUNHINT" ;;
    *) warn "Add this to your shell profile, then reopen the terminal:"
       printf '    export PATH="%s:$PATH"\n' "$BIN"
       ok "Then run:  $RUNHINT" ;;
esac
