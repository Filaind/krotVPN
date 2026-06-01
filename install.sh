#!/usr/bin/env bash
# krotVPN installer — fetch the latest GitHub release, install the binaries
# into /usr/local/bin and launch krotctl.
#
# Quick start (paste into a terminal):
#   curl -fsSL https://raw.githubusercontent.com/Filaind/krotVPN/main/install.sh | sudo bash
#
# Besides installing into the system path, it drops a ./krotctl copy into the
# directory you run it from, so you can later do e.g. `sudo ./krotctl uninstall`.
#
# Options (via environment variables):
#   KROT_VERSION=v0.1.0   pin a specific release tag (default: latest)
#   KROT_BINDIR=/path     system install dir          (default: /usr/local/bin)
#   KROT_LOCAL_DIR=/path  where to drop ./krotctl     (default: current dir)
#   KROT_NO_RUN=1         install only, do not launch krotctl
set -euo pipefail

REPO="Filaind/krotVPN"
BINDIR="${KROT_BINDIR:-/usr/local/bin}"
VERSION="${KROT_VERSION:-}"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- platform check -----------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "krot server/client run on Linux only (got $(uname -s))."

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m) (need amd64 or arm64)." ;;
esac

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "'$tool' is required but not installed."
done

# --- resolve the release tag --------------------------------------------------
if [ -z "$VERSION" ]; then
  say "Resolving latest release of $REPO ..."
  # Fetch the whole API response first, THEN parse it. Piping curl straight into
  # `grep -m1` makes grep close the pipe early; curl then dies on SIGPIPE and,
  # under `set -o pipefail`, aborts the script — which surfaces to the outer
  # `curl | bash` as "curl: (23) Failed writing body".
  api_resp="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")" \
    || die "could not reach the GitHub API (network, or rate limit — set KROT_VERSION=vX.Y.Z to skip)."
  VERSION="$(printf '%s\n' "$api_resp" | grep '"tag_name"' | head -n1 | cut -d'"' -f4)"
  [ -n "$VERSION" ] || die "could not determine the latest release tag (no release published yet?)."
fi
say "Installing krotVPN $VERSION (linux/$ARCH)"

# --- download + verify --------------------------------------------------------
TARBALL="krot-${VERSION}-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Downloading $TARBALL ..."
curl -fSL --progress-bar -o "$TMP/$TARBALL" "$BASE/$TARBALL" \
  || die "download failed: $BASE/$TARBALL"

if curl -fsSL -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt" 2>/dev/null; then
  say "Verifying checksum ..."
  ( cd "$TMP" && sha256sum -c SHA256SUMS.txt --ignore-missing ) \
    || die "checksum verification failed."
else
  warn "SHA256SUMS.txt not found in release — skipping checksum verification."
fi

# --- install ------------------------------------------------------------------
tar -C "$TMP" -xzf "$TMP/$TARBALL"
SRC="$TMP/krot-${VERSION}-linux-${ARCH}"

say "Installing binaries into $BINDIR (may require sudo) ..."
if [ -w "$BINDIR" ] || [ "$(id -u)" = 0 ]; then
  install -m 0755 "$SRC"/krot-server "$SRC"/krot-client "$SRC"/krot-keygen "$SRC"/krotctl "$BINDIR/"
else
  sudo install -m 0755 "$SRC"/krot-server "$SRC"/krot-client "$SRC"/krot-keygen "$SRC"/krotctl "$BINDIR/"
fi

say "Installed: krot-server krot-client krot-keygen krotctl -> $BINDIR"

# Also drop a krotctl copy into the directory the script was invoked from, so
# you can run it as ./krotctl (e.g. ./krotctl uninstall) without relying on PATH.
LOCAL_DIR="${KROT_LOCAL_DIR:-$PWD}"
if [ -d "$LOCAL_DIR" ] && [ "$(cd "$LOCAL_DIR" && pwd)" != "$BINDIR" ]; then
  if install -m 0755 "$SRC/krotctl" "$LOCAL_DIR/krotctl" 2>/dev/null; then
    # Keep it owned by the user who invoked sudo, not root.
    [ -n "${SUDO_USER:-}" ] && chown "$SUDO_USER" "$LOCAL_DIR/krotctl" 2>/dev/null || true
    say "Local copy: $LOCAL_DIR/krotctl  (run e.g. 'sudo ./krotctl uninstall')"
  else
    warn "Could not write a local krotctl copy to $LOCAL_DIR (use the one in $BINDIR)."
  fi
fi

"$BINDIR/krotctl" version || true

# --- launch -------------------------------------------------------------------
if [ "${KROT_NO_RUN:-}" = "1" ]; then
  say "Done. Run 'krotctl' (or './krotctl') to start the interactive setup wizard."
  exit 0
fi

# When this script is run via `curl ... | bash`, stdin is the pipe from curl,
# not the terminal — so krotctl's wizard would read EOF and silently accept all
# defaults. Reconnect stdin to the controlling terminal so prompts work.
if [ ! -t 0 ] && [ ! -e /dev/tty ]; then
  warn "No interactive terminal available — skipping the wizard."
  say "Run 'sudo krotctl' yourself to configure interactively."
  exit 0
fi

say "Launching krotctl setup wizard ..."
if [ "$(id -u)" = 0 ]; then
  exec "$BINDIR/krotctl" "$@" < /dev/tty
else
  exec sudo "$BINDIR/krotctl" "$@" < /dev/tty
fi
