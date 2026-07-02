#!/usr/bin/env bash
set -euo pipefail

# ── Darksync installer ───────────────────────────────────────────────────────
# Usage (clone the repository first, then run the installer from it):
#   git clone https://github.com/plue-gmbh/darkdrive.de.git
#   cd darkdrive.de
#   ./darksync.sh
#   ./darksync.sh /path/to/backup
#   ./darksync.sh /path/to/backup https://your-server
#
# The darksync.py that ships next to this script is installed directly, so
# no executable code is ever fetched over the network — the client is only
# ever delivered through the version-controlled repository, not a server.
#
# Safe to re-run: only updates the sync script, never touches config,
# state, cookies, or synced files.
# ──────────────────────────────────────────────────────────────────────────────

BACKUP_DIR="${1:-}"
SERVER_URL="${2:-}"
SCRIPT_NAME="darksync.py"
INSTALL_DIR="${HOME}/.local/bin"

info()  { printf '\n\033[1;34m[info]\033[0m %s\n' "$*"; }
error() { printf '\n\033[1;31m[error]\033[0m %s\n' "$*" >&2; }
ok()    { printf '\n\033[1;32m[ok]\033[0m %s\n' "$*"; }

# ── check dependencies ───────────────────────────────────────────────────────

command -v python3 >/dev/null 2>&1 || { error "python3 not found. Install Python 3 first."; exit 1; }
command -v curl    >/dev/null 2>&1 || { error "curl not found."; exit 1; }

# ── install darksync.py from the local repo copy ─────────────────────────────

DEST="$INSTALL_DIR/$SCRIPT_NAME"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/$SCRIPT_NAME"
mkdir -p "$INSTALL_DIR"

if [ ! -f "$SCRIPT_SRC" ]; then
  error "Could not find darksync.py next to this installer. Clone the repository and run ./darksync.sh from it: git clone https://github.com/plue-gmbh/darkdrive.de.git"
  exit 1
fi
if [ "$SCRIPT_SRC" != "$DEST" ]; then
  info "Installing darksync.py from local repo copy …"
  cp "$SCRIPT_SRC" "$DEST.tmp"
  mv "$DEST.tmp" "$DEST"
fi
chmod +x "$DEST"
ok "Installed $DEST"

# ── install Python dependencies ──────────────────────────────────────────────

info "Installing Python dependencies …"
python3 -m pip install --user --quiet requests keyring 2>/dev/null \
  || python3 -m pip install --quiet requests keyring 2>/dev/null \
  || { error "Could not install Python packages. Run: pip install requests keyring"; exit 1; }
ok "Python dependencies installed."

# ── detect existing setup ────────────────────────────────────────────────────

EXISTING=false

# if backup dir given, check for existing config
if [ -n "$BACKUP_DIR" ]; then
  BACKUP_DIR="${BACKUP_DIR/#\~/$HOME}"
  if [ -f "$BACKUP_DIR/.darkdrive/config.json" ]; then
    EXISTING=true
  fi
# if no backup dir given, try to find one from existing config
elif [ -f "${HOME}/Darkdrive/.darkdrive/config.json" ]; then
  BACKUP_DIR="${HOME}/Darkdrive"
  EXISTING=true
fi

# ── server URL (read from existing config or prompt) ─────────────────────────

if [ "$EXISTING" = true ] && [ -z "$SERVER_URL" ] && [ -n "$BACKUP_DIR" ]; then
  SERVER_URL=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('url',''))" "$BACKUP_DIR/.darkdrive/config.json" 2>/dev/null || true)
  if [ -n "$SERVER_URL" ]; then
    info "Found existing config: $SERVER_URL"
  fi
fi

if [ -z "$SERVER_URL" ]; then
  printf '\nDarkdrive server URL (e.g. https://drive.example.com): '
  read -r SERVER_URL </dev/tty
fi
SERVER_URL="${SERVER_URL%/}"
[ -z "$SERVER_URL" ] && { error "No server URL provided."; exit 1; }
case "$SERVER_URL" in
  https://*) ;;
  *) error "Server URL must start with https://"; exit 1 ;;
esac

# ── backup directory ─────────────────────────────────────────────────────────

if [ -z "$BACKUP_DIR" ]; then
  DEFAULT_DIR="${HOME}/Darkdrive"
  printf '\nBackup folder [%s]: ' "$DEFAULT_DIR"
  read -r BACKUP_DIR </dev/tty
  BACKUP_DIR="${BACKUP_DIR:-$DEFAULT_DIR}"
fi
BACKUP_DIR="${BACKUP_DIR/#\~/$HOME}"
mkdir -p "$BACKUP_DIR"
info "Backup folder: $BACKUP_DIR"

# ── configure (only on fresh install) ────────────────────────────────────────

DD_DIR="$BACKUP_DIR/.darkdrive"
CONFIG="$DD_DIR/config.json"

if [ "$EXISTING" = true ]; then
  ok "Existing setup detected — config, state and files left untouched."
else
  mkdir -p "$DD_DIR"
  if [ ! -f "$CONFIG" ]; then
    python3 -c "import json,sys; json.dump({'url':sys.argv[1]},open(sys.argv[2],'w'),indent=2)" "$SERVER_URL" "$CONFIG"
    info "Server URL saved to $CONFIG"
  fi

  # first interactive run (login + keyring save)
  info "Running first sync (log in and save password to keyring) …"
  echo ""
  python3 "$DEST" "$BACKUP_DIR"
  echo ""
fi

# ── set up cron job ──────────────────────────────────────────────────────────

CRON_CMD="python3 $DEST $BACKUP_DIR"

setup_cron() {
  if crontab -l 2>/dev/null | grep -qF "$DEST $BACKUP_DIR"; then
    info "Cron job already exists, skipping."
    return
  fi
  # DBUS address needed for desktop notifications from cron
  DBUS_LINE="DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus"
  EXISTING_CRON=$(crontab -l 2>/dev/null || true)
  ( echo "$EXISTING_CRON"
    if ! echo "$EXISTING_CRON" | grep -qF "DBUS_SESSION_BUS_ADDRESS="; then
      echo "$DBUS_LINE"
    fi
    echo "*/5 * * * * $CRON_CMD"
  ) | crontab -
  ok "Cron job added (every 5 minutes)."
}

if [ "$(uname)" = "Darwin" ] || [ "$(uname)" = "Linux" ]; then
  if crontab -l 2>/dev/null | grep -qF "$DEST $BACKUP_DIR"; then
    info "Cron job already exists."
  else
    printf '\nSet up cron job to sync every 5 minutes? [Y/n] '
    read -r answer </dev/tty
    case "$answer" in
      [nN]*) info "Skipping cron setup. Run manually: $CRON_CMD" ;;
      *)     setup_cron ;;
    esac
  fi
else
  info "On Windows, create a Task Scheduler entry:"
  info "  Action:  python3 $DEST $BACKUP_DIR"
  info "  Trigger: every 5 minutes"
fi

# ── done ─────────────────────────────────────────────────────────────────────

ok "Darksync is ready!"
info "Backup folder:  $BACKUP_DIR"
info "Upload files:   drop into $BACKUP_DIR/uploads/"
info "Script:         $DEST"
echo ""
