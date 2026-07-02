#!/usr/bin/env python3
"""
darksync.py — Darkdrive sync client
Two-way sync: uploads new files, then pulls remote state to local backup folder.

Usage:
  python3 darksync.py [/path/to/backup]        # run sync (folder picker if path omitted)
  python3 darksync.py /path/to/backup --logout  # clear session + saved password

Uploads:
  Drop files into <backup>/uploads/ — they are uploaded on the next sync run,
  deleted from uploads/, and then pulled into the appropriate type subfolder.
  Files directly in uploads/ are tagged "upload".
  Files in subfolders are tagged with their parent folder name:
    uploads/vacation/photo.jpg        → tag "vacation"
    uploads/work/reports/doc.pdf      → tag "reports"
  Failed uploads stay in place for the next run.

Unattended scheduling (requires password saved locally — run once manually first):
  Linux:    crontab -e → */5 * * * * python3 /path/to/darksync.py /path/to/backup
  Mac:      crontab or launchd plist with StartInterval 300
  Windows:  Task Scheduler → action: python3 darksync.py C:\\path\\to\\backup, trigger: every 5 min
  Multiple instances: one cron entry per backup dir
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import stat
import sys
import time
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

# ── helpers ──────────────────────────────────────────────────────────────────

TYPES = ["images", "videos", "audio", "documents", "archives",
         "texts", "fonts", "contacts", "design", "other"]

DARKDRIVE_DIR  = ".darkdrive"
CONFIG_FILE    = "config.json"
STATE_FILE     = "state.json"
COOKIES_FILE   = "cookies"
LOCK_FILE      = "sync.lock"
UPLOADS_DIR    = "uploads"

_IS_WINDOWS = sys.platform == "win32"


def _safe_filename(name: str) -> str:
    """Sanitize a server-supplied filename to prevent path traversal."""
    # strip any directory components
    name = os.path.basename(name)
    # reject empty or dot-only names
    if not name or name in (".", ".."):
        name = "unnamed"
    return name


def _lock_acquire(lock_fh):
    """Try to acquire an exclusive lock. Returns True on success."""
    try:
        if _IS_WINDOWS:
            import msvcrt
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, IOError):
        return False


def _lock_release(lock_fh):
    """Release the lock."""
    try:
        if _IS_WINDOWS:
            import msvcrt
            lock_fh.seek(0)
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
    except (OSError, IOError):
        pass


def _dd_dir(backup_dir: str) -> str:
    return os.path.join(backup_dir, DARKDRIVE_DIR)


def _config_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), CONFIG_FILE)


def _state_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), STATE_FILE)


def _cookies_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), COOKIES_FILE)


def _lock_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), LOCK_FILE)


def _ensure_dd_dir(backup_dir: str) -> None:
    os.makedirs(_dd_dir(backup_dir), exist_ok=True)


def _derive_auth_key(password: str) -> str:
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        b"darkdrive-auth-v1",
        100_000,
    )
    return dk.hex()


# ── permissions ──────────────────────────────────────────────────────────────

def _make_writable(path: str) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


def _make_readonly_file(path: str) -> None:
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def _make_writable_dir(path: str) -> None:
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass


def _make_readonly_dir(path: str) -> None:
    try:
        os.chmod(path, 0o555)
    except OSError:
        pass


def _lock_down(backup_dir: str) -> None:
    """Make all files and dirs inside backup_dir read-only, except uploads/ and .darkdrive/."""
    skip = {
        os.path.join(backup_dir, UPLOADS_DIR),
        os.path.join(backup_dir, DARKDRIVE_DIR),
    }
    for dirpath, dirnames, filenames in os.walk(backup_dir, topdown=False):
        # skip uploads/ and .darkdrive/ trees entirely
        if any(dirpath == s or dirpath.startswith(s + os.sep) for s in skip):
            continue
        # skip icon metadata files in the backup root (need to stay writable)
        _icon_skip = {".directory", "desktop.ini"} if dirpath == backup_dir else set()
        for name in filenames:
            if name not in _icon_skip:
                _make_readonly_file(os.path.join(dirpath, name))
        # don't chmod the backup root — only subdirectories
        if dirpath != backup_dir:
            _make_readonly_dir(dirpath)


# ── folder status icon ────────────────────────────────────────────────────────

ICON_STATUS_FILE = "icon_status"
_STALE_SECONDS   = 1800          # 30 min — success icon expires after this

# KDE icon names (Breeze has rich folder variants)
_KDE_ICONS = {
    "syncing": "folder-sync",
    "ok":      "folder-cloud",
    "error":   "folder-important",
}

# GNOME emblems (small badge overlays on the standard folder icon)
_GNOME_EMBLEMS = {
    "syncing": "emblem-synchronizing-symbolic",
    "ok":      "emblem-ok-symbolic",
    "error":   "emblem-important-symbolic",
}

# Windows: shell32.dll icon indices
_WIN_ICONS = {
    "syncing": r"%SystemRoot%\System32\shell32.dll,46",
    "ok":      r"%SystemRoot%\System32\shell32.dll,144",
    "error":   r"%SystemRoot%\System32\shell32.dll,110",
}


def _icon_status_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), ICON_STATUS_FILE)


def _read_icon_status(backup_dir: str) -> tuple[str, float]:
    """Return (status, timestamp) from the icon_status file, or ('', 0)."""
    try:
        with open(_icon_status_path(backup_dir)) as f:
            parts = f.read().strip().split(" ", 1)
            return parts[0], float(parts[1]) if len(parts) > 1 else 0
    except (OSError, ValueError):
        return "", 0


def _set_folder_icon(backup_dir: str, status: str) -> None:
    """Set the backup folder icon to reflect sync status."""
    _ensure_dd_dir(backup_dir)

    # persist status + timestamp
    try:
        with open(_icon_status_path(backup_dir), "w") as f:
            f.write(f"{status} {time.time():.0f}")
    except OSError:
        pass

    dd_dir = _dd_dir(backup_dir)
    for folder in (backup_dir, dd_dir):
        if _IS_WINDOWS:
            _set_icon_windows(folder, status)
        else:
            _set_icon_linux(folder, status)


def _set_icon_linux(backup_dir: str, status: str) -> None:
    import subprocess

    # KDE / Dolphin: .directory file in the folder root
    kde_icon = _KDE_ICONS.get(status, "")
    dot_dir = os.path.join(backup_dir, ".directory")
    if kde_icon:
        try:
            with open(dot_dir, "w") as f:
                f.write(f"[Desktop Entry]\nIcon={kde_icon}\n")
        except OSError:
            pass
    else:
        try:
            os.remove(dot_dir)
        except OSError:
            pass

    # GNOME / Nautilus 43+: emblem overlay on standard folder icon
    emblem = _GNOME_EMBLEMS.get(status, "")
    try:
        if emblem:
            subprocess.run(
                ["gio", "set", "-t", "stringv", backup_dir, "metadata::emblems", emblem],
                capture_output=True, timeout=5,
            )
        else:
            subprocess.run(
                ["gio", "set", "-t", "unset", backup_dir, "metadata::emblems"],
                capture_output=True, timeout=5,
            )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _set_icon_windows(backup_dir: str, status: str) -> None:
    import subprocess

    ini_path = os.path.join(backup_dir, "desktop.ini")
    icon_resource = _WIN_ICONS.get(status, "")
    if not icon_resource:
        try:
            os.remove(ini_path)
        except OSError:
            pass
        return

    try:
        with open(ini_path, "w") as f:
            f.write(f"[.ShellClassInfo]\nIconResource={icon_resource}\n")
        subprocess.run(["attrib", "+S", "+H", ini_path], capture_output=True, timeout=5)
        subprocess.run(["attrib", "+S", backup_dir], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _notify_user(title: str, message: str) -> None:
    """Send a desktop notification (best-effort, for unattended cron runs)."""
    import subprocess
    try:
        if _IS_WINDOWS:
            # PowerShell toast notification — escape XML special chars
            import html
            xt = html.escape(title)
            xm = html.escape(message)
            ps = (
                f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
                f"ContentType = WindowsRuntime] > $null; "
                f"$t = [Windows.UI.Notifications.ToastNotification]::new("
                f"[Windows.Data.Xml.Dom.XmlDocument]::new()); "
                f"$x = $t.Content; $x.LoadXml('<toast><visual><binding template=\"ToastText02\">"
                f"<text id=\"1\">{xt}</text><text id=\"2\">{xm}</text>"
                f"</binding></visual></toast>'); "
                f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('darksync').Show($t)"
            )
            subprocess.run(["powershell", "-Command", ps], capture_output=True, timeout=10)
        elif sys.platform == "darwin":
            # osascript — pass via -s o and escaped args to avoid injection
            esc_t = title.replace("\\", "\\\\").replace('"', '\\"')
            esc_m = message.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.run(
                ["osascript", "-e", f'display notification "{esc_m}" with title "{esc_t}"'],
                capture_output=True, timeout=5,
            )
        else:
            # notify-send — arguments are passed as list, no shell injection
            subprocess.run(
                ["notify-send", "--app-name=Darksync", title, message],
                capture_output=True, timeout=5,
            )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _expire_stale_icon(backup_dir: str) -> None:
    """If last successful sync is too old, downgrade icon to error."""
    status, ts = _read_icon_status(backup_dir)
    if status == "ok" and ts and (time.time() - ts) > _STALE_SECONDS:
        print("[info] Last successful sync is stale, updating icon.")
        _set_folder_icon(backup_dir, "error")


# ── password storage (AES-256-GCM, same scheme as Darkdrive enc_key cookie) ──

ENC_SHARE_FILE = "enc_share"


def _enc_share_path(backup_dir: str) -> str:
    return os.path.join(_dd_dir(backup_dir), ENC_SHARE_FILE)


def _save_password(backup_dir: str, password: str) -> None:
    """Encrypt password with a random key (enc_share) and store both split across files."""
    _ensure_dd_dir(backup_dir)
    share = os.urandom(32)
    nonce = os.urandom(12)
    ct = AESGCM(share).encrypt(nonce, password.encode("utf-8"), None)
    # store share in its own file (like session-side enc_share)
    sp = _enc_share_path(backup_dir)
    with open(sp, "wb") as f:
        f.write(share)
    os.chmod(sp, 0o600)
    # store encrypted blob in config (like cookie-side enc_key)
    import base64
    config = _load_config(backup_dir)
    config["encrypted_password"] = base64.b64encode(nonce + ct).decode("ascii")
    _save_config(backup_dir, config)


def _load_password(backup_dir: str) -> str | None:
    """Decrypt stored password from config + enc_share. Returns None if not saved."""
    config = _load_config(backup_dir)
    blob_b64 = config.get("encrypted_password")
    if not blob_b64:
        return None
    sp = _enc_share_path(backup_dir)
    if not os.path.exists(sp):
        return None
    try:
        import base64
        with open(sp, "rb") as f:
            share = f.read()
        blob = base64.b64decode(blob_b64)
        nonce = blob[:12]
        ct = blob[12:]
        return AESGCM(share).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        return None


def _delete_password(backup_dir: str) -> None:
    """Remove stored password and enc_share."""
    sp = _enc_share_path(backup_dir)
    if os.path.exists(sp):
        try:
            _make_writable(sp)
            os.remove(sp)
        except OSError:
            pass
    config = _load_config(backup_dir)
    if "encrypted_password" in config:
        del config["encrypted_password"]
        _save_config(backup_dir, config)


# ── config ────────────────────────────────────────────────────────────────────

def _load_config(backup_dir: str) -> dict:
    path = _config_path(backup_dir)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def _save_config(backup_dir: str, config: dict) -> None:
    _ensure_dd_dir(backup_dir)
    with open(_config_path(backup_dir), "w") as f:
        json.dump(config, f, indent=2)


def _load_state(backup_dir: str) -> dict:
    path = _state_path(backup_dir)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def _save_state(backup_dir: str, state: dict) -> None:
    _ensure_dd_dir(backup_dir)
    with open(_state_path(backup_dir), "w") as f:
        json.dump(state, f, indent=2)


# ── backup dir selection ──────────────────────────────────────────────────────

def _pick_backup_dir() -> str:
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askdirectory(title="Select Darkdrive backup folder")
        root.destroy()
        if path:
            return path
    except Exception:
        pass
    # headless fallback
    path = input("Enter path to backup folder: ").strip()
    if not path:
        sys.exit("No backup folder specified.")
    return path


# ── session / auth ────────────────────────────────────────────────────────────

def _extract_csrf(html: str) -> str | None:
    m = re.search(r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']', html)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']', html)
    return m.group(1) if m else None


def _build_session(backup_dir: str) -> requests.Session:
    session = requests.Session()
    cookies_path = _cookies_path(backup_dir)
    jar = http.cookiejar.MozillaCookieJar(cookies_path)
    if os.path.exists(cookies_path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass
    session.cookies = jar  # type: ignore[assignment]
    return session


def _save_cookies(session: requests.Session, backup_dir: str) -> None:
    jar = session.cookies
    if isinstance(jar, http.cookiejar.MozillaCookieJar):
        _ensure_dd_dir(backup_dir)
        jar.save(ignore_discard=True, ignore_expires=True)
        # lock the cookies file (readable only by owner)
        try:
            os.chmod(_cookies_path(backup_dir), 0o600)
        except OSError:
            pass


def _is_login_page(response: requests.Response) -> bool:
    """True if the server redirected us to / or returned the HTML login form."""
    ct = response.headers.get("Content-Type", "")
    if "application/json" in ct:
        return False
    # login page contains the login form
    if b'name="auth_key"' in response.content or b'id="login-form"' in response.content:
        return True
    return False


def _login(session: requests.Session, url: str, password: str) -> bool:
    """Perform the login handshake. Returns True on success."""
    # GET home page to obtain CSRF token
    try:
        resp = session.get(url + "/", timeout=30, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[error] Could not reach server: {e}")
        return False

    csrf = _extract_csrf(resp.text)
    if not csrf:
        print("[error] Could not extract CSRF token from login page.")
        return False

    auth_key = _derive_auth_key(password)
    try:
        resp = session.post(
            url + "/",
            data={
                "csrf_token": csrf,
                "auth_key":   auth_key,
                "password":   password,
            },
            timeout=30,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        print(f"[error] Login request failed: {e}")
        return False

    # After successful login the server redirects to / and we get the gallery,
    # not the login form.
    if _is_login_page(resp):
        print("[error] Login failed — wrong password?")
        return False

    return True


def _ensure_authenticated(
    session: requests.Session,
    url: str,
    backup_dir: str,
    password: str | None,
) -> list | None:
    """Verify session is alive; if not, log in. Returns file list on success, None on failure."""
    try:
        resp = session.get(url + "/?route=api/files", timeout=30, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[error] Cannot reach server: {e}")
        return None

    if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
        try:
            return resp.json().get("files", [])
        except ValueError:
            pass

    # Need to log in
    if password is None:
        password = _load_password(backup_dir)
    if password is None:
        try:
            import getpass
            password = getpass.getpass(f"Password for {url}: ")
        except EOFError:
            _notify_user("Darksync: Login required",
                         f"Session expired for {url}. Run darksync manually to save password.")
            sys.exit("[error] No terminal available and no saved password. Run once manually first.")

    if not _login(session, url, password):
        if not sys.stdin.isatty():
            _notify_user("Darksync: Login failed",
                         f"Could not authenticate to {url}. Run darksync manually.")
        return None

    _save_cookies(session, backup_dir)

    # Offer to save password locally (only in interactive context)
    if _load_password(backup_dir) is None and sys.stdin.isatty():
        try:
            answer = input("Save password for unattended sync? [y/N] ").strip().lower()
            if answer == "y":
                _save_password(backup_dir, password)
                print("[info] Password saved.")
        except EOFError:
            pass

    return _fetch_file_list(session, url)


# ── file operations ───────────────────────────────────────────────────────────

def _type_dir(backup_dir: str, file_type: str) -> str:
    return os.path.join(backup_dir, file_type)


def _resolve_local_path(backup_dir: str, file_type: str, name: str, mtime: int, existing_names: set) -> str:
    """
    Return the local path for a file, applying mtime prefix on collision.
    existing_names is the set of bare names already used in this type directory.
    """
    type_dir = _type_dir(backup_dir, file_type)
    candidate = name
    if candidate in existing_names:
        candidate = f"{mtime}_{name}"
    return os.path.join(type_dir, candidate)


def _download_file(session: requests.Session, url: str, file_id: str, name: str,
                    dest_path: str, expected_size: int | None = None) -> bool:
    """Download a Darkdrive file to dest_path. Returns True on success."""
    dl_url = f"{url}/?route=load/{urllib.parse.quote(file_id, safe='')}/{urllib.parse.quote(name, safe='')}"
    try:
        with session.get(dl_url, stream=True, timeout=(30, 300)) as resp:
            if resp.status_code != 200:
                print(f"[error] HTTP {resp.status_code} downloading {name}")
                return False
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            # ensure writable before writing
            if os.path.exists(dest_path):
                _make_writable(dest_path)
            with open(dest_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    f.write(chunk)
    except requests.RequestException as e:
        print(f"[error] Download failed for {name}: {e}")
        return False
    # verify downloaded size matches expected
    if expected_size is not None:
        actual = os.path.getsize(dest_path)
        if actual != expected_size:
            print(f"[warn] Size mismatch for {name}: expected {expected_size}, got {actual} — keeping file")
    return True


def _trash_file(backup_dir: str, local_path: str, file_type: str, name: str) -> None:
    """Move a deleted file to .trash/{type}/{name}."""
    trash_dir = os.path.join(backup_dir, ".trash", file_type)
    os.makedirs(trash_dir, exist_ok=True)
    dest = os.path.join(trash_dir, name)
    # ensure source file and its parent dir are writable to allow move
    _make_writable(local_path)
    src_dir = os.path.dirname(local_path)
    _make_writable_dir(src_dir)
    if os.path.exists(dest):
        # avoid overwriting an existing trash entry
        base, ext = os.path.splitext(name)
        dest = os.path.join(trash_dir, f"{base}_{int(time.time())}{ext}")
    try:
        shutil.move(local_path, dest)
    except OSError as e:
        print(f"[warn] Could not move {local_path} to trash: {e}")
    finally:
        _make_readonly_dir(src_dir)


# ── upload ─────────────────────────────────────────────────────────────────

def _uploads_dir(backup_dir: str) -> str:
    return os.path.join(backup_dir, UPLOADS_DIR)


def _ensure_uploads_dir(backup_dir: str) -> None:
    os.makedirs(_uploads_dir(backup_dir), exist_ok=True)


def _fetch_csrf(session: requests.Session, url: str) -> str | None:
    """Fetch a CSRF token from the server."""
    try:
        resp = session.get(url + "/", timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[error] Could not reach server for CSRF: {e}")
        return None
    return _extract_csrf(resp.text)


def _upload_file(session: requests.Session, url: str, file_path: str, tag: str, csrf: str) -> bool:
    """Upload a single file to the Darkdrive server with a tag. Returns True on success."""
    name = os.path.basename(file_path)
    post_url = url + "/?" + urllib.parse.urlencode({"tag": tag})
    try:
        with open(file_path, "rb") as fh:
            resp = session.post(
                post_url,
                files={"upload": (name, fh)},
                data={"csrf_token": csrf},
                timeout=600,
            )
    except requests.RequestException as e:
        print(f"[error] Upload request failed for {name}: {e}")
        return False

    # The response may contain SSE-style lines; the last non-empty line is the
    # result: either "filename|cleanname" (success) or a JSON error object.
    body = resp.text.strip()
    if not body:
        print(f"[error] Empty response uploading {name}")
        return False

    last_line = body.splitlines()[-1].strip()

    # check for JSON error
    if last_line.startswith("{"):
        try:
            err = json.loads(last_line)
            print(f"[error] Server rejected {name}: {err.get('error', last_line)}")
        except ValueError:
            print(f"[error] Unexpected response uploading {name}: {last_line}")
        return False

    if "|" in last_line:
        print(f"[upload] {name} (tag: {tag}) → ok")
        return True

    print(f"[error] Unexpected response uploading {name}: {last_line}")
    return False


def _process_uploads(session: requests.Session, url: str, backup_dir: str) -> list[str]:
    """Upload all files from the uploads/ folder recursively.

    Returns list of source paths that were successfully uploaded (files are kept
    in place so they can be moved into the type folder instead of re-downloaded).
    """
    uploads_path = _uploads_dir(backup_dir)
    if not os.path.isdir(uploads_path):
        return []

    # collect all files with their tag (parent folder name, or "upload" for root)
    pending: list[tuple[str, str]] = []  # (file_path, tag)
    for dirpath, _dirnames, filenames in os.walk(uploads_path):
        for name in filenames:
            if name.startswith("."):
                continue
            file_path = os.path.join(dirpath, name)
            # determine tag from the immediate parent relative to uploads/
            rel = os.path.relpath(dirpath, uploads_path)
            if rel == ".":
                tag = "upload"
            else:
                # immediate parent folder name
                tag = os.path.basename(dirpath)
            pending.append((file_path, tag))

    if not pending:
        return []

    csrf = _fetch_csrf(session, url)
    if not csrf:
        print("[error] Could not extract CSRF token for uploads.")
        return []

    pending.sort()
    uploaded: list[str] = []
    for file_path, tag in pending:
        if _upload_file(session, url, file_path, tag, csrf):
            uploaded.append(file_path)

    return uploaded


def _place_uploaded_files(uploaded: list[str], remote_files: list, backup_dir: str) -> None:
    """Move successfully uploaded files from uploads/ into their type folders.

    Matches by filename against the remote file list so the pull phase's
    auto-detect ([found]) picks them up without re-downloading.
    """
    if not uploaded:
        return

    # build lookup: basename → remote entry (last wins on duplicates, which
    # matches the server keeping the latest upload)
    name_to_remote: dict[str, dict] = {}
    for rf in remote_files:
        name_to_remote[rf["name"]] = rf

    uploads_path = _uploads_dir(backup_dir)

    for src in uploaded:
        basename = os.path.basename(src)
        rf = name_to_remote.get(basename)
        if rf is None:
            # server may have renamed the file; can't match — leave for pull
            print(f"[warn] Could not match uploaded {basename} in file list, will download")
            try:
                os.remove(src)
            except OSError:
                pass
            continue

        file_type = rf["type"] if rf["type"] in TYPES else "other"
        type_dir = _type_dir(backup_dir, file_type)
        _make_writable_dir(type_dir)
        os.makedirs(type_dir, exist_ok=True)

        dest = os.path.join(type_dir, _safe_filename(basename))
        try:
            shutil.move(src, dest)
            print(f"[placed] {file_type}/{basename}")
        except OSError as e:
            print(f"[warn] Could not move {basename} to {file_type}/: {e}")
            try:
                os.remove(src)
            except OSError:
                pass

    # clean up empty directories (bottom-up), but keep uploads/ itself
    for dirpath, _dirnames, _filenames in os.walk(uploads_path, topdown=False):
        if dirpath == uploads_path:
            continue
        try:
            os.rmdir(dirpath)  # only removes if empty
        except OSError:
            pass


# ── sync ──────────────────────────────────────────────────────────────────────

def _fetch_file_list(session: requests.Session, url: str) -> list | None:
    try:
        resp = session.get(url + "/?route=api/files", timeout=60)
    except requests.RequestException as e:
        print(f"[error] Could not fetch file list: {e}")
        return None
    if resp.status_code == 401:
        print("[error] Not authenticated.")
        return None
    if resp.status_code != 200:
        print(f"[error] Unexpected HTTP {resp.status_code} from api/files")
        return None
    try:
        data = resp.json()
        return data.get("files", [])
    except ValueError:
        print("[error] Invalid JSON from api/files")
        return None


def sync(backup_dir: str, password: str | None = None) -> None:
    _ensure_dd_dir(backup_dir)
    _ensure_uploads_dir(backup_dir)

    # prevent concurrent runs (e.g. overlapping cron jobs)
    lock_fh = open(_lock_path(backup_dir), "w")
    if not _lock_acquire(lock_fh):
        print("[info] Another sync is already running, skipping.")
        lock_fh.close()
        return

    # expire stale success icon before starting
    _expire_stale_icon(backup_dir)
    _set_folder_icon(backup_dir, "syncing")

    try:
        _sync_inner(backup_dir, password)
        _set_folder_icon(backup_dir, "ok")
    except SystemExit:
        _set_folder_icon(backup_dir, "error")
        raise
    except Exception:
        _set_folder_icon(backup_dir, "error")
        raise
    finally:
        _lock_release(lock_fh)
        lock_fh.close()


def _sync_inner(backup_dir: str, password: str | None) -> None:
    config = _load_config(backup_dir)
    if not config.get("url"):
        url = input("Darkdrive server URL (e.g. https://drive.example.com): ").strip().rstrip("/")
        if not url:
            sys.exit("No URL provided.")
        if not url.startswith("https://"):
            sys.exit("[error] Server URL must start with https://")
        config["url"] = url
        _save_config(backup_dir, config)
        print(f"[info] Config saved to {_config_path(backup_dir)}")
    else:
        url = config["url"].rstrip("/")

    session = _build_session(backup_dir)

    remote_files = _ensure_authenticated(session, url, backup_dir, password)
    if remote_files is None:
        sys.exit("[error] Could not authenticate or fetch file list.")

    # ── upload pending files ──────────────────────────────────────────────
    uploaded = _process_uploads(session, url, backup_dir)
    _save_cookies(session, backup_dir)
    if uploaded:
        print(f"[info] {len(uploaded)} file(s) uploaded, refreshing file list…")
        remote_files = _fetch_file_list(session, url)
        if remote_files is None:
            sys.exit("[error] Could not refresh file list after upload.")
        _place_uploaded_files(uploaded, remote_files, backup_dir)

    state = _load_state(backup_dir)

    # index remote by id
    remote_by_id = {f["id"]: f for f in remote_files}

    # track names used per type dir to detect collisions
    names_used: dict[str, set] = {t: set() for t in TYPES}
    for entry in state.values():
        lp = entry.get("local_path", "")
        if lp:
            names_used.setdefault(entry.get("type", "other"), set()).add(os.path.basename(lp))

    new_state = {}

    # ── handle new and changed files ─────────────────────────────────────────
    for file_id, rf in remote_by_id.items():
        name      = _safe_filename(rf["name"])
        file_type = rf["type"] if rf["type"] in TYPES else "other"
        size      = rf["size"]
        mtime     = rf["mtime"]

        existing = state.get(file_id)
        needs_download = (
            existing is None
            or existing.get("size")  != size
            or existing.get("mtime") != mtime
        )

        if existing and not needs_download:
            # unchanged — keep entry, ensure file still present
            local_path = existing["local_path"]
            if not os.path.exists(local_path):
                needs_download = True
            else:
                new_state[file_id] = existing
                continue

        # resolve destination path
        type_dir = _type_dir(backup_dir, file_type)

        if existing is not None:
            # update — reuse the existing local path (avoids self-collision)
            local_path = existing["local_path"]
            candidate = os.path.basename(local_path)
        else:
            # new file — collision detection
            used = names_used.setdefault(file_type, set())
            candidate = name
            if candidate in used:
                candidate = f"{mtime}_{name}"
            local_path = os.path.join(type_dir, candidate)
            used.add(candidate)

        # auto-detect: if the file already exists locally with correct name and size, skip download
        if os.path.exists(local_path) and os.path.getsize(local_path) == size:
            print(f"[found] {file_type}/{candidate} (already on disk)")
            _make_readonly_file(local_path)
            new_state[file_id] = {
                "name":       name,
                "type":       file_type,
                "size":       size,
                "mtime":      mtime,
                "local_path": local_path,
            }
            _save_state(backup_dir, new_state)
            continue

        # ensure type dir is writable for new files / overwrites
        _make_writable_dir(type_dir)
        os.makedirs(type_dir, exist_ok=True)

        print(f"[{'new' if existing is None else 'update'}] {file_type}/{candidate}")
        if _download_file(session, url, file_id, name, local_path, expected_size=size):
            _make_readonly_file(local_path)
            _make_readonly_dir(type_dir)
            new_state[file_id] = {
                "name":       name,
                "type":       file_type,
                "size":       size,
                "mtime":      mtime,
                "local_path": local_path,
            }
            _save_state(backup_dir, new_state)
        else:
            _make_readonly_dir(type_dir)
            # keep old state entry to avoid re-download loop on transient errors
            if existing:
                new_state[file_id] = existing

    # ── handle deleted files ──────────────────────────────────────────────────
    for file_id, entry in state.items():
        if file_id in remote_by_id:
            continue  # already handled above
        local_path = entry.get("local_path", "")
        if local_path and os.path.exists(local_path):
            print(f"[delete] {entry.get('type','other')}/{os.path.basename(local_path)} → .trash/")
            _trash_file(backup_dir, local_path, entry.get("type", "other"), os.path.basename(local_path))
        else:
            print(f"[delete] {file_id} (local file already missing, skipping trash)")
        _save_state(backup_dir, new_state)
    _save_cookies(session, backup_dir)

    # ── enforce read-only on all synced content ───────────────────────────
    _lock_down(backup_dir)

    print(f"[done] {len(new_state)} files in sync.")


# ── logout ────────────────────────────────────────────────────────────────────

def logout(backup_dir: str) -> None:
    config = _load_config(backup_dir)
    url = config.get("url", "").rstrip("/")

    cookies_path = _cookies_path(backup_dir)
    if os.path.exists(cookies_path):
        try:
            _make_writable(cookies_path)
            os.remove(cookies_path)
            print("[info] Session cookies removed.")
        except OSError as e:
            print(f"[warn] Could not remove cookies: {e}")
    else:
        print("[info] No session cookies found.")

    _delete_password(backup_dir)
    print("[info] Saved password cleared.")


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Darkdrive down-sync client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("backup_dir", nargs="?", default=None, help="Path to backup folder")
    parser.add_argument("--logout", action="store_true", help="Clear session and saved password")
    args = parser.parse_args()

    backup_dir = args.backup_dir
    if not backup_dir:
        backup_dir = _pick_backup_dir()
    backup_dir = os.path.expanduser(backup_dir)

    if args.logout:
        logout(backup_dir)
    else:
        sync(backup_dir)


if __name__ == "__main__":
    main()
