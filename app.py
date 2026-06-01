from __future__ import annotations

import ipaddress
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from flask import Flask, Response, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(os.environ.get("SIMPLE_WOL_DIR", "/opt/simplewol"))
DB_PATH = Path(os.environ.get("SIMPLE_WOL_DB", APP_DIR / "simplewol.db"))
LEGACY_CONFIG_PATH = Path(os.environ.get("SIMPLE_WOL_CONFIG", APP_DIR / "devices.yaml"))
LEGACY_STATE_PATH = Path(os.environ.get("SIMPLE_WOL_STATE", APP_DIR / "state.json"))
BACKUP_DIR = APP_DIR / "backups"

HOST = os.environ.get("SIMPLE_WOL_HOST", "0.0.0.0")
PORT = int(os.environ.get("SIMPLE_WOL_PORT", "80"))
SECRET_KEY = os.environ.get("SIMPLE_WOL_SECRET_KEY", secrets.token_hex(32))

PING_INTERVAL_SECONDS = 30
OFFLINE_BEFORE_WOL_SECONDS = 5 * 60
WOL_RETRY_INTERVAL_SECONDS = 60
WOL_RETRY_COUNT = 5
WATCHDOG_RESET_AFTER_SECONDS = 60 * 60
MAX_HISTORY_ITEMS = 100

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

db_lock = threading.RLock()


@dataclass
class Device:
    id: str
    name: str
    mac: str
    broadcast: str = "255.255.255.255"
    ip: str | None = None
    description: str | None = None


def now_ts() -> int:
    return int(time.time())


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower()).strip("-")
    return slug or secrets.token_hex(4)


def normalize_mac(mac: str) -> str:
    return mac.strip().upper()


def validate_mac(mac: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", mac.strip()))


def validate_ip_or_empty(value: str | None, field_name: str) -> str | None:
    if not value:
        return None
    value = value.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IP address") from exc
    return value


def validate_broadcast(value: str | None) -> str:
    value = value.strip() if value else "255.255.255.255"
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Broadcast must be a valid IP address") from exc
    return value


def db() -> sqlite3.Connection:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with db_lock, db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                mac TEXT NOT NULL UNIQUE,
                ip TEXT,
                broadcast TEXT NOT NULL DEFAULT '255.255.255.255',
                description TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS watchdog_state (
                device_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                offline_since INTEGER,
                retry_count INTEGER NOT NULL DEFAULT 0,
                last_wol INTEGER,
                last_status INTEGER,
                last_check INTEGER,
                last_message TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time INTEGER NOT NULL,
                action TEXT NOT NULL,
                message TEXT NOT NULL,
                device_id TEXT,
                username TEXT,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
            );
            """
        )


def users_exist() -> bool:
    with db_lock, db() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return bool(row["c"])


def setup_required() -> bool:
    return not users_exist()


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db_lock, db() as conn:
        return conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def current_username() -> str | None:
    user = current_user()
    return str(user["username"]) if user else None


def current_role() -> str:
    user = current_user()
    return str(user["role"]) if user else "anonymous"


def can_wol() -> bool:
    return True


def can_watchdog() -> bool:
    return current_role() in {"user", "admin"}


def can_manage_devices() -> bool:
    return current_role() == "admin"


def can_manage_users() -> bool:
    return current_role() == "admin"


def permission_error(message: str = "Permission denied", status: int = 403):
    return jsonify({"ok": False, "error": message}), status


def watchdog_default_message() -> str:
    return "Watchdog disabled"


def add_history(action: str, message: str, device_id: str | None = None) -> None:
    with db_lock, db() as conn:
        conn.execute(
            """
            INSERT INTO history (time, action, message, device_id, username)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now_ts(), action, message, device_id, current_username()),
        )
        conn.execute(
            """
            DELETE FROM history
            WHERE id NOT IN (
                SELECT id FROM history
                ORDER BY time DESC, id DESC
                LIMIT ?
            )
            """,
            (MAX_HISTORY_ITEMS,),
        )


def list_devices() -> list[sqlite3.Row]:
    with db_lock, db() as conn:
        return list(conn.execute("SELECT * FROM devices ORDER BY name COLLATE NOCASE"))


def get_device(device_id: str) -> sqlite3.Row | None:
    with db_lock, db() as conn:
        return conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()


def get_watchdog(device_id: str) -> sqlite3.Row | None:
    with db_lock, db() as conn:
        return conn.execute(
            "SELECT * FROM watchdog_state WHERE device_id = ?",
            (device_id,),
        ).fetchone()


def ensure_watchdog_state(device_id: str) -> None:
    with db_lock, db() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO watchdog_state (device_id, last_message)
            VALUES (?, ?)
            """,
            (device_id, watchdog_default_message()),
        )


def list_history(limit: int = 20) -> list[sqlite3.Row]:
    with db_lock, db() as conn:
        return list(
            conn.execute(
                """
                SELECT *
                FROM history
                ORDER BY time DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            )
        )


def list_users() -> list[sqlite3.Row]:
    with db_lock, db() as conn:
        return list(
            conn.execute(
                "SELECT id, username, role, created_at, updated_at FROM users ORDER BY username COLLATE NOCASE"
            )
        )


def count_admins() -> int:
    with db_lock, db() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()
        return int(row["c"])


def create_user(username: str, password: str, role: str) -> None:
    username = username.strip()
    if not username:
        raise ValueError("Username is required")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters")
    if role not in {"user", "admin"}:
        raise ValueError("Invalid role")

    ts = now_ts()
    with db_lock, db() as conn:
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, generate_password_hash(password), role, ts, ts),
        )


def backup_db(reason: str) -> None:
    if not DB_PATH.exists():
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"simplewol-{stamp}-{slugify(reason)}.db"
    with db_lock, sqlite3.connect(DB_PATH) as src, sqlite3.connect(target) as dst:
        src.backup(dst)


def device_from_payload(payload: dict[str, Any], existing_id: str | None = None) -> Device:
    name = str(payload.get("name") or "").strip()
    raw_id = str(payload.get("id") or existing_id or name).strip()
    device_id = slugify(raw_id)
    mac = normalize_mac(str(payload.get("mac") or ""))
    ip = validate_ip_or_empty(str(payload.get("ip") or "").strip() or None, "IP")
    broadcast = validate_broadcast(str(payload.get("broadcast") or "255.255.255.255"))
    description = str(payload.get("description") or "").strip() or None

    if not name:
        raise ValueError("Name is required")
    if not validate_mac(mac):
        raise ValueError("MAC address must use format AA:BB:CC:DD:EE:FF")

    return Device(
        id=device_id,
        name=name,
        mac=mac,
        ip=ip,
        broadcast=broadcast,
        description=description,
    )


def ping(ip: str, timeout_seconds: int = 1) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_seconds), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds + 2,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def wake(device: sqlite3.Row) -> None:
    subprocess.run(
        ["wakeonlan", "-i", str(device["broadcast"]), str(device["mac"])],
        check=True,
        timeout=10,
    )


def migrate_legacy_files_if_empty() -> None:
    with db_lock, db() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()
        if int(row["c"]):
            return

    if not LEGACY_CONFIG_PATH.exists():
        return

    try:
        raw = yaml.safe_load(LEGACY_CONFIG_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        return

    devices: list[Device] = []
    used_ids: set[str] = set()
    used_macs: set[str] = set()

    for item in raw.get("devices", []):
        try:
            device = device_from_payload(item)
            if device.id in used_ids or device.mac in used_macs:
                continue
            used_ids.add(device.id)
            used_macs.add(device.mac)
            devices.append(device)
        except Exception:
            continue

    if not devices:
        return

    ts = now_ts()
    with db_lock, db() as conn:
        for d in devices:
            conn.execute(
                """
                INSERT INTO devices (id, name, mac, ip, broadcast, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (d.id, d.name, d.mac, d.ip, d.broadcast, d.description, ts, ts),
            )
            conn.execute(
                """
                INSERT INTO watchdog_state (device_id, last_message)
                VALUES (?, ?)
                """,
                (d.id, watchdog_default_message()),
            )

    add_history("migration", f"Imported {len(devices)} devices from devices.yaml")


def update_watchdog_state(device_id: str, **updates: Any) -> dict[str, Any]:
    ensure_watchdog_state(device_id)

    allowed = {
        "enabled",
        "offline_since",
        "retry_count",
        "last_wol",
        "last_status",
        "last_check",
        "last_message",
    }

    updates = {k: v for k, v in updates.items() if k in allowed}

    if not updates:
        row = get_watchdog(device_id)
        return dict(row) if row else {}

    fields = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [device_id]

    with db_lock, db() as conn:
        conn.execute(f"UPDATE watchdog_state SET {fields} WHERE device_id = ?", values)
        row = conn.execute(
            "SELECT * FROM watchdog_state WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row)


def watchdog_worker() -> None:
    while True:
        devices = list_devices()

        for device in devices:
            device_id = str(device["id"])
            ip = device["ip"]

            if not ip:
                continue

            wd = get_watchdog(device_id)
            if not wd or not wd["enabled"]:
                continue

            online = ping(str(ip))
            ts = now_ts()

            if online:
                update_watchdog_state(
                    device_id,
                    offline_since=None,
                    retry_count=0,
                    last_status=1,
                    last_check=ts,
                    last_message="Online",
                )
                continue

            offline_since = wd["offline_since"] or ts
            retry_count = int(wd["retry_count"] or 0)
            last_wol = wd["last_wol"]
            offline_for = ts - int(offline_since)

            if offline_for >= WATCHDOG_RESET_AFTER_SECONDS:
                retry_count = 0

            updates: dict[str, Any] = {
                "offline_since": offline_since,
                "retry_count": retry_count,
                "last_status": 0,
                "last_check": ts,
                "last_message": f"Offline for {offline_for // 60} min",
            }

            should_wake = offline_for >= OFFLINE_BEFORE_WOL_SECONDS
            retry_available = retry_count < WOL_RETRY_COUNT
            retry_due = last_wol is None or ts - int(last_wol) >= WOL_RETRY_INTERVAL_SECONDS

            if should_wake and retry_available and retry_due:
                try:
                    wake(device)
                    retry_count += 1
                    updates.update(
                        retry_count=retry_count,
                        last_wol=ts,
                        last_message=f"WOL sent by watchdog, retry {retry_count}/{WOL_RETRY_COUNT}",
                    )
                    add_history("watchdog_wake", f"WOL sent to {device['name']} by watchdog", device_id)
                except FileNotFoundError:
                    updates["last_message"] = "WOL failed: wakeonlan command not found"
                    add_history("error", f"WOL failed for {device['name']}: wakeonlan missing", device_id)
                except subprocess.SubprocessError as exc:
                    updates["last_message"] = f"WOL failed: {exc}"
                    add_history("error", f"WOL failed for {device['name']}: {exc}", device_id)

            elif retry_count >= WOL_RETRY_COUNT:
                updates["last_message"] = "Offline; watchdog retry limit reached"

            update_watchdog_state(device_id, **updates)

        time.sleep(PING_INTERVAL_SECONDS)


@app.template_filter("ts")
def ts_filter(value: int | None) -> str:
    if not value:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(value)))

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Simple WOL</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --card: #fff;
      --text: #101828;
      --muted: #667085;
      --border: #e4e7ec;
      --button: #155eef;
      --button-text: #fff;
      --danger: #d92d20;
      --online: #12b76a;
      --offline: #f04438;
      --shadow: 0 12px 32px rgba(16,24,40,.08);
    }
    body.dark {
      --bg: #0b1220;
      --card: #111827;
      --text: #f9fafb;
      --muted: #9ca3af;
      --border: #243044;
      --button: #528bff;
      --button-text: #07111f;
      --shadow: 0 12px 32px rgba(0,0,0,.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: radial-gradient(circle at top, rgba(21,94,239,.10), transparent 30%), var(--bg);
      color: var(--text);
      min-height: 100vh;
    }
    .page { width: min(1150px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0; }
    header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 28px; }
    h1 { margin: 0; font-size: clamp(28px, 5vw, 44px); letter-spacing: -.04em; }
    h2 { margin: 0 0 14px; }
    .muted, .description, .timestamp { color: var(--muted); }
    .top-actions { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; }
    button {
      border: 0;
      border-radius: 14px;
      padding: 12px 14px;
      font-size: 14px;
      font-weight: 800;
      cursor: pointer;
    }
    .pill, .secondary {
      border: 1px solid var(--border);
      background: var(--card);
      color: var(--text);
      box-shadow: var(--shadow);
    }
    .pill.active, .primary {
      background: var(--button);
      color: var(--button-text);
    }
    .danger {
      background: transparent;
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 18px; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 20px;
      box-shadow: var(--shadow);
    }
    .card-top { display: flex; justify-content: space-between; gap: 12px; align-items: flex-start; margin-bottom: 16px; }
    .device-name { margin: 0; font-size: 22px; letter-spacing: -.02em; }
    .description { margin: 6px 0 0; font-size: 14px; line-height: 1.4; }
    .status {
      display: inline-flex; align-items: center; gap: 7px;
      border: 1px solid var(--border); border-radius: 999px;
      padding: 7px 10px; font-size: 13px; font-weight: 800; white-space: nowrap;
    }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--muted); }
    .status.online .dot { background: var(--online); }
    .status.offline .dot { background: var(--offline); }
    dl { display: grid; grid-template-columns: 86px 1fr; gap: 8px 12px; margin: 0 0 18px; color: var(--muted); font-size: 14px; }
    dt { font-weight: 800; }
    dd { margin: 0; overflow-wrap: anywhere; }
    .watchdog {
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 14px;
      margin: 0 0 16px;
      background: rgba(128,128,128,.06);
    }
    .watchdog-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .watchdog-title { font-weight: 900; }
    .watchdog-message, .timestamp { font-size: 13px; margin-top: 8px; line-height: 1.4; }
    .switch { position: relative; display: inline-block; width: 54px; height: 30px; flex: 0 0 auto; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider { position: absolute; cursor: pointer; inset: 0; background: var(--border); border-radius: 999px; transition: .2s; }
    .slider:before { content: ""; position: absolute; height: 22px; width: 22px; left: 4px; top: 4px; background: white; border-radius: 50%; transition: .2s; }
    .switch input:checked + .slider { background: var(--online); }
    .switch input:checked + .slider:before { transform: translateX(24px); }
    .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .edit-actions { display: none; margin-top: 10px; }
    body.edit-mode .edit-actions { display: grid; }
    .panel { margin-top: 22px; }
    .list { display: grid; gap: 8px; font-size: 14px; color: var(--muted); }
    .user-row { display: grid; grid-template-columns: 1fr auto auto auto; gap: 10px; align-items: center; border-top: 1px solid var(--border); padding-top: 10px; }
    .modal-backdrop {
      position: fixed; inset: 0; background: rgba(0,0,0,.45);
      display: none; align-items: center; justify-content: center;
      padding: 16px; z-index: 10;
    }
    .modal-backdrop.show { display: flex; }
    .modal {
      width: min(560px, 100%);
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      padding: 20px;
    }
    .form-grid { display: grid; gap: 12px; }
    label { display: grid; gap: 6px; font-weight: 800; font-size: 14px; }
    input, select, textarea {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px;
      background: transparent;
      color: var(--text);
      font: inherit;
    }
    textarea { min-height: 180px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px; }
    .toast {
      position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%);
      background: var(--card); color: var(--text); border: 1px solid var(--border);
      border-radius: 999px; padding: 12px 18px; box-shadow: var(--shadow);
      display: none; font-weight: 800; z-index: 20;
    }
    .toast.show { display: block; }
    @media (max-width: 700px) {
      .page { width: min(100% - 20px, 1150px); padding: 18px 0; }
      header { flex-direction: column; }
      .top-actions { width: 100%; }
      .pill { flex: 1; }
      .actions, .user-row { grid-template-columns: 1fr; }
      dl { grid-template-columns: 72px 1fr; }
    }
  </style>
</head>
<body data-role="{{ role }}" data-setup-required="{{ 'true' if setup_required else 'false' }}">
  <main class="page">
    <header>
      <div>
        <h1>Wake-on-LAN</h1>
        <p class="muted">
          {% if user %}
            Logged in as <strong>{{ user.username }}</strong> / {{ user.role }}
          {% else %}
            Not logged in. Wake is allowed; watchdog and management require login.
          {% endif %}
        </p>
      </div>

      <div class="top-actions">
        {% if user %}
          <button class="pill" id="changePasswordButton" type="button">Change password</button>
          <button class="pill" id="logoutButton" type="button">Logout</button>
        {% else %}
          <button class="pill" id="loginButton" type="button">Login</button>
        {% endif %}

        {% if role == "admin" %}
          <button class="pill" id="editToggle" type="button">Edit devices</button>
          <button class="pill" id="addDeviceButton" type="button" style="display:none">Add device</button>
          <button class="pill" id="exportButton" type="button" style="display:none">Export</button>
          <button class="pill" id="importButton" type="button" style="display:none">Import</button>
          <button class="pill" id="usersButton" type="button">Users</button>
        {% endif %}

        <button class="pill" id="themeToggle" type="button">Theme</button>
      </div>
    </header>

    <section class="grid">
      {% for d in devices %}
        <article
          class="card"
          data-device-id="{{ d.id }}"
          data-name="{{ d.name }}"
          data-mac="{{ d.mac }}"
          data-ip="{{ d.ip or '' }}"
          data-broadcast="{{ d.broadcast }}"
          data-description="{{ d.description or '' }}"
        >
          <div class="card-top">
            <div>
              <h2 class="device-name">{{ d.name }}</h2>
              {% if d.description %}<p class="description">{{ d.description }}</p>{% endif %}
            </div>
            <span class="status unknown" id="status-{{ d.id }}">
              <span class="dot"></span>
              <span class="status-text">Checking</span>
            </span>
          </div>

          <dl>
            <dt>ID</dt><dd>{{ d.id }}</dd>
            <dt>IP</dt><dd>{{ d.ip or "not set" }}</dd>
            <dt>MAC</dt><dd>{{ d.mac }}</dd>
            <dt>Broadcast</dt><dd>{{ d.broadcast }}</dd>
          </dl>

          <div class="watchdog">
            <div class="watchdog-row">
              <div class="watchdog-title">WOL watchdog</div>
              <label class="switch">
                <input id="watchdog-toggle-{{ d.id }}" type="checkbox" onchange="toggleWatchdog('{{ d.id }}', this.checked)" {% if role not in ["user", "admin"] %}disabled{% endif %}>
                <span class="slider"></span>
              </label>
            </div>
            <div class="watchdog-message" id="watchdog-message-{{ d.id }}">Watchdog state unknown</div>
            <div class="timestamp" id="last-check-{{ d.id }}"></div>
            <div class="timestamp" id="last-wol-{{ d.id }}"></div>
          </div>

          <div class="actions">
            <button class="primary" type="button" onclick="wakeDevice('{{ d.id }}')">Wake now</button>
            <button class="secondary" type="button" onclick="checkStatus('{{ d.id }}')">Refresh status</button>
          </div>

          {% if role == "admin" %}
            <div class="actions edit-actions">
              <button class="secondary" type="button" onclick="openEditDevice('{{ d.id }}')">Edit</button>
              <button class="danger" type="button" onclick="deleteDevice('{{ d.id }}')">Remove</button>
            </div>
          {% endif %}
        </article>
      {% else %}
        <article class="card">
          <h2>No devices configured</h2>
          <p class="description">Login as admin to add devices.</p>
        </article>
      {% endfor %}
    </section>

    <section class="card panel">
      <h2>Recent history</h2>
      <div class="list">
        {% for item in history %}
          <div>{{ item.time | ts }} - {{ item.message }}{% if item.username %} / {{ item.username }}{% endif %}</div>
        {% else %}
          <div>No recent events.</div>
        {% endfor %}
      </div>
    </section>
  </main>

  <div class="modal-backdrop" id="setupModal">
    <form class="modal" id="setupForm">
      <h2>Create first admin</h2>
      <p class="muted">No users exist yet. Create the first admin account.</p>
      <div class="form-grid">
        <label>Username <input id="setupUsername" required autocomplete="username"></label>
        <label>Password <input id="setupPassword" type="password" required autocomplete="new-password"></label>
      </div>
      <div class="modal-actions">
        <button class="primary" type="submit">Create admin</button>
      </div>
    </form>
  </div>

  <div class="modal-backdrop" id="loginModal">
    <form class="modal" id="loginForm">
      <h2>Login</h2>
      <div class="form-grid">
        <label>Username <input id="loginUsername" required autocomplete="username"></label>
        <label>Password <input id="loginPassword" type="password" required autocomplete="current-password"></label>
      </div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeModal('loginModal')">Cancel</button>
        <button class="primary" type="submit">Login</button>
      </div>
    </form>
  </div>

  <div class="modal-backdrop" id="passwordModal">
    <form class="modal" id="passwordForm">
      <h2>Change password</h2>
      <div class="form-grid">
        <label>Current password <input id="currentPassword" type="password" required></label>
        <label>New password <input id="newPassword" type="password" required></label>
      </div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeModal('passwordModal')">Cancel</button>
        <button class="primary" type="submit">Save</button>
      </div>
    </form>
  </div>

  <div class="modal-backdrop" id="deviceModal">
    <form class="modal" id="deviceForm">
      <h2 id="modalTitle">Add device</h2>
      <div class="form-grid">
        <label>ID <input id="deviceId" placeholder="desktop-pc"></label>
        <label>Name <input id="deviceName" required></label>
        <label>MAC address <input id="deviceMac" required placeholder="AA:BB:CC:DD:EE:FF"></label>
        <label>IP address <input id="deviceIp" placeholder="192.168.1.50"></label>
        <label>Broadcast <input id="deviceBroadcast" value="255.255.255.255"></label>
        <label>Description <input id="deviceDescription"></label>
      </div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeModal('deviceModal')">Cancel</button>
        <button class="primary" type="submit">Save</button>
      </div>
    </form>
  </div>

  <div class="modal-backdrop" id="importModal">
    <form class="modal" id="importForm">
      <h2>Import devices.yaml</h2>
      <div class="form-grid">
        <label>YAML <textarea id="importYaml" required></textarea></label>
      </div>
      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeModal('importModal')">Cancel</button>
        <button class="primary" type="submit">Import</button>
      </div>
    </form>
  </div>

  <div class="modal-backdrop" id="usersModal">
    <div class="modal">
      <h2>User management</h2>
      <div class="form-grid">
        <label>New username <input id="newUserUsername"></label>
        <label>New password <input id="newUserPassword" type="password"></label>
        <label>Role
          <select id="newUserRole">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <button class="primary" type="button" onclick="createUser()">Add user</button>
      </div>

      <div class="list" id="usersList" style="margin-top:18px"></div>

      <div class="modal-actions">
        <button class="secondary" type="button" onclick="closeModal('usersModal')">Close</button>
      </div>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const role = document.body.dataset.role;
    const setupRequired = document.body.dataset.setupRequired === "true";
    let editingDeviceId = null;
    let editMode = false;

    const savedTheme = localStorage.getItem("theme");
    if (savedTheme === "dark" || (!savedTheme && window.matchMedia("(prefers-color-scheme: dark)").matches)) {
      document.body.classList.add("dark");
    }

    if (setupRequired) openModal("setupModal");

    document.getElementById("themeToggle").addEventListener("click", () => {
      document.body.classList.toggle("dark");
      localStorage.setItem("theme", document.body.classList.contains("dark") ? "dark" : "light");
    });

    document.getElementById("loginButton")?.addEventListener("click", () => openModal("loginModal"));
    document.getElementById("changePasswordButton")?.addEventListener("click", () => openModal("passwordModal"));
    document.getElementById("usersButton")?.addEventListener("click", async () => {
      await loadUsers();
      openModal("usersModal");
    });

    document.getElementById("logoutButton")?.addEventListener("click", async () => {
      await fetch("/logout", { method: "POST" });
      location.reload();
    });

    document.getElementById("editToggle")?.addEventListener("click", () => {
      editMode = !editMode;
      document.body.classList.toggle("edit-mode", editMode);
      document.getElementById("editToggle").classList.toggle("active", editMode);
      document.getElementById("editToggle").textContent = editMode ? "Done editing" : "Edit devices";
      document.getElementById("addDeviceButton").style.display = editMode ? "inline-block" : "none";
      document.getElementById("exportButton").style.display = editMode ? "inline-block" : "none";
      document.getElementById("importButton").style.display = editMode ? "inline-block" : "none";
    });

    document.getElementById("addDeviceButton")?.addEventListener("click", openAddDevice);
    document.getElementById("importButton")?.addEventListener("click", () => openModal("importModal"));
    document.getElementById("exportButton")?.addEventListener("click", () => {
      window.location.href = "/api/config/export";
    });

    function toast(message) {
      const el = document.getElementById("toast");
      el.textContent = message;
      el.classList.add("show");
      setTimeout(() => el.classList.remove("show"), 3000);
    }

    function openModal(id) { document.getElementById(id).classList.add("show"); }
    function closeModal(id) { document.getElementById(id).classList.remove("show"); }

    function formatTime(ts) {
      if (!ts) return "";
      return new Date(ts * 1000).toLocaleString();
    }

    function setStatus(deviceId, online) {
      const el = document.getElementById(`status-${deviceId}`);
      if (!el) return;
      el.classList.remove("unknown", "online", "offline");
      el.classList.add(online ? "online" : "offline");
      el.querySelector(".status-text").textContent = online ? "Online" : "Offline";
    }

    function setWatchdog(deviceId, data) {
      const toggle = document.getElementById(`watchdog-toggle-${deviceId}`);
      const message = document.getElementById(`watchdog-message-${deviceId}`);
      const lastCheck = document.getElementById(`last-check-${deviceId}`);
      const lastWol = document.getElementById(`last-wol-${deviceId}`);
      if (toggle) toggle.checked = !!data.enabled;
      if (message) message.textContent = data.last_message || "Watchdog state unknown";
      if (lastCheck) lastCheck.textContent = data.last_check ? `Last checked: ${formatTime(data.last_check)}` : "";
      if (lastWol) lastWol.textContent = data.last_wol ? `Last WOL: ${formatTime(data.last_wol)}` : "";
    }

    async function checkStatus(deviceId) {
      const response = await fetch(`/api/status/${deviceId}`);
      const data = await response.json();
      setStatus(deviceId, data.online);
      if (data.watchdog) setWatchdog(deviceId, data.watchdog);
    }

    async function wakeDevice(deviceId) {
      const response = await fetch(`/api/wake/${deviceId}`, { method: "POST" });
      const data = await response.json();
      toast(data.ok ? `Wake packet sent to ${data.name}` : data.error);
      setTimeout(() => checkStatus(deviceId), 2500);
    }

    async function toggleWatchdog(deviceId, enabled) {
      const response = await fetch(`/api/watchdog/${deviceId}`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({enabled})
      });
      const data = await response.json();
      if (!data.ok) {
        toast(data.error);
        const toggle = document.getElementById(`watchdog-toggle-${deviceId}`);
        if (toggle) toggle.checked = !enabled;
        return;
      }
      setWatchdog(deviceId, data.watchdog);
    }

    document.getElementById("setupForm").addEventListener("submit", async e => {
      e.preventDefault();
      const response = await fetch("/setup", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          username: document.getElementById("setupUsername").value,
          password: document.getElementById("setupPassword").value
        })
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      location.reload();
    });

    document.getElementById("loginForm").addEventListener("submit", async e => {
      e.preventDefault();
      const response = await fetch("/login", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          username: document.getElementById("loginUsername").value,
          password: document.getElementById("loginPassword").value
        })
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      location.reload();
    });

    document.getElementById("passwordForm").addEventListener("submit", async e => {
      e.preventDefault();
      const response = await fetch("/api/me/password", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          current_password: document.getElementById("currentPassword").value,
          new_password: document.getElementById("newPassword").value
        })
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      toast("Password changed");
      closeModal("passwordModal");
    });

    function openAddDevice() {
      editingDeviceId = null;
      document.getElementById("modalTitle").textContent = "Add device";
      document.getElementById("deviceId").value = "";
      document.getElementById("deviceName").value = "";
      document.getElementById("deviceMac").value = "";
      document.getElementById("deviceIp").value = "";
      document.getElementById("deviceBroadcast").value = "255.255.255.255";
      document.getElementById("deviceDescription").value = "";
      openModal("deviceModal");
    }

    function openEditDevice(deviceId) {
      const card = document.querySelector(`[data-device-id="${deviceId}"]`);
      if (!card) return;
      editingDeviceId = deviceId;
      document.getElementById("modalTitle").textContent = "Edit device";
      document.getElementById("deviceId").value = card.dataset.deviceId || "";
      document.getElementById("deviceName").value = card.dataset.name || "";
      document.getElementById("deviceMac").value = card.dataset.mac || "";
      document.getElementById("deviceIp").value = card.dataset.ip || "";
      document.getElementById("deviceBroadcast").value = card.dataset.broadcast || "255.255.255.255";
      document.getElementById("deviceDescription").value = card.dataset.description || "";
      openModal("deviceModal");
    }

    document.getElementById("deviceForm").addEventListener("submit", async e => {
      e.preventDefault();
      const payload = {
        id: document.getElementById("deviceId").value,
        name: document.getElementById("deviceName").value,
        mac: document.getElementById("deviceMac").value,
        ip: document.getElementById("deviceIp").value,
        broadcast: document.getElementById("deviceBroadcast").value,
        description: document.getElementById("deviceDescription").value
      };
      const response = await fetch(editingDeviceId ? `/api/devices/${editingDeviceId}` : "/api/devices", {
        method: editingDeviceId ? "PUT" : "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      location.reload();
    });

    async function deleteDevice(deviceId) {
      if (!confirm("Remove this device and its watchdog state?")) return;
      const response = await fetch(`/api/devices/${deviceId}`, {method: "DELETE"});
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      location.reload();
    }

    document.getElementById("importForm").addEventListener("submit", async e => {
      e.preventDefault();
      const response = await fetch("/api/config/import", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({yaml: document.getElementById("importYaml").value})
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      location.reload();
    });

    async function loadUsers() {
      const response = await fetch("/api/users");
      const data = await response.json();
      if (!data.ok) return toast(data.error);

      const el = document.getElementById("usersList");
      el.innerHTML = "";

      data.users.forEach(u => {
        const row = document.createElement("div");
        row.className = "user-row";
        row.innerHTML = `
          <div><strong>${u.username}</strong> / ${u.role}</div>
          <button class="secondary" onclick="setUserRole(${u.id}, '${u.role === "admin" ? "user" : "admin"}')">Make ${u.role === "admin" ? "user" : "admin"}</button>
          <button class="secondary" onclick="resetUserPassword(${u.id})">Reset password</button>
          <button class="danger" onclick="deleteUser(${u.id})">Delete</button>
        `;
        el.appendChild(row);
      });
    }

    async function createUser() {
      const response = await fetch("/api/users", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          username: document.getElementById("newUserUsername").value,
          password: document.getElementById("newUserPassword").value,
          role: document.getElementById("newUserRole").value
        })
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      await loadUsers();
      toast("User added");
    }

    async function setUserRole(userId, role) {
      const response = await fetch(`/api/users/${userId}/role`, {
        method: "PUT",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({role})
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      await loadUsers();
    }

    async function resetUserPassword(userId) {
      const password = prompt("New password:");
      if (!password) return;
      const response = await fetch(`/api/users/${userId}/password`, {
        method: "PUT",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({password})
      });
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      toast("Password reset");
    }

    async function deleteUser(userId) {
      if (!confirm("Delete this user?")) return;
      const response = await fetch(`/api/users/${userId}`, {method: "DELETE"});
      const data = await response.json();
      if (!data.ok) return toast(data.error);
      await loadUsers();
    }

    document.querySelectorAll("[data-device-id]").forEach(card => checkStatus(card.dataset.deviceId));
    setInterval(() => {
      document.querySelectorAll("[data-device-id]").forEach(card => checkStatus(card.dataset.deviceId));
    }, 30000);
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    user = current_user()
    return render_template_string(
        PAGE,
        devices=list_devices(),
        history=list_history(20),
        users=list_users() if can_manage_users() else [],
        role=current_role(),
        user=user,
        setup_required=setup_required(),
    )


@app.route("/setup", methods=["POST"])
def setup():
    if not setup_required():
        return permission_error("Setup already completed", 403)

    payload = request.get_json(silent=True) or {}
    try:
        create_user(str(payload.get("username") or ""), str(payload.get("password") or ""), "admin")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    with db_lock, db() as conn:
        user = conn.execute("SELECT id FROM users WHERE username = ?", (payload.get("username"),)).fetchone()
        session["user_id"] = user["id"]

    add_history("setup", "First admin account created")
    return jsonify({"ok": True})


@app.route("/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "")
    password = str(payload.get("password") or "")

    with db_lock, db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "Invalid username or password"}), 401

    session["user_id"] = user["id"]
    add_history("login", f"{username} logged in")
    return jsonify({"ok": True})


@app.route("/logout", methods=["POST"])
def logout():
    username = current_username()
    session.clear()
    if username:
        add_history("logout", f"{username} logged out")
    return jsonify({"ok": True})


@app.route("/api/status/<device_id>")
def api_status(device_id: str):
    device = get_device(device_id)
    if not device:
        return jsonify({"online": False, "error": "Invalid device ID"}), 404

    ensure_watchdog_state(device_id)
    wd = get_watchdog(device_id)
    online = False if not device["ip"] else ping(str(device["ip"]))

    return jsonify({"online": online, "name": device["name"], "watchdog": dict(wd)})


@app.route("/api/wake/<device_id>", methods=["POST"])
def api_wake(device_id: str):
    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": "Invalid device ID"}), 404

    try:
        wake(device)
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "wakeonlan command not found"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "wakeonlan command timed out"}), 500
    except subprocess.CalledProcessError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    add_history("manual_wake", f"Manual WOL sent to {device['name']}", device_id)
    return jsonify({"ok": True, "name": device["name"]})


@app.route("/api/watchdog/<device_id>", methods=["POST"])
def api_watchdog(device_id: str):
    if not can_watchdog():
        return permission_error("Login as user or admin required", 403)

    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": "Invalid device ID"}), 404

    payload = request.get_json(silent=True) or {}
    enabled = 1 if payload.get("enabled") else 0

    wd = update_watchdog_state(
        device_id,
        enabled=enabled,
        offline_since=None,
        retry_count=0,
        last_wol=None,
        last_message="Watchdog enabled" if enabled else "Watchdog disabled",
    )

    add_history("watchdog_toggle", f"Watchdog {'enabled' if enabled else 'disabled'} for {device['name']}", device_id)
    return jsonify({"ok": True, "watchdog": wd})


@app.route("/api/devices", methods=["POST"])
def api_add_device():
    if not can_manage_devices():
        return permission_error("Admin required", 403)

    payload = request.get_json(silent=True) or {}
    try:
        device = device_from_payload(payload)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    ts = now_ts()
    backup_db("add-device")

    try:
        with db_lock, db() as conn:
            conn.execute(
                """
                INSERT INTO devices (id, name, mac, ip, broadcast, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (device.id, device.name, device.mac, device.ip, device.broadcast, device.description, ts, ts),
            )
            conn.execute(
                "INSERT INTO watchdog_state (device_id, last_message) VALUES (?, ?)",
                (device.id, watchdog_default_message()),
            )
    except sqlite3.IntegrityError as exc:
        return jsonify({"ok": False, "error": f"Duplicate ID or MAC: {exc}"}), 400

    add_history("device_add", f"Added device {device.name}", device.id)
    return jsonify({"ok": True})


@app.route("/api/devices/<device_id>", methods=["PUT"])
def api_update_device(device_id: str):
    if not can_manage_devices():
        return permission_error("Admin required", 403)

    existing = get_device(device_id)
    if not existing:
        return jsonify({"ok": False, "error": "Invalid device ID"}), 404

    payload = request.get_json(silent=True) or {}

    try:
        updated = device_from_payload(payload, existing_id=device_id)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    ts = now_ts()
    backup_db("edit-device")

    try:
        with db_lock, db() as conn:
            conn.execute(
                """
                UPDATE devices
                SET id = ?, name = ?, mac = ?, ip = ?, broadcast = ?, description = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    updated.id,
                    updated.name,
                    updated.mac,
                    updated.ip,
                    updated.broadcast,
                    updated.description,
                    ts,
                    device_id,
                ),
            )

            if updated.id != device_id:
                conn.execute(
                    "UPDATE watchdog_state SET device_id = ? WHERE device_id = ?",
                    (updated.id, device_id),
                )
                conn.execute(
                    "UPDATE history SET device_id = ? WHERE device_id = ?",
                    (updated.id, device_id),
                )
    except sqlite3.IntegrityError as exc:
        return jsonify({"ok": False, "error": f"Duplicate ID or MAC: {exc}"}), 400

    add_history("device_edit", f"Edited device {updated.name}", updated.id)
    return jsonify({"ok": True})


@app.route("/api/devices/<device_id>", methods=["DELETE"])
def api_delete_device(device_id: str):
    if not can_manage_devices():
        return permission_error("Admin required", 403)

    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": "Invalid device ID"}), 404

    backup_db("delete-device")

    with db_lock, db() as conn:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))

    add_history("device_delete", f"Removed device {device['name']}", device_id)
    return jsonify({"ok": True})


@app.route("/api/config/export")
def api_config_export():
    if not can_manage_devices():
        return redirect(url_for("index"))

    data = {
        "devices": [
            {
                "id": d["id"],
                "name": d["name"],
                "mac": d["mac"],
                "broadcast": d["broadcast"],
                **({"ip": d["ip"]} if d["ip"] else {}),
                **({"description": d["description"]} if d["description"] else {}),
            }
            for d in list_devices()
        ]
    }

    return Response(
        yaml.safe_dump(data, sort_keys=False),
        mimetype="application/x-yaml",
        headers={"Content-Disposition": "attachment; filename=devices.yaml"},
    )


@app.route("/api/config/import", methods=["POST"])
def api_config_import():
    if not can_manage_devices():
        return permission_error("Admin required", 403)

    payload = request.get_json(silent=True) or {}
    yaml_text = str(payload.get("yaml") or "")

    try:
        raw = yaml.safe_load(yaml_text) or {}
        imported = [device_from_payload(item) for item in raw.get("devices", [])]
        if len({d.id for d in imported}) != len(imported):
            raise ValueError("Duplicate device ID")
        if len({d.mac for d in imported}) != len(imported):
            raise ValueError("Duplicate MAC")
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Invalid import: {exc}"}), 400

    backup_db("import-config")
    ts = now_ts()

    with db_lock, db() as conn:
        conn.execute("DELETE FROM devices")
        for d in imported:
            conn.execute(
                """
                INSERT INTO devices (id, name, mac, ip, broadcast, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (d.id, d.name, d.mac, d.ip, d.broadcast, d.description, ts, ts),
            )
            conn.execute(
                "INSERT INTO watchdog_state (device_id, last_message) VALUES (?, ?)",
                (d.id, watchdog_default_message()),
            )

    add_history("config_import", "Imported device config")
    return jsonify({"ok": True})


@app.route("/api/me/password", methods=["POST"])
def api_change_own_password():
    user = current_user()
    if not user:
        return permission_error("Login required", 403)

    payload = request.get_json(silent=True) or {}
    current_password = str(payload.get("current_password") or "")
    new_password = str(payload.get("new_password") or "")

    if len(new_password) < 6:
        return jsonify({"ok": False, "error": "New password must be at least 6 characters"}), 400

    with db_lock, db() as conn:
        full_user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not check_password_hash(full_user["password_hash"], current_password):
            return jsonify({"ok": False, "error": "Current password is incorrect"}), 400

        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(new_password), now_ts(), user["id"]),
        )

    add_history("password_change", f"{user['username']} changed their password")
    return jsonify({"ok": True})


@app.route("/api/users")
def api_users():
    if not can_manage_users():
        return permission_error("Admin required", 403)

    return jsonify(
        {
            "ok": True,
            "users": [
                {
                    "id": u["id"],
                    "username": u["username"],
                    "role": u["role"],
                    "created_at": u["created_at"],
                    "updated_at": u["updated_at"],
                }
                for u in list_users()
            ],
        }
    )


@app.route("/api/users", methods=["POST"])
def api_create_user():
    if not can_manage_users():
        return permission_error("Admin required", 403)

    payload = request.get_json(silent=True) or {}
    try:
        create_user(
            str(payload.get("username") or ""),
            str(payload.get("password") or ""),
            str(payload.get("role") or "user"),
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    add_history("user_add", f"Created user {payload.get('username')}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>/role", methods=["PUT"])
def api_set_user_role(user_id: int):
    if not can_manage_users():
        return permission_error("Admin required", 403)

    payload = request.get_json(silent=True) or {}
    role = str(payload.get("role") or "")

    if role not in {"user", "admin"}:
        return jsonify({"ok": False, "error": "Invalid role"}), 400

    with db_lock, db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if target["role"] == "admin" and role != "admin" and count_admins() <= 1:
            return jsonify({"ok": False, "error": "Cannot demote the last admin"}), 400

        conn.execute(
            "UPDATE users SET role = ?, updated_at = ? WHERE id = ?",
            (role, now_ts(), user_id),
        )

    add_history("user_role", f"Changed role for {target['username']} to {role}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>/password", methods=["PUT"])
def api_reset_user_password(user_id: int):
    if not can_manage_users():
        return permission_error("Admin required", 403)

    payload = request.get_json(silent=True) or {}
    password = str(payload.get("password") or "")

    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters"}), 400

    with db_lock, db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        conn.execute(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (generate_password_hash(password), now_ts(), user_id),
        )

    add_history("user_password_reset", f"Reset password for {target['username']}")
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id: int):
    if not can_manage_users():
        return permission_error("Admin required", 403)

    with db_lock, db() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if target["role"] == "admin" and count_admins() <= 1:
            return jsonify({"ok": False, "error": "Cannot delete the last admin"}), 400

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    if session.get("user_id") == user_id:
        session.clear()

    add_history("user_delete", f"Deleted user {target['username']}")
    return jsonify({"ok": True})


def start() -> None:
    init_db()
    migrate_legacy_files_if_empty()


init_db()
migrate_legacy_files_if_empty()

if os.environ.get("SIMPLE_WOL_START_WORKER", "1") == "1":
    threading.Thread(target=watchdog_worker, daemon=True).start()


if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
