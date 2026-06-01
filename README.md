# Simple WOL

A lightweight Wake-on-LAN web dashboard.

Features:

- Wake devices from a browser
- Ping-based online/offline status
- SQLite storage
- Web-based first admin setup
- User roles
- Watchdog auto-wake
- Device add/edit/delete
- YAML import/export
- Event history
- Dark mode
- systemd + gunicorn deployment

---

## Permissions

| Role | Wake | Watchdog | Manage Devices | Import/Export | Manage Users |
|---|---:|---:|---:|---:|---:|
| No login | Yes | No | No | No | No |
| User | Yes | Yes | No | No | No |
| Admin | Yes | Yes | Yes | Yes | Yes |

On first launch, the web UI asks you to create the first admin user.

---

## Requirements

Debian/Ubuntu packages:

```bash
apt install -y python3 python3-venv python3-full wakeonlan iputils-ping
````

Python packages:

```bash
flask
pyyaml
gunicorn
werkzeug
```

---

## Quick Install

```bash
git clone https://git.micin.cz/stalker/simplewol.git
cd simplewol
chmod +x install.sh
sudo ./install.sh
```

Then open:

```text
http://SERVER-IP:80
```

---

## Manual Install

```bash
mkdir -p /opt/simplewol
cd /opt/simplewol
```

Copy `app.py` into `/opt/simplewol/app.py`.

Create virtual environment:

```bash
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install flask pyyaml gunicorn werkzeug
```

Run manually:

```bash
SIMPLE_WOL_SECRET_KEY="$(openssl rand -hex 32)" \
./venv/bin/gunicorn app:app --bind 0.0.0.0:80 --workers 1
```

---

## systemd Service

Create:

```bash
nano /etc/systemd/system/simplewol.service
```

Example:

```ini
[Unit]
Description=Simple Wake-on-LAN Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/simplewol
Environment=SIMPLE_WOL_DIR=/opt/simplewol
Environment=SIMPLE_WOL_DB=/opt/simplewol/simplewol.db
Environment=SIMPLE_WOL_SECRET_KEY=replace-with-random-secret
ExecStart=/opt/simplewol/venv/bin/gunicorn app:app --bind 0.0.0.0:80 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
systemctl daemon-reload
systemctl enable --now simplewol.service
```

Logs:

```bash
journalctl -u simplewol.service -f
```

---

## Important

Use only one gunicorn worker:

```bash
--workers 1
```

The watchdog runs in-process. Multiple workers would duplicate watchdog checks.

---

## Database

SQLite database location:

```text
/opt/simplewol/simplewol.db
```

Backups are stored in:

```text
/opt/simplewol/backups/
```

---

## Import / Export

Admins can import/export `devices.yaml` from the web UI.

Example format:

```yaml
devices:
  - id: desktop-pc
    name: Desktop PC
    mac: "AA:BB:CC:DD:EE:FF"
    ip: "192.168.1.50"
    broadcast: "192.168.1.255"
    description: Main workstation
```

---

## Troubleshooting

Check service:

```bash
systemctl status simplewol.service
```

Check logs:

```bash
journalctl -u simplewol.service -n 100 --no-pager
```

Test WOL manually:

```bash
wakeonlan AA:BB:CC:DD:EE:FF
```

Check app files:

```bash
du -h --max-depth=1 /opt/simplewol | sort -hr
```

---

## Reset First Admin

Stop service:

```bash
systemctl stop simplewol.service
```

Delete database:

```bash
rm /opt/simplewol/simplewol.db
```

Start service:

```bash
systemctl start simplewol.service
```

Then open the web UI and create a new first admin.

Warning: this removes devices, users, watchdog state, and history.
