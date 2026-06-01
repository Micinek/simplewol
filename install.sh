#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/simplewol"
SERVICE_FILE="/etc/systemd/system/simplewol.service"
PORT="${SIMPLE_WOL_PORT:-80}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
if [ -t 1 ]; then
    GREEN="\033[0;32m"
    YELLOW="\033[1;33m"
    RED="\033[0;31m"
    BLUE="\033[0;34m"
    NC="\033[0m"
else
    GREEN=""
    YELLOW=""
    RED=""
    BLUE=""
    NC=""
fi

info() {
    echo -e "${GREEN}$1${NC}"
}

warn() {
    echo -e "${YELLOW}$1${NC}"
}

error() {
    echo -e "${RED}$1${NC}"
}

section() {
    echo
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo
}

section "Simple WOL Installer"

if [ "$(id -u)" -ne 0 ]; then
    error "Please run as root."
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/app.py" ]; then
    error "app.py not found next to install.sh."
    echo "Run this installer from the cloned repository."
    exit 1
fi

info "[1/8] Installing system packages..."
apt update
apt install -y \
    python3 \
    python3-venv \
    python3-full \
    wakeonlan \
    iputils-ping \
    iproute2 \
    curl \
    openssl

info "[2/8] Creating application directory..."
mkdir -p "$APP_DIR"

info "[3/8] Copying application files..."
cp "$SCRIPT_DIR/app.py" "$APP_DIR/app.py"

if [ -f "$SCRIPT_DIR/README.md" ]; then
    cp "$SCRIPT_DIR/README.md" "$APP_DIR/README.md"
fi

info "[4/8] Creating Python virtual environment..."
python3 -m venv "$APP_DIR/venv"

info "[5/8] Installing Python dependencies..."
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install \
    flask \
    pyyaml \
    gunicorn \
    werkzeug

info "[6/8] Creating secret key..."
SECRET_KEY="$(openssl rand -hex 32)"

info "[7/8] Writing systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Simple Wake-on-LAN Web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
Environment=SIMPLE_WOL_DIR=$APP_DIR
Environment=SIMPLE_WOL_DB=$APP_DIR/simplewol.db
Environment=SIMPLE_WOL_SECRET_KEY=$SECRET_KEY
ExecStart=$APP_DIR/venv/bin/gunicorn app:app --bind 0.0.0.0:$PORT --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

info "[8/8] Enabling service..."
systemctl daemon-reload
systemctl enable --now simplewol.service

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

if [ -z "$IP" ]; then
    IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
fi

section "Simple WOL Installed Successfully"

if [ -n "$IP" ]; then
    info "Web UI:"
    echo "  http://$IP:$PORT"
else
    warn "Web UI:"
    echo "  http://SERVER-IP:$PORT"
fi

echo

info "First Launch:"
echo "  Create the first admin account from the web UI."

echo

info "Service:"
echo "  systemctl status simplewol.service"

echo

info "Logs:"
echo "  journalctl -u simplewol.service -f"

echo

info "Files:"
echo "  Application: $APP_DIR"
echo "  Database:    $APP_DIR/simplewol.db"
echo "  Backups:     $APP_DIR/backups"

echo