#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Pi Backup Manager — installer
# Usage:  bash install.sh
# Run as a normal user (not root). sudo access is required for systemd setup.
# ─────────────────────────────────────────────────────────────────────────────
set -e

INSTALL_DIR="$HOME/pi-backup-manager"
SERVICE_NAME="pi-backup-manager"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PORT="${PBM_PORT:-7823}"
IMGBAK_REPO="$HOME/RonR-RPi-image-utils"
IMGBAK_BIN="/usr/local/sbin/image-backup"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}   $*"; }
step()  { echo -e "${CYAN}[step]${NC}   $*"; }
die()   { echo -e "${RED}[error]${NC}  $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] && die "Do not run as root. Run as your normal user with sudo access."
command -v python3 >/dev/null || die "python3 not found. Install it with: sudo apt install python3"
command -v sudo    >/dev/null || die "sudo not found."

PYTHON="$(command -v python3)"

info "Installing Pi Backup Manager for user: $USER"
info "Install directory: $INSTALL_DIR"
info "Service port:      $PORT"
echo

# ── Create install directory ──────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

# ── Copy server.py ────────────────────────────────────────────────────────────
step "Copying server.py…"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/server.py" ]]; then
    cp "$SCRIPT_DIR/server.py" "$INSTALL_DIR/server.py"
    info "Copied server.py from $SCRIPT_DIR"
elif [[ -f "$PWD/server.py" ]]; then
    cp "$PWD/server.py" "$INSTALL_DIR/server.py"
    info "Copied server.py from $PWD"
else
    die "server.py not found alongside install.sh or in current directory."
fi

# ── Syntax-check server.py ────────────────────────────────────────────────────
step "Syntax-checking server.py…"
"$PYTHON" -c "import py_compile; py_compile.compile('${INSTALL_DIR}/server.py', doraise=True)" \
    || die "server.py has a syntax error — aborting."
info "Syntax OK."

# ── Install Flask ─────────────────────────────────────────────────────────────
step "Checking for Flask…"
if ! "$PYTHON" -c "import flask" 2>/dev/null; then
    info "Installing Flask via apt (recommended for Raspberry Pi OS)…"
    sudo apt-get install -y python3-flask -q \
        || {
            warn "apt install failed — falling back to pip…"
            pip3 install flask --break-system-packages -q \
                || pip3 install flask -q \
                || die "Flask install failed. Try manually: sudo apt install python3-flask"
        }
    info "Flask installed."
else
    info "Flask already present."
fi

# ── Install zerofree ─────────────────────────────────────────────────────────
step "Checking for zerofree…"
if command -v zerofree >/dev/null 2>&1; then
    info "zerofree already installed."
else
    info "Installing zerofree (used by Compact Image feature)…"
    sudo apt-get install -y zerofree -q \
        || warn "zerofree install failed — Compact Image will use slower fallback method."
fi

# ── Install image-backup (RonR RPi-image-utils) ───────────────────────────────
step "Checking for image-backup…"
if [[ -x "$IMGBAK_BIN" ]]; then
    info "image-backup already installed at $IMGBAK_BIN."
else
    info "image-backup not found — installing from GitHub…"

    # Ensure git is available
    if ! command -v git >/dev/null 2>&1; then
        info "Installing git…"
        sudo apt-get install -y git -q || die "Failed to install git."
    fi

    # Clone the repo
    if [[ -d "$IMGBAK_REPO" ]]; then
        info "Updating existing clone at $IMGBAK_REPO…"
        git -C "$IMGBAK_REPO" pull --ff-only \
            || { warn "git pull failed — removing and re-cloning…"; rm -rf "$IMGBAK_REPO"; }
    fi

    if [[ ! -d "$IMGBAK_REPO" ]]; then
        info "Cloning RonR-RPi-image-utils…"
        git clone https://github.com/seamusdemora/RonR-RPi-image-utils.git "$IMGBAK_REPO" \
            || die "Clone failed — check internet connectivity."
    fi

    # Install binaries to /usr/local/sbin
    info "Installing image-* utilities to /usr/local/sbin…"
    sudo install --mode=755 "$IMGBAK_REPO"/image-* /usr/local/sbin \
        || die "Failed to install image-backup binaries."

    # Verify
    if [[ -x "$IMGBAK_BIN" ]]; then
        info "image-backup installed successfully at $IMGBAK_BIN."
    else
        die "image-backup install verification failed — $IMGBAK_BIN not found."
    fi
fi

# ── Check for Runtipi ─────────────────────────────────────────────────────────
step "Checking for Runtipi…"
if [[ -f "$HOME/runtipi/runtipi-cli" ]]; then
    info "Runtipi found at $HOME/runtipi."
else
    warn "Runtipi not found at $HOME/runtipi."
    warn "If you use Runtipi, install it first: https://runtipi.io/docs/getting-started/installation"
    warn "Then update the Runtipi Directory in the backup manager settings."
fi

# ── Docker group ──────────────────────────────────────────────────────────────
step "Checking Docker group membership…"
if getent group docker &>/dev/null; then
    if id -nG "$USER" | grep -qw docker; then
        info "$USER is already in the docker group."
    else
        sudo usermod -aG docker "$USER"
        info "Added $USER to the docker group."
        warn "Docker group change takes effect on next login (the service will work immediately)."
    fi
else
    warn "Docker group not found — Docker may not be installed yet."
    warn "After installing Docker, run: sudo usermod -aG docker \$USER"
    warn "Then restart the service:     sudo systemctl restart $SERVICE_NAME"
fi

# ── Write systemd unit ────────────────────────────────────────────────────────
step "Writing systemd service…"
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Pi Backup Manager Web UI
After=network.target
After=docker.socket
Wants=docker.socket

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/server.py
Restart=on-failure
RestartSec=5
Environment=PBM_PORT=$PORT
Environment=PBM_HOST=0.0.0.0
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
info "Service file written to $SERVICE_FILE"

# ── Enable and start ───────────────────────────────────────────────────────────
step "Enabling and starting service…"
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

# ── Done ───────────────────────────────────────────────────────────────────────
sleep 3
STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)
echo
if [[ "$STATUS" == "active" ]]; then
    LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo -e "${GREEN}  ✓ Pi Backup Manager is running!${NC}"
    echo
    echo "  Open in your browser:"
    echo "    http://localhost:$PORT"
    [[ -n "$LOCAL_IP" ]] && echo "    http://$LOCAL_IP:$PORT"
    echo
    echo "  Manage the service:"
    echo "    sudo systemctl status  $SERVICE_NAME"
    echo "    sudo systemctl stop    $SERVICE_NAME"
    echo "    sudo journalctl -u $SERVICE_NAME -f"
    echo
    echo "  Next steps:"
    echo "    1. Open the UI and set up auth (first-run setup page)"
    echo "    2. Configure your backup destination (Destination tab)"
    echo "    3. Generate and install your backup script (Schedule tab)"
    echo
else
    warn "Service status is '$STATUS'. Check logs:"
    warn "  sudo journalctl -u $SERVICE_NAME -n 30"
fi
