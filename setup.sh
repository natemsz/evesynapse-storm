#!/bin/bash
# setup.sh — install/update the evesynapse-storm warming node on this box.
# Usage: sudo ./setup.sh [/path/to/storm-binary]
#   Binary defaults to /tmp/storm (where scp drops it).
# Safe to re-run: preserves an existing .env, restarts the service.
set -euo pipefail

BIN_SRC="${1:-}"
INSTALL_DIR="/opt/evesynapse-storm"
BIN_DST="$INSTALL_DIR/storm"
ENV_FILE="$INSTALL_DIR/.env"
SERVICE="evesynapse-storm"

# No arg: auto-detect a storm binary in /tmp (storm, storm-arm64, storm-amd64).
if [ -z "$BIN_SRC" ]; then
    for candidate in /tmp/storm /tmp/storm-arm64 /tmp/storm-amd64; do
        if [ -f "$candidate" ]; then
            BIN_SRC="$candidate"
            break
        fi
    done
fi

if [ -z "$BIN_SRC" ] || [ ! -f "$BIN_SRC" ]; then
    echo "error: no storm binary found." >&2
    echo "  scp one to /tmp/ (storm, storm-arm64, or storm-amd64), or:" >&2
    echo "  usage: sudo $0 [/path/to/storm-binary]" >&2
    exit 1
fi
echo "==> using binary: $BIN_SRC"

echo "==> installing binary to $BIN_DST"
mkdir -p "$INSTALL_DIR"
cp "$BIN_SRC" "$BIN_DST"
chmod +x "$BIN_DST"

# SELinux (AlmaLinux/RHEL): binary needs bin_t or systemd gets 203/EXEC.
if command -v chcon >/dev/null 2>&1 && [ -d /sys/fs/selinux ]; then
    echo "==> setting SELinux context"
    chcon -t bin_t "$BIN_DST" || true
fi

# .env: create with placeholders on first run, never overwrite.
if [ ! -f "$ENV_FILE" ]; then
    echo "==> creating $ENV_FILE (fill in values, then re-run)"
    cat > "$ENV_FILE" <<'EOF'
SHARED_CACHE_SECRET=c6cc85fec7f9fa9c3776cb9d7aeeea931e113f4e86b682add3361dfa31fe6caa
ESI_CONTACT=admin@evesynapse.app
SWARM_SEED_URL=https://neuron.evesynapse.app
PUBLIC_BASE_URL=https://storm.evesynapse.app
POLL_INTERVAL=60s
BIND_ADDR=127.0.0.1:8079
DB_PATH=/opt/evesynapse-storm/storm.db
IDENTITY_PATH=/opt/evesynapse-storm/storm-identity.json
EOF
    chmod 600 "$ENV_FILE"
else
    echo "==> keeping existing $ENV_FILE"
    chmod 600 "$ENV_FILE"
fi

# Service runs as nobody; it must own the dir for SQLite + identity file.
echo "==> setting ownership (nobody:nobody)"
chown -R nobody:nobody "$INSTALL_DIR"
chmod 600 "$ENV_FILE"

echo "==> installing systemd unit"
cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=EveSynapse storm node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_DST
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null

# Warn if required values are still empty; start anyway so logs show the error.
if grep -q '^SHARED_CACHE_SECRET=$' "$ENV_FILE" || grep -q '^PUBLIC_BASE_URL=$' "$ENV_FILE"; then
    echo "==> WARNING: SHARED_CACHE_SECRET or PUBLIC_BASE_URL is empty in $ENV_FILE"
    echo "    edit it (sudo nano $ENV_FILE), then: sudo systemctl restart $SERVICE"
fi

echo "==> (re)starting $SERVICE"
systemctl restart "$SERVICE"
sleep 2
systemctl is-active "$SERVICE"
echo "done. logs: sudo journalctl -u $SERVICE -f"
