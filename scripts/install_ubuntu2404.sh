#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install_ubuntu2404.sh"
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/dhcp_server"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  postgresql postgresql-contrib redis-server \
  python3 python3-venv python3-pip tcpdump iproute2 jq curl rsync

sudo -u postgres psql <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dhcp') THEN
    CREATE ROLE dhcp LOGIN PASSWORD 'change_me';
  END IF;
END
$$;
SQL

sudo -u postgres psql <<'SQL'
SELECT 'CREATE DATABASE dhcp OWNER dhcp'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'dhcp')\gexec
SQL

sudo -u postgres psql -d dhcp -f "$REPO_DIR/db/schema.sql"

mkdir -p "$INSTALL_DIR"
rsync -a --delete --exclude '.git' "$REPO_DIR/" "$INSTALL_DIR/"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/services/requirements.txt"

if [[ ! -f "$INSTALL_DIR/config/server.yml" ]]; then
  cp "$INSTALL_DIR/config/server.example.yml" "$INSTALL_DIR/config/server.yml"
fi

if [[ ! -f "$INSTALL_DIR/services/.env" ]]; then
  cp "$INSTALL_DIR/services/.env.example" "$INSTALL_DIR/services/.env"
fi

cp "$INSTALL_DIR/systemd/dhcp-scapy-server.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/dhcp-forensics-api.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/dhcp-admin-gui.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now redis-server postgresql
systemctl enable --now dhcp-scapy-server.service dhcp-forensics-api.service dhcp-admin-gui.service

echo "Install complete. Edit $INSTALL_DIR/config/server.yml and $INSTALL_DIR/services/.env before production use."
