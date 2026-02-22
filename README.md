# Scapy DHCP Server Platform (IPv4 + IPv6, PostgreSQL, Redis HA, Forensics, Web GUI)

This project provides an open-source DHCP platform for **Ubuntu 24.04** with **no Kea dependency**.

## What it includes

- **Scapy-based DHCP engine** for DHCPv4 and DHCPv6 packet handling (DHCPv6 message types 1-4 support).
- **PostgreSQL** lease database (`dhcp_leases`) and event ledger (`lease_event_log`).
- **Redis HA sync channel** so two nodes can run as primary/secondary.
- **FastAPI forensic API** for legal discovery search + CSV/JSON export.
- **Web GUI** for DHCP server operations:
  - subnet management,
  - pool management,
  - user management,
  - utilization reporting,
  - HA status visibility.

## Services

- `dhcp-scapy-server.service` (portless, packet listener)
- `dhcp-forensics-api.service` on port `8088`
- `dhcp-admin-gui.service` on port `8090`

## Install on fresh Ubuntu 24.04

```bash
sudo bash scripts/install_ubuntu2404.sh
```

Then configure:

1. `/opt/dhcp_server/config/server.yml`
2. `/opt/dhcp_server/services/.env`

Restart services:

```bash
sudo systemctl restart dhcp-scapy-server.service dhcp-forensics-api.service dhcp-admin-gui.service
```

## GUI access

- URL: `http://<server-ip>:8090/login`
- Default credentials (change immediately):
  - Username from `GUI_DEFAULT_ADMIN`
  - Password from `GUI_DEFAULT_PASSWORD`

## Forensic API examples

```bash
curl -G http://127.0.0.1:8088/forensics/search \
  --data-urlencode "ip=192.168.50.101"
```

```bash
curl -G http://127.0.0.1:8088/forensics/export \
  --data-urlencode "start=2026-01-01T00:00:00Z" \
  --data-urlencode "end=2026-01-31T23:59:59Z" \
  --data-urlencode "format=csv" -o subpoena_export.csv
```

## Database permission repair (existing installs)

If GUI logs show `permission denied for table app_users`, run:

```bash
sudo -u postgres psql -d dhcp -f /opt/dhcp_server/db/permissions.sql
sudo systemctl restart dhcp-admin-gui.service
```

## HA notes

- Set `role: primary` on active responder, `role: secondary` on standby.
- Both nodes sync lease events through Redis.
- GUI shows server heartbeat status from `dhcp_server_status`.
- Keep both nodes synchronized via NTP for evidentiary timeline integrity.

## Security guidance

- Place GUI and Forensics API behind mTLS/authenticated reverse proxy.
- Restrict PostgreSQL + Redis to private interfaces.
- Rotate database credentials and default GUI credentials.
- Use encrypted disk and immutable central logs for legal-grade retention.

## License

MIT
