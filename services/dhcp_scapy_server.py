#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import signal
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
import redis
import yaml
from psycopg.rows import dict_row
from scapy.all import (  # type: ignore
    BOOTP,
    DHCP,
    DHCP6_Advertise,
    DHCP6_Confirm,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptIAAddress,
    DHCP6OptIA_NA,
    DHCP6OptServerId,
    Ether,
    IP,
    IPv6,
    UDP,
    conf,
    get_if_hwaddr,
    sendp,
    sniff,
)

RUNNING = True


@dataclass
class Cfg:
    node_id: str
    role: str
    interface: str
    postgres_dsn: str
    redis_url: str
    redis_channel: str
    ipv4: dict[str, Any]
    ipv6: dict[str, Any]


def load_cfg() -> Cfg:
    path = os.getenv("DHCP_CONFIG", "/opt/dhcp_server/config/server.yml")
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return Cfg(**raw)


def stop_handler(_sig: int, _frm: Any) -> None:
    global RUNNING
    RUNNING = False


def db_conn(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, row_factory=dict_row)


def active_lease_for_client(conn: psycopg.Connection, client_id: str, ip_version: int) -> str | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT host(address) AS addr
            FROM dhcp_leases
            WHERE client_id = %s AND ip_version = %s AND state='active' AND lease_end > NOW()
            ORDER BY lease_end DESC LIMIT 1
            """,
            (client_id, ip_version),
        )
        row = cur.fetchone()
    return row["addr"] if row else None


def first_free(pool_start: str, pool_end: str, used: set[str]) -> str:
    a = int(ipaddress.ip_address(pool_start))
    b = int(ipaddress.ip_address(pool_end))
    for n in range(a, b + 1):
        cand = str(ipaddress.ip_address(n))
        if cand not in used:
            return cand
    raise RuntimeError("No free addresses in pool")


def used_addresses(conn: psycopg.Connection, ip_version: int, subnet: str) -> set[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT host(address) AS addr FROM dhcp_leases
            WHERE ip_version = %s AND subnet_cidr = %s AND state='active' AND lease_end > NOW()
            """,
            (ip_version, subnet),
        )
        return {r["addr"] for r in cur.fetchall()}


def persist_and_publish(
    conn: psycopg.Connection,
    rc: redis.Redis,
    channel: str,
    node_id: str,
    event: dict[str, Any],
) -> None:
    payload = json.dumps(event)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO lease_event_log (op, lease_pk, source_node, payload) VALUES (%s,%s,%s,%s::jsonb)",
            (event["op"], event["lease_pk"], node_id, payload),
        )
    conn.commit()
    rc.publish(channel, payload)


def upsert_lease(conn: psycopg.Connection, event: dict[str, Any]) -> None:
    l = event["lease"]
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO dhcp_leases
            (ip_version,address,client_id,mac_address,duid,iaid,hostname,subnet_cidr,lease_start,lease_end,state,node_id,user_context)
            VALUES (%(ip_version)s,%(address)s,%(client_id)s,%(mac_address)s,%(duid)s,%(iaid)s,%(hostname)s,%(subnet_cidr)s,
                    %(lease_start)s,%(lease_end)s,'active',%(node_id)s,%(user_context)s::jsonb)
            ON CONFLICT (ip_version,address)
            DO UPDATE SET client_id=EXCLUDED.client_id,mac_address=EXCLUDED.mac_address,duid=EXCLUDED.duid,iaid=EXCLUDED.iaid,
                          hostname=EXCLUDED.hostname,lease_start=EXCLUDED.lease_start,lease_end=EXCLUDED.lease_end,
                          state='active',node_id=EXCLUDED.node_id,user_context=EXCLUDED.user_context
            """,
            l,
        )
    conn.commit()


def sync_subscriber(cfg: Cfg) -> None:
    rc = redis.Redis.from_url(cfg.redis_url, decode_responses=True)
    ps = rc.pubsub(ignore_subscribe_messages=True)
    ps.subscribe(cfg.redis_channel)
    with db_conn(cfg.postgres_dsn) as conn:
        while RUNNING:
            msg = ps.get_message(timeout=1.0)
            if not msg:
                continue
            event = json.loads(msg["data"])
            if event.get("source_node") == cfg.node_id:
                continue
            upsert_lease(conn, event)




def select_runtime_network(conn: psycopg.Connection, ip_version: int, fallback: dict[str, Any]) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.subnet_id,s.subnet_cidr::text,s.router::text AS router,s.dns_servers,s.lease_seconds,
                   p.pool_start::text AS pool_start,p.pool_end::text AS pool_end
            FROM dhcp_subnets s
            JOIN dhcp_pools p ON p.subnet_id=s.subnet_id
            WHERE s.enabled=true AND p.enabled=true AND s.ip_version=%s
            ORDER BY s.subnet_id,p.pool_id LIMIT 1
            """,
            (ip_version,),
        )
        row = cur.fetchone()
    if not row:
        return fallback
    merged = dict(fallback)
    merged.update({k: row[k] for k in ["subnet_cidr", "router", "dns_servers", "lease_seconds", "pool_start", "pool_end"] if row.get(k) is not None})
    return merged


def update_heartbeat(cfg: Cfg) -> None:
    details = {"ipv4_enabled": bool(cfg.ipv4.get("enabled")), "ipv6_enabled": bool(cfg.ipv6.get("enabled"))}
    with db_conn(cfg.postgres_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dhcp_server_status (node_id, role, interface, last_seen, details)
                VALUES (%s,%s,%s,NOW(),%s::jsonb)
                ON CONFLICT (node_id)
                DO UPDATE SET role=EXCLUDED.role, interface=EXCLUDED.interface, last_seen=EXCLUDED.last_seen, details=EXCLUDED.details
                """,
                (cfg.node_id, cfg.role, cfg.interface, json.dumps(details)),
            )
        conn.commit()


def heartbeat_loop(cfg: Cfg) -> None:
    while RUNNING:
        try:
            update_heartbeat(cfg)
        except Exception:
            pass
        time.sleep(5)

def dhcp4_handler(pkt: Any, cfg: Cfg, conn: psycopg.Connection, rc: redis.Redis) -> None:
    if DHCP not in pkt or BOOTP not in pkt:
        return
    opts = {k: v for k, v in pkt[DHCP].options if isinstance(k, str)}
    if opts.get("message-type") != 1:  # discover only
        return

    runtime_v4 = select_runtime_network(conn, 4, cfg.ipv4)
    client_mac = pkt[Ether].src
    client_id = opts.get("client_id", client_mac)
    lease = active_lease_for_client(conn, str(client_id), 4)
    if not lease:
        used = used_addresses(conn, 4, runtime_v4["subnet_cidr"])
        lease = first_free(runtime_v4["pool_start"], runtime_v4["pool_end"], used)

    lease_end = datetime.now(timezone.utc) + timedelta(seconds=int(runtime_v4["lease_seconds"]))
    event = {
        "op": "upsert",
        "lease_pk": f"4:{lease}",
        "source_node": cfg.node_id,
        "lease": {
            "ip_version": 4,
            "address": lease,
            "client_id": str(client_id),
            "mac_address": client_mac,
            "duid": None,
            "iaid": None,
            "hostname": opts.get("hostname"),
            "subnet_cidr": runtime_v4["subnet_cidr"],
            "lease_start": datetime.now(timezone.utc),
            "lease_end": lease_end,
            "node_id": cfg.node_id,
            "user_context": json.dumps({"protocol": "dhcp4"}),
        },
    }
    upsert_lease(conn, event)
    persist_and_publish(conn, rc, cfg.redis_channel, cfg.node_id, event)

    offer = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(cfg.interface))
        / IP(src=runtime_v4["server_ip"], dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=lease, siaddr=runtime_v4["server_ip"], xid=pkt[BOOTP].xid, chaddr=pkt[BOOTP].chaddr)
        / DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", runtime_v4["server_ip"]),
                ("router", runtime_v4["router"]),
                ("name_server", runtime_v4["dns_servers"]),
                ("lease_time", int(runtime_v4["lease_seconds"])),
                "end",
            ]
        )
    )
    sendp(offer, iface=cfg.interface, verbose=False)


def dhcp6_handler(pkt: Any, cfg: Cfg, conn: psycopg.Connection, rc: redis.Redis) -> None:
    msg_type = None
    if DHCP6_Solicit in pkt:
        msg_type = 1
    elif DHCP6_Request in pkt:
        msg_type = 3
    elif DHCP6_Confirm in pkt:
        msg_type = 4

    if msg_type is None:
        return
    cid_opt = pkt.getlayer(DHCP6OptClientId)
    if cid_opt is None:
        return

    runtime_v6 = select_runtime_network(conn, 6, cfg.ipv6)
    duid = bytes(cid_opt.duid).hex(":")
    client_id = duid
    lease = active_lease_for_client(conn, client_id, 6)
    if not lease:
        used = used_addresses(conn, 6, runtime_v6["subnet_cidr"])
        lease = first_free(runtime_v6["pool_start"], runtime_v6["pool_end"], used)

    lease_end = datetime.now(timezone.utc) + timedelta(seconds=int(runtime_v6["lease_seconds"]))
    event = {
        "op": "upsert",
        "lease_pk": f"6:{lease}",
        "source_node": cfg.node_id,
        "lease": {
            "ip_version": 6,
            "address": lease,
            "client_id": client_id,
            "mac_address": None,
            "duid": duid,
            "iaid": 0,
            "hostname": None,
            "subnet_cidr": runtime_v6["subnet_cidr"],
            "lease_start": datetime.now(timezone.utc),
            "lease_end": lease_end,
            "node_id": cfg.node_id,
            "user_context": json.dumps({"protocol": "dhcp6"}),
        },
    }
    upsert_lease(conn, event)
    persist_and_publish(conn, rc, cfg.redis_channel, cfg.node_id, event)

    response_cls = DHCP6_Advertise if msg_type == 1 else DHCP6_Reply
    response = (
        Ether(dst="33:33:00:01:00:02")
        / IPv6(src=str(ipaddress.ip_network(runtime_v6["subnet_cidr"])[1]), dst="ff02::1:2")
        / UDP(sport=547, dport=546)
        / response_cls()
        / DHCP6OptServerId(duid=bytes.fromhex(runtime_v6["server_duid"].replace(":", "")))
        / DHCP6OptClientId(duid=cid_opt.duid)
        / DHCP6OptIA_NA(iaid=0, T1=600, T2=1200)
        / DHCP6OptIAAddress(addr=lease, preflft=int(runtime_v6["lease_seconds"]), validlft=int(runtime_v6["lease_seconds"]))
    )
    sendp(response, iface=cfg.interface, verbose=False)


def main() -> int:
    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)
    conf.verb = 0

    cfg = load_cfg()
    t = threading.Thread(target=sync_subscriber, args=(cfg,), daemon=True)
    t.start()
    hb = threading.Thread(target=heartbeat_loop, args=(cfg,), daemon=True)
    hb.start()

    if cfg.role != "primary":
        while RUNNING:
            time.sleep(1)
        return 0

    rc = redis.Redis.from_url(cfg.redis_url, decode_responses=True)
    with db_conn(cfg.postgres_dsn) as conn:
        def handler(pkt: Any) -> None:
            if cfg.ipv4.get("enabled"):
                dhcp4_handler(pkt, cfg, conn, rc)
            if cfg.ipv6.get("enabled"):
                dhcp6_handler(pkt, cfg, conn, rc)

        sniff(iface=cfg.interface, filter="udp and (port 67 or port 68 or port 546 or port 547)", prn=handler, store=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
