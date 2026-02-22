#!/usr/bin/env python3
from __future__ import annotations

import csv
import io
import os
from datetime import datetime
from typing import Any

import psycopg
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from psycopg.rows import dict_row

app = FastAPI(title="DHCP Forensics API", version="2.0.0")


def dsn() -> str:
    return os.getenv("PG_DSN", "postgresql://dhcp:change_me@127.0.0.1:5432/dhcp")


def search_rows(filters: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {"limit": limit}

    if filters.get("ip"):
        clauses.append("host(l.address) = %(ip)s")
        params["ip"] = filters["ip"]
    if filters.get("mac"):
        clauses.append("lower(l.mac_address) = lower(%(mac)s)")
        params["mac"] = filters["mac"]
    if filters.get("duid"):
        clauses.append("lower(l.duid) = lower(%(duid)s)")
        params["duid"] = filters["duid"]
    if filters.get("client_id"):
        clauses.append("l.client_id = %(client_id)s")
        params["client_id"] = filters["client_id"]
    if filters.get("start"):
        clauses.append("e.event_ts >= %(start)s")
        params["start"] = filters["start"]
    if filters.get("end"):
        clauses.append("e.event_ts <= %(end)s")
        params["end"] = filters["end"]

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"""
        SELECT e.event_id, e.event_ts, e.op, e.source_node,
               l.ip_version, host(l.address) AS address, l.client_id, l.mac_address, l.duid,
               l.hostname, l.subnet_cidr::text AS subnet_cidr, l.lease_start, l.lease_end, l.state
        FROM lease_event_log e
        JOIN dhcp_leases l
          ON e.lease_pk = (l.ip_version::text || ':' || host(l.address))
        {where}
        ORDER BY e.event_ts DESC
        LIMIT %(limit)s
    """

    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/forensics/search")
def search(
    ip: str | None = None,
    mac: str | None = None,
    duid: str | None = None,
    client_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(500, ge=1, le=5000),
) -> JSONResponse:
    rows = search_rows(
        {"ip": ip, "mac": mac, "duid": duid, "client_id": client_id, "start": start, "end": end},
        limit,
    )
    return JSONResponse({"count": len(rows), "results": rows})


@app.get("/forensics/export")
def export(
    ip: str | None = None,
    mac: str | None = None,
    duid: str | None = None,
    client_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    format: str = Query("csv", pattern="^(csv|json)$"),
    limit: int = Query(5000, ge=1, le=50000),
):
    rows = search_rows(
        {"ip": ip, "mac": mac, "duid": duid, "client_id": client_id, "start": start, "end": end},
        limit,
    )
    if format == "json":
        return JSONResponse({"count": len(rows), "results": rows})

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()) if rows else ["event_id"])
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return PlainTextResponse(
        out.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dhcp_forensics_export.csv"},
    )
