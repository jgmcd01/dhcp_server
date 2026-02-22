#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from psycopg.rows import dict_row

app = FastAPI(title="DHCP Admin GUI", version="1.0.1")
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def dsn() -> str:
    return os.getenv("PG_DSN", "postgresql://dhcp:change_me@127.0.0.1:5432/dhcp")


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    salt, _ = password_hash.split("$", 1)
    return hash_password(password, salt) == password_hash


def db_query(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


def db_exec(sql: str, params: tuple[Any, ...] = ()) -> None:
    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()


def ensure_control_plane_schema() -> None:
    # Guard against pre-existing deployments that have older schema versions.
    statements = [
        """
        CREATE TABLE IF NOT EXISTS app_users (
          user_id BIGSERIAL PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS dhcp_subnets (
          subnet_id BIGSERIAL PRIMARY KEY,
          ip_version SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
          name TEXT NOT NULL UNIQUE,
          subnet_cidr CIDR NOT NULL UNIQUE,
          router INET,
          dns_servers TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
          lease_seconds INTEGER NOT NULL DEFAULT 3600,
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS dhcp_pools (
          pool_id BIGSERIAL PRIMARY KEY,
          subnet_id BIGINT NOT NULL REFERENCES dhcp_subnets(subnet_id) ON DELETE CASCADE,
          pool_start INET NOT NULL,
          pool_end INET NOT NULL,
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS dhcp_server_status (
          node_id TEXT PRIMARY KEY,
          role TEXT NOT NULL,
          interface TEXT NOT NULL,
          last_seen TIMESTAMPTZ NOT NULL,
          details JSONB NOT NULL DEFAULT '{}'::jsonb
        )
        """,
    ]
    for stmt in statements:
        db_exec(stmt)


@app.on_event("startup")
def startup() -> None:
    ensure_control_plane_schema()
    admin_user = os.getenv("GUI_DEFAULT_ADMIN", "admin")
    admin_pass = os.getenv("GUI_DEFAULT_PASSWORD", "admin123!")
    rows = db_query("SELECT 1 FROM app_users WHERE username=%s", (admin_user,))
    if not rows:
        db_exec(
            "INSERT INTO app_users (username, password_hash, role) VALUES (%s,%s,'admin')",
            (admin_user, hash_password(admin_pass)),
        )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/login")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)) -> HTMLResponse:
    rows = db_query("SELECT username,password_hash,role,enabled FROM app_users WHERE username=%s", (username,))
    if not rows or not rows[0]["enabled"] or not verify_password(password, rows[0]["password_hash"]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"}, status_code=401)

    resp = RedirectResponse(url="/dashboard", status_code=303)
    resp.set_cookie("dhcp_user", rows[0]["username"], httponly=True)
    resp.set_cookie("dhcp_role", rows[0]["role"], httponly=True)
    return resp


def require_user(request: Request) -> tuple[str, str]:
    user = request.cookies.get("dhcp_user")
    role = request.cookies.get("dhcp_role")
    if not user or not role:
        raise HTTPException(status_code=401, detail="Login required")
    return user, role


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    user, role = require_user(request)

    subnets = db_query("SELECT * FROM dhcp_subnets ORDER BY subnet_id")
    pools = db_query(
        """
        SELECT p.pool_id,s.name AS subnet_name,s.subnet_cidr::text AS subnet_cidr,p.pool_start::text,p.pool_end::text,p.enabled
        FROM dhcp_pools p JOIN dhcp_subnets s ON p.subnet_id=s.subnet_id ORDER BY p.pool_id
        """
    )
    users = db_query("SELECT user_id,username,role,enabled,created_at FROM app_users ORDER BY user_id")
    servers = db_query("SELECT node_id,role,interface,last_seen,details FROM dhcp_server_status ORDER BY node_id")

    utilization = db_query(
        """
        SELECT s.subnet_id,s.name,s.subnet_cidr::text,
               COUNT(DISTINCT l.address) FILTER (WHERE l.state='active' AND l.lease_end > NOW()) AS active_leases
        FROM dhcp_subnets s
        LEFT JOIN dhcp_leases l ON l.subnet_cidr=s.subnet_cidr
        GROUP BY s.subnet_id,s.name,s.subnet_cidr
        ORDER BY s.subnet_id
        """
    )
    pools_for_capacity = db_query("SELECT subnet_id,pool_start::text,pool_end::text FROM dhcp_pools WHERE enabled=true")
    capacity_by_subnet: dict[int, int] = {}
    for p in pools_for_capacity:
        start = int(ipaddress.ip_address(p["pool_start"]))
        end = int(ipaddress.ip_address(p["pool_end"]))
        capacity_by_subnet[p["subnet_id"]] = capacity_by_subnet.get(p["subnet_id"], 0) + max(0, (end - start + 1))
    for row in utilization:
        row["pool_capacity"] = capacity_by_subnet.get(row["subnet_id"], 0)

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "role": role,
            "subnets": subnets,
            "pools": pools,
            "users": users,
            "servers": servers,
            "utilization": utilization,
            "now": datetime.now(timezone.utc),
        },
    )


@app.post("/subnets")
def create_subnet(
    request: Request,
    name: str = Form(...),
    ip_version: int = Form(...),
    subnet_cidr: str = Form(...),
    router: str = Form(""),
    dns_servers: str = Form(""),
    lease_seconds: int = Form(3600),
) -> RedirectResponse:
    _, role = require_user(request)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    dns_list = [x.strip() for x in dns_servers.split(",") if x.strip()]
    db_exec(
        "INSERT INTO dhcp_subnets (name,ip_version,subnet_cidr,router,dns_servers,lease_seconds) VALUES (%s,%s,%s,%s,%s,%s)",
        (name, ip_version, subnet_cidr, router or None, dns_list, lease_seconds),
    )
    return RedirectResponse(url="/dashboard", status_code=303)


@app.post("/pools")
def create_pool(request: Request, subnet_id: int = Form(...), pool_start: str = Form(...), pool_end: str = Form(...)) -> RedirectResponse:
    _, role = require_user(request)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    db_exec("INSERT INTO dhcp_pools (subnet_id,pool_start,pool_end) VALUES (%s,%s,%s)", (subnet_id, pool_start, pool_end))
    return RedirectResponse(url="/dashboard", status_code=303)


@app.post("/users")
def create_user(request: Request, username: str = Form(...), password: str = Form(...), role: str = Form(...)) -> RedirectResponse:
    _, my_role = require_user(request)
    if my_role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    db_exec(
        "INSERT INTO app_users (username,password_hash,role) VALUES (%s,%s,%s)",
        (username, hash_password(password), role),
    )
    return RedirectResponse(url="/dashboard", status_code=303)


@app.post("/logout")
def logout() -> RedirectResponse:
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("dhcp_user")
    resp.delete_cookie("dhcp_role")
    return resp
