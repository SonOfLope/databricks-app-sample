"""Lakebase access for the app's own service principal.

The app connects with an OAuth credential minted for its service principal, so
there is no password anywhere. Two things live here: the caller ledger the app
writes on every identified request, and reads of the synced table that Unity
Catalog publishes into the same database.
"""

import logging
import os
import threading
import time

import psycopg

log = logging.getLogger("db")

ENDPOINT = os.environ.get("ENDPOINT_NAME", "")
HOST = os.environ.get("PGHOST", "")
DBNAME = os.environ.get("PGDATABASE", "databricks_postgres")
SYNCED_TABLE = os.environ.get("SYNCED_TABLE", "coverage_sites_synced")

_lock = threading.Lock()
_token = {"value": "", "expires": 0.0}


def configured() -> bool:
    return bool(ENDPOINT and HOST)


def _credential() -> str:
    with _lock:
        if _token["value"] and time.time() < _token["expires"]:
            return _token["value"]
        from databricks.sdk import WorkspaceClient

        cred = WorkspaceClient().postgres.generate_database_credential(endpoint=ENDPOINT)
        _token["value"] = cred.token
        _token["expires"] = time.time() + 1800
        return _token["value"]


def connect():
    user = os.environ.get("PGUSER") or os.environ["DATABRICKS_CLIENT_ID"]
    return psycopg.connect(host=HOST, port=5432, dbname=DBNAME, user=user,
                           password=_credential(), sslmode="require", connect_timeout=10)


DDL = """
create schema if not exists app;
create table if not exists app.callers (
  id bigserial primary key,
  seen_at timestamptz not null default now(),
  identity text not null,
  kind text not null,
  model text not null,
  route text not null,
  environment text not null
);
create index if not exists callers_seen_at on app.callers (seen_at desc);
"""


def init() -> None:
    if not configured():
        log.info("lakebase not configured, caller ledger disabled")
        return
    with connect() as conn:
        conn.execute(DDL)


def record(identity: str, kind: str, model: str, route: str, environment: str) -> None:
    if not configured():
        return
    try:
        with connect() as conn:
            conn.execute(
                "insert into app.callers (identity, kind, model, route, environment) values (%s,%s,%s,%s,%s)",
                (identity, kind, model, route, environment))
    except Exception as exc:
        log.warning("caller not recorded: %s", exc)


def callers(limit: int = 25) -> list[dict]:
    if not configured():
        return []
    with connect() as conn:
        rows = conn.execute(
            "select identity, kind, model, route, environment, seen_at from app.callers order by seen_at desc limit %s",
            (limit,)).fetchall()
    return [{"identity": r[0], "kind": r[1], "model": r[2], "route": r[3], "environment": r[4],
             "seen_at": r[5].isoformat()} for r in rows]


def caller_totals() -> list[dict]:
    if not configured():
        return []
    with connect() as conn:
        rows = conn.execute(
            "select identity, kind, count(*), max(seen_at) from app.callers group by identity, kind order by 3 desc"
        ).fetchall()
    return [{"identity": r[0], "kind": r[1], "calls": r[2], "last_seen": r[3].isoformat()} for r in rows]


def _synced_relation(conn) -> str | None:
    """Unity Catalog decides the schema the synced table lands in, so find it."""
    row = conn.execute(
        "select table_schema from information_schema.tables where table_name = %s order by table_schema limit 1",
        (SYNCED_TABLE,)).fetchone()
    return f'"{row[0]}"."{SYNCED_TABLE}"' if row else None


def synced_rows(limit: int = 50) -> dict:
    if not configured():
        return {"table": None, "columns": [], "rows": []}
    with connect() as conn:
        rel = _synced_relation(conn)
        if not rel:
            return {"table": None, "columns": [], "rows": []}
        cur = conn.execute(f"select * from {rel} limit {int(limit)}")
        cols = [d.name for d in cur.description]
        rows = [[str(v) for v in r] for r in cur.fetchall()]
    return {"table": rel.replace('"', ""), "columns": cols, "rows": rows}
