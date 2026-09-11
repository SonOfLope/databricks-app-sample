"""Minimal FastAPI application for Databricks Apps.

Supported caller models are documented in README.md: the proxy identity model
(/api/whoami, the caller reaches the app through APIM which exchanges the
user's token on-behalf-of) and the vendor token model (/api/data, the app
validates the caller's Entra token itself from X-Vendor-Token).
"""

import base64
import json
import logging
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

import db
from entra_auth import require_role

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sample")

APP_ENV = os.environ.get("APP_ENV", "unset")
SHOWN_CLAIMS = ("aud", "appid", "azp", "scp", "upn", "preferred_username", "oid", "iss", "exp")

app = FastAPI(title="databricks-app-sample")


@app.on_event("startup")
def startup():
    try:
        db.init()
    except Exception as exc:
        log.warning("caller ledger unavailable: %s", exc)


def _unverified_claims(token: str) -> dict:
    """Display only. The Apps proxy already verified this token; the app never
    trusts these values for authorization."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}
    return {k: claims.get(k) for k in SHOWN_CLAIMS if k in claims}


def _note_caller(request: Request, identity: str, kind: str) -> None:
    model = request.headers.get("x-poc-model", "direct")
    db.record(identity, kind, model, request.url.path, APP_ENV)


@app.get("/api/whoami")
def whoami(request: Request):
    h = request.headers
    token = h.get("x-forwarded-access-token", "")
    email = h.get("x-forwarded-email")
    name = h.get("x-forwarded-preferred-username") or ""
    # A service principal reaches the proxy too; its email header carries the
    # client id rather than an address.
    kind = "machine" if (email and "@" not in email) else "human"
    _note_caller(request, email or "unknown", kind)
    return {
        "env": APP_ENV,
        "forwarded": {"email": email, "user": h.get("x-forwarded-user"), "preferred_username": name},
        "token_claims": _unverified_claims(token) if token else {},
    }


@app.get("/api/data")
def api_data(request: Request):
    claims = require_role(request, "integration")
    caller = claims.get("azp") or claims.get("appid") or "unknown"
    _note_caller(request, caller, "machine")
    return {"env": APP_ENV, "caller_appid": caller, "aud": claims.get("aud"),
            "roles": claims.get("roles"), "data": [1, 2, 3]}


@app.get("/api/db")
def api_db():
    if not db.configured():
        raise HTTPException(503, "ENDPOINT_NAME and PGHOST must be set for the Lakebase check")
    with db.connect() as conn:
        row = conn.execute("select current_user, inet_server_addr()::text, version()").fetchone()
    return {"env": APP_ENV, "current_user": row[0], "server_addr": row[1], "host": db.HOST, "version": row[2]}


@app.get("/api/callers")
def api_callers():
    return {"env": APP_ENV, "totals": db.caller_totals(), "recent": db.callers()}


@app.get("/api/coverage")
def api_coverage():
    return {"env": APP_ENV, **db.synced_rows()}


def _table(columns, rows, empty):
    if not rows:
        return f'<p class="empty">{empty}</p>'
    head = "".join(f"<th>{c}</th>" for c in columns)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


@app.get("/", response_class=HTMLResponse)
def root():
    try:
        totals = db.caller_totals()
        recent = db.callers(15)
        synced = db.synced_rows()
        err = ""
    except Exception as exc:
        totals, recent, synced, err = [], [], {"table": None, "columns": [], "rows": []}, str(exc)

    callers_html = _table(
        ["identity", "kind", "calls", "last seen"],
        [[t["identity"], t["kind"], t["calls"], t["last_seen"]] for t in totals],
        "No calls recorded yet.")
    recent_html = _table(
        ["seen at", "identity", "kind", "model", "route"],
        [[r["seen_at"], r["identity"], r["kind"], r["model"], r["route"]] for r in recent],
        "Nothing yet.")
    synced_html = _table(synced["columns"], synced["rows"],
                         "The synced table has not landed in this database yet.")
    note = f'<p class="err">{err}</p>' if err else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>databricks-app-sample {APP_ENV}</title>
<meta http-equiv="refresh" content="15">
<style>
body {{ font: 14px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; color: #1a1a1a; }}
h1 {{ font-size: 1.2rem; }} h2 {{ font-size: 1rem; margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: .35rem .6rem; border-bottom: 1px solid #e3e3e3; font-variant-numeric: tabular-nums; }}
th {{ font-weight: 600; color: #555; }}
.empty, .err {{ color: #777; }} .err {{ color: #a00; }}
code {{ background: #f4f4f4; padding: .1rem .3rem; }}
</style></head><body>
<h1>databricks-app-sample, environment {APP_ENV}</h1>
<p>Every caller that reaches this app, whether a person through the gateway or a machine with a vendor token, is recorded in Lakebase. The table below is published from Unity Catalog by a synced table.</p>
{note}
<h2>Callers</h2>
{callers_html}
<h2>Recent calls</h2>
{recent_html}
<h2>Synced table {synced['table'] or ''}</h2>
{synced_html}
</body></html>"""


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DATABRICKS_APP_PORT", "8000")))
