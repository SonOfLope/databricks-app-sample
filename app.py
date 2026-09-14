"""Minimal FastAPI application for Databricks Apps.

Supported caller models are documented in README.md: the proxy identity model
(/api/whoami, the caller reaches the app through APIM which exchanges the
user's token on-behalf-of) and the vendor token model (/api/data, the app
validates the caller's Entra token itself from X-Vendor-Token).
"""

import base64
import html
import json
import logging
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

import db
import identity
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


def _note_caller(request: Request, who: str, kind: str) -> None:
    model = request.headers.get("x-poc-model", "direct")
    db.record(who, kind, model, request.url.path, APP_ENV)


@app.get("/api/whoami")
def whoami(request: Request):
    h = request.headers
    token = h.get("x-forwarded-access-token", "")
    who = identity.resolve(request)
    kind = "human" if who["email"] and "@" in who["email"] else "machine"
    _note_caller(request, who["email"] or h.get("x-forwarded-email") or "unknown", kind)
    return {
        "env": APP_ENV,
        "identity": who,
        "forwarded": {"email": h.get("x-forwarded-email"), "user": h.get("x-forwarded-user"),
                      "preferred_username": h.get("x-forwarded-preferred-username")},
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


def _rows(columns, rows, empty):
    if not rows:
        return f'<p class="empty">{empty}</p>'
    head = "".join(f"<th>{html.escape(str(c))}</th>" for c in columns)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    who = identity.resolve(request)
    if who["email"]:
        _note_caller(request, who["email"], "human" if "@" in who["email"] else "machine")
    try:
        totals, recent, synced, err = db.caller_totals(), db.callers(15), db.synced_rows(), ""
    except Exception as exc:
        totals, recent, synced, err = [], [], {"table": None, "columns": [], "rows": []}, str(exc)

    signed_in = (f'<strong>{html.escape(who["email"])}</strong>, known from {html.escape(who["source"])}'
                 if who["email"] else f'Not signed in. {html.escape(who["source"])}.')
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>ecoverage sample, {html.escape(APP_ENV)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body {{ font: 14px/1.55 system-ui, sans-serif; margin: 2rem auto; max-width: 62rem; color: #17181a; padding: 0 1rem; }}
h1 {{ font-size: 1.25rem; margin-bottom: .2rem; }} h2 {{ font-size: 1rem; margin-top: 2rem; }}
.sub {{ color: #666; margin-top: 0; }}
.who {{ background: #f5f6f7; border-left: 3px solid #999; padding: .7rem .9rem; margin: 1.2rem 0; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; padding: .35rem .6rem; border-bottom: 1px solid #e6e6e6; font-variant-numeric: tabular-nums; }}
th {{ font-weight: 600; color: #555; }}
.empty {{ color: #777; }} .err {{ color: #a00; }}
</style></head><body>
<h1>ecoverage sample</h1>
<p class="sub">Served by the app itself, environment {html.escape(APP_ENV)}.</p>
<div class="who">{signed_in}</div>
{f'<p class="err">{html.escape(err)}</p>' if err else ''}
<h2>Callers</h2>
{_rows(["identity", "kind", "calls", "last seen"], [[t["identity"], t["kind"], t["calls"], t["last_seen"]] for t in totals], "No calls recorded yet.")}
<h2>Recent calls</h2>
{_rows(["seen at", "identity", "kind", "model", "route"], [[r["seen_at"], r["identity"], r["kind"], r["model"], r["route"]] for r in recent], "Nothing yet.")}
<h2>Coverage, published from Unity Catalog</h2>
{_rows(synced["columns"], synced["rows"], "The synced table has not landed in this database yet.")}
</body></html>"""


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DATABRICKS_APP_PORT", "8000")))
