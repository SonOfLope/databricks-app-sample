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


@app.get("/")
def root():
    return {"service": "databricks-app-sample", "env": APP_ENV,
            "routes": ["/api/whoami", "/api/data", "/api/db", "/api/callers", "/api/coverage", "/health"]}


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DATABRICKS_APP_PORT", "8000")))
