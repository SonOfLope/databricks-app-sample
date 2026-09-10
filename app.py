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

from entra_auth import require_role

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sample")

APP_ENV = os.environ.get("APP_ENV", "unset")
SHOWN_CLAIMS = ("aud", "appid", "azp", "scp", "upn", "preferred_username", "oid", "iss", "exp")

app = FastAPI(title="databricks-app-sample")


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


@app.get("/api/whoami")
def whoami(request: Request):
    h = request.headers
    token = h.get("x-forwarded-access-token", "")
    return {
        "env": APP_ENV,
        "forwarded": {
            "email": h.get("x-forwarded-email"),
            "user": h.get("x-forwarded-user"),
            "preferred_username": h.get("x-forwarded-preferred-username"),
        },
        "token_claims": _unverified_claims(token) if token else {},
    }


@app.get("/api/data")
def api_data(request: Request):
    claims = require_role(request, "integration")
    return {"env": APP_ENV, "caller_appid": claims.get("azp") or claims.get("appid"),
            "aud": claims.get("aud"), "roles": claims.get("roles"), "data": [1, 2, 3]}


@app.get("/api/db")
def api_db():
    endpoint = os.environ.get("ENDPOINT_NAME", "")
    host = os.environ.get("PGHOST", "")
    if not (endpoint and host):
        raise HTTPException(503, "ENDPOINT_NAME and PGHOST must be set for the Lakebase check")
    import psycopg
    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient()
    token = w.postgres.generate_database_credential(endpoint=endpoint).token
    user = os.environ.get("PGUSER") or os.environ["DATABRICKS_CLIENT_ID"]
    with psycopg.connect(host=host, port=5432, dbname="databricks_postgres", user=user,
                         password=token, sslmode="require", connect_timeout=10) as conn:
        row = conn.execute("select current_user, inet_server_addr()::text, version()").fetchone()
    return {"env": APP_ENV, "current_user": row[0], "server_addr": row[1], "host": host, "version": row[2]}


@app.get("/")
def root():
    return {"service": "databricks-app-sample", "status": "ok", "env": APP_ENV}


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DATABRICKS_APP_PORT", "8000")))
