"""Entra ID (v2) JWT validation for machine callers.

The Databricks Apps proxy owns the Authorization header (workspace OAuth,
app-audience token), so the vendor's Entra token rides X-Vendor-Token.
Validation is per environment: ENTRA_AUDIENCE pins this instance to its own
app registration, so a token minted for the other environment fails on `aud`
before any role check.
"""

import logging
import os

import jwt
from fastapi import HTTPException, Request

log = logging.getLogger("entra")

TENANT_ID = os.environ.get("ENTRA_TENANT_ID", "")
AUDIENCE = os.environ.get("ENTRA_AUDIENCE", "")
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URL = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"

_jwks = jwt.PyJWKClient(JWKS_URL, cache_keys=True, lifespan=3600)


def require_role(request: Request, role: str) -> dict:
    if not (TENANT_ID and AUDIENCE):
        raise HTTPException(503, "vendor auth not configured for this environment")
    token = request.headers.get("x-vendor-token", "")
    if not token:
        raise HTTPException(401, "missing X-Vendor-Token")
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=AUDIENCE, issuer=ISSUER,
            options={"require": ["exp", "aud", "iss", "sub"]})
    except jwt.InvalidAudienceError:
        raise HTTPException(403, "token audience is not this environment")
    except jwt.PyJWTError as exc:
        log.info("token rejected: %s", exc)
        raise HTTPException(401, f"invalid token: {type(exc).__name__}")
    if role not in (claims.get("roles") or []):
        raise HTTPException(403, f"caller lacks the '{role}' app role")
    return claims
