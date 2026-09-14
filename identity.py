"""Who is calling, and how we know.

Two sources, in order. The Apps proxy sets X-Forwarded-Email when the caller
presented their own Databricks token, which is the case when a person reaches
the app directly. When a gateway calls as itself, that header names the gateway,
so the person's identity arrives separately and is verified here rather than
trusted.
"""

import logging
import os

import jwt
from fastapi import Request

import entra_auth

log = logging.getLogger("identity")

ASSERTION_HEADER = "x-user-assertion"
ACCESS_HEADER = "cf-access-jwt-assertion"
ACCESS_TEAM = os.environ.get("CF_ACCESS_TEAM", "")
ACCESS_AUDIENCE = os.environ.get("CF_ACCESS_AUDIENCE", "")

_access_jwks = None


def _cloudflare_claims(token: str) -> dict:
    global _access_jwks
    if not (ACCESS_TEAM and ACCESS_AUDIENCE):
        raise ValueError("cloudflare access is not configured")
    if _access_jwks is None:
        _access_jwks = jwt.PyJWKClient(f"https://{ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs",
                                       cache_keys=True, lifespan=3600)
    key = _access_jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(token, key, algorithms=["RS256"], audience=ACCESS_AUDIENCE,
                      issuer=f"https://{ACCESS_TEAM}.cloudflareaccess.com",
                      options={"require": ["exp", "aud", "iss"]})


def resolve(request: Request) -> dict:
    h = request.headers
    email = h.get("x-forwarded-email")
    if email and "@" in email:
        return {"email": email, "source": "apps proxy",
                "name": h.get("x-forwarded-preferred-username") or email}

    token = h.get(ASSERTION_HEADER, "")
    if token:
        try:
            claims = entra_auth.verify(token)
            return {"email": claims.get("preferred_username") or claims.get("email") or claims.get("upn"),
                    "source": "entra assertion verified by the app",
                    "name": claims.get("name") or claims.get("preferred_username")}
        except Exception as exc:
            log.info("user assertion rejected: %s", exc)
            return {"email": None, "source": f"assertion rejected: {type(exc).__name__}", "name": None}

    token = h.get(ACCESS_HEADER, "")
    if token:
        try:
            claims = _cloudflare_claims(token)
            return {"email": claims.get("email"), "source": "cloudflare access, verified by the app",
                    "name": claims.get("email")}
        except Exception as exc:
            log.info("access assertion rejected: %s", exc)
            return {"email": None, "source": f"access assertion rejected: {type(exc).__name__}", "name": None}

    return {"email": email, "source": "caller presented no user identity", "name": None}
