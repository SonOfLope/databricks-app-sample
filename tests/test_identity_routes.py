"""Identity routes: /api/whoami echoes the proxy identity, /api/data keeps the
vendor-token model. Plain script: python3 tests/test_identity_routes.py"""

import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("ENTRA_TENANT_ID", "65b6be73-2104-4ff4-899f-5bff3196f3d1")
os.environ.setdefault("ENTRA_AUDIENCE", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("APP_ENV", "test")

from fastapi.testclient import TestClient  # noqa: E402

import app as app_module  # noqa: E402

client = TestClient(app_module.app)


def _fake_jwt(claims: dict) -> str:
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'RS256'})}.{b64(claims)}.sig"


def test_whoami_echoes_proxy_headers_and_decodes_token_without_verifying():
    tok = _fake_jwt({"aud": "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d", "upn": "someone@arctiq.com",
                     "appid": "poc-app-staging", "scp": "user_impersonation", "iss": "https://sts.windows.net/x/", "exp": 1})
    r = client.get("/api/whoami", headers={
        "X-Forwarded-Email": "someone@arctiq.com", "X-Forwarded-User": "someone@arctiq.com",
        "X-Forwarded-Preferred-Username": "someone@arctiq.com", "X-Forwarded-Access-Token": tok})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["env"] == "test"
    assert d["forwarded"]["email"] == "someone@arctiq.com"
    assert d["token_claims"]["aud"] == "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
    assert d["token_claims"]["appid"] == "poc-app-staging"
    assert "sig" not in json.dumps(d)


def test_whoami_without_proxy_headers_reports_nothing_forwarded():
    d = client.get("/api/whoami").json()
    assert d["forwarded"] == {"email": None, "user": None, "preferred_username": None}
    assert d["token_claims"] == {}


def test_data_still_requires_vendor_token():
    assert client.get("/api/data").status_code == 401


def test_db_reports_missing_configuration_not_500():
    r = client.get("/api/db")
    assert r.status_code == 503, r.text
    assert "ENDPOINT_NAME" in r.json()["detail"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  {name}")
    print("test_identity_routes PASSED")
