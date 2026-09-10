# databricks-app-sample

Minimal FastAPI app for Databricks Apps used to prove two ways a caller can reach an app behind API Management.

| Route | Model | Who validates the caller | What the app reads |
|---|---|---|---|
| `GET /api/whoami` | Proxy identity. Caller sends a token for the environment's API registration to APIM; APIM exchanges it on-behalf-of for an Azure Databricks token and forwards that. | The Databricks Apps proxy | `X-Forwarded-Email`, `X-Forwarded-User`, `X-Forwarded-Preferred-Username`; token claims shown unverified |
| `GET /api/data` | Vendor token. Caller (a machine) sends a token carrying the `integration` app role; APIM calls the app as its own managed identity and forwards the caller's token in `X-Vendor-Token`. Also works without APIM when the caller holds its own Databricks token. | The app (`entra_auth.py`: issuer, audience `ENTRA_AUDIENCE`, role) | The validated claims |
| `GET /api/db` | Lakebase over OAuth as the app's own service principal (`ENDPOINT_NAME`, `PGHOST`, `postgres` app resource) | Lakebase | `current_user`, server address |
| `GET /`, `GET /health` | none | | |

Tokens for the tests:

    az account get-access-token --scope api://<api client id>/access_as_user --query accessToken -o tsv
    curl -s -X POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token -d "grant_type=client_credentials&client_id=<machine client id>&client_secret=<secret>&scope=api://<api client id>/.default"

Deploy (targets `arctiq-staging`, `arctiq-prod`; values in `databricks.yml` come from the infra repo's `terraform output`):

    databricks bundle validate -t arctiq-staging -p arctiq-ws
    databricks bundle deploy -t arctiq-staging -p arctiq-ws

Tests: `python3 tests/test_identity_routes.py`. The gateway, network and identity setup live in `databricks-private-app-infra-sample`.
