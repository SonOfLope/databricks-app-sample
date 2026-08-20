# databricks-app-sample

Minimal FastAPI app deployed as a Databricks App with OpenTelemetry
auto-instrumentation, exporting logs, metrics and traces to Unity Catalog.

Endpoints: `GET /`, `GET /health`.

## Deploy

Set the workspace host and the three table names in `databricks.yml`, then:

```
databricks bundle validate -t dev
databricks bundle deploy -t dev
```
