"""Minimal FastAPI application for Databricks Apps."""

import logging
import os

from fastapi import FastAPI

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sample")

app = FastAPI(title="databricks-app-sample")


@app.get("/")
def root():
    log.info("handled root request")
    return {"service": "databricks-app-sample", "status": "ok"}


@app.get("/health")
def health():
    log.info("handled health request")
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("DATABRICKS_APP_PORT", "8000")))
