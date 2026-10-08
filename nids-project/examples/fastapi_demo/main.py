"""
NetGuard FastAPI demo — local development example.

Run from nids-project/ (inner project root):

    set NETGUARD_AUTH_USERNAME=admin
    set NETGUARD_AUTH_PASSWORD=secret
    set NETGUARD_PROJECT_ID=demo-app
    uvicorn examples.fastapi_demo.main:app --reload --port 8000

Health (requires auth):
    curl -u admin:secret http://localhost:8000/netguard/health
"""

from __future__ import annotations

import os
import sys

# Allow running without editable install during local dev
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from fastapi import FastAPI

from netguard import NetGuard
from netguard.integrations.fastapi import setup_netguard

app = FastAPI(title="NetGuard Demo App")

guard = NetGuard(
    project_id=os.getenv("NETGUARD_PROJECT_ID", "demo-app"),
    auth_username=os.getenv("NETGUARD_AUTH_USERNAME", "admin"),
    auth_password=os.getenv("NETGUARD_AUTH_PASSWORD", "secret"),
    model_dir=os.getenv("NETGUARD_MODEL_DIR", "models"),
    console_alerts=True,
)

setup_netguard(app, guard)


@app.get("/")
async def root():
    return {"message": "NetGuard demo app is running.", "netguard": guard.stats()}


@app.get("/simulate/portscan")
async def simulate_portscan():
    """Generate rapid small requests resembling port-scan traffic."""
    import httpx

    base = "http://127.0.0.1:8000"
    async with httpx.AsyncClient() as client:
        for i in range(30):
            await client.get(f"{base}/probe/{i}")
    return {"status": "portscan simulation sent", "netguard": guard.stats()}


@app.get("/probe/{port}")
async def probe(port: int):
    return {"port": port, "open": False}
