"""
examples/fastapi_demo/main.py
-----------------------------
Example FastAPI application protected by NetGuard AI.

Run:
    uvicorn main:app --reload --port 8000

Then open in your browser:
    - Web Application : http://localhost:8000/
    - NetGuard Shield : http://localhost:8000/_netguard
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from netguard.integrations.fastapi import NetGuard

app = FastAPI(
    title="CloudCommerce API",
    description="Sample e-commerce web application protected by NetGuard AI",
    version="1.0.0",
)

# ── Attach NetGuard In-App Threat Protection & Embedded Web Dashboard ─────────
# Works with ZERO administrative privileges on any machine!
guard = NetGuard(
    app,
    dashboard=True,              # Mounts the real-time web dashboard
    mount_path="/_netguard",     # Dashboard accessible at http://localhost:8000/_netguard
    block_attacks=False,         # Set to True to auto-block attack IPs with 403 Forbidden
    # alert_webhook="https://discord.com/api/webhooks/...", # Optional Discord/Slack webhook
)


# ── Sample Application Endpoints ──────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
    <head><title>CloudCommerce Web Store</title></head>
    <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center;">
        <h1 style="color: #38bdf8;">🛍️ Welcome to CloudCommerce</h1>
        <p>This web application is protected in real-time by <strong>NetGuard AI</strong>.</p>
        <p style="margin-top: 24px;">
            <a href="/_netguard" target="_blank" style="display: inline-block; background: #06b6d4; color: #000; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold;">
                Open NetGuard Threat Dashboard &rarr;
            </a>
        </p>
        <p style="margin-top: 30px; font-size: 13px; color: #94a3b8;">
            Try running <code>python simulate_traffic.py</code> to test real-time attack detection!
        </p>
    </body>
    </html>
    """


@app.get("/api/products")
async def get_products():
    return {
        "products": [
            {"id": 1, "name": "Quantum Laptop Pro", "price": 1299.99},
            {"id": 2, "name": "CyberShield Router", "price": 189.50},
            {"id": 3, "name": "Neural ANC Headphones", "price": 249.00},
        ]
    }


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
async def login(req: LoginRequest):
    if req.username == "admin" and req.password == "supersecret":
        return {"status": "authenticated", "token": "jwt_token_sample"}
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.get("/api/search")
async def search(q: str = Query("", description="Search term")):
    return {"query": q, "results_count": 0, "items": []}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
