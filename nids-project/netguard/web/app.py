"""Authenticated embedded dashboard for the canonical NetGuard core."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from typing import Set

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from netguard.auth import verify_api_key, verify_basic_auth
from netguard.core import NetGuard
from netguard.detection import PredictionResult


def _authorized(headers, config) -> bool:
    authorization = headers.get("authorization", "")
    scheme, _, credential = authorization.partition(" ")
    if scheme.lower() == "bearer" and verify_api_key(credential.strip(), config):
        return True
    if scheme.lower() == "basic":
        try:
            decoded = base64.b64decode(credential).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            return False
        return verify_basic_auth(username, password, config)
    return False


def create_dashboard_app(guard: NetGuard) -> Starlette:
    """Create the authenticated dashboard application for a NetGuard instance."""
    html_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    active_websockets: Set[WebSocket] = set()

    class DashboardAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if not _authorized(request.headers, guard.config):
                return Response(
                    "NetGuard dashboard authentication required",
                    status_code=401,
                    headers={"WWW-Authenticate": "Basic"},
                )
            return await call_next(request)

    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", **guard.stats()})

    async def dashboard_html(request: Request) -> HTMLResponse:
        with open(html_path, "r", encoding="utf-8") as dashboard_file:
            return HTMLResponse(dashboard_file.read())

    async def stats(request: Request) -> JSONResponse:
        return JSONResponse(guard.stats())

    async def alerts(request: Request) -> JSONResponse:
        return JSONResponse({"alerts": [alert.to_dict() for alert in guard.recent_alerts()]})

    async def block_ip(request: Request) -> JSONResponse:
        body = await request.json()
        client_ip = body.get("ip")
        if not client_ip:
            return JSONResponse({"error": "Missing 'ip' parameter"}, status_code=400)
        if body.get("action", "block") == "unblock":
            guard.unblock_ip(client_ip)
            return JSONResponse({"status": "unblocked", "ip": client_ip})
        guard.block_ip(client_ip)
        return JSONResponse({"status": "blocked", "ip": client_ip})

    async def ingest_event(request: Request) -> JSONResponse:
        body = await request.json()
        label = str(body.get("label", "BENIGN"))
        confidence = float(body.get("confidence", 0.0))
        result = PredictionResult(
            label=label,
            label_index=-1,
            confidence=confidence,
            probabilities=body.get("probabilities", {label: confidence}),
            is_attack=label != "BENIGN",
            flow_summary=str(body.get("flow_summary", "remote dashboard event")),
            detection_source=str(body.get("detection_source", "remote")),
        )
        alert = guard.alert_manager.trigger(result)
        return JSONResponse({"accepted": True, "alert": alert.to_dict() if alert else None})

    async def telemetry(websocket: WebSocket):
        api_key = websocket.query_params.get("api_key")
        if not (
            api_key and verify_api_key(api_key, guard.config)
        ) and not _authorized(websocket.headers, guard.config):
            await websocket.close(code=1008)
            return

        await websocket.accept()
        active_websockets.add(websocket)
        try:
            while True:
                await websocket.send_text(json.dumps({"type": "telemetry", "data": guard.stats()}))
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            pass
        finally:
            active_websockets.discard(websocket)

    def on_alert(alert) -> None:
        payload = json.dumps({"type": "alert", "data": alert.to_dict()})
        for websocket in list(active_websockets):
            try:
                asyncio.create_task(websocket.send_text(payload))
            except RuntimeError:
                active_websockets.discard(websocket)

    guard.on_alert(on_alert)
    app = Starlette(
        routes=[
            Route("/", dashboard_html, methods=["GET"]),
            Route("/health", health, methods=["GET"]),
            Route("/api/stats", stats, methods=["GET"]),
            Route("/api/alerts", alerts, methods=["GET"]),
            Route("/api/block-ip", block_ip, methods=["POST"]),
            Route("/api/events", ingest_event, methods=["POST"]),
            WebSocketRoute("/ws", telemetry),
        ]
    )
    app.add_middleware(DashboardAuthMiddleware)
    return app