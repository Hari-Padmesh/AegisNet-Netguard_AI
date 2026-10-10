"""Multi-project standalone NetGuard dashboard server."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from typing import Dict, Set

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from netguard.auth import verify_api_key, verify_basic_auth
from netguard.config import NetGuardConfig
from netguard.web.app import _authorized


class DashboardProjectStore:
    """Persist bounded per-project alert state in a JSON file."""

    def __init__(self, path: str = "netguard-projects.json"):
        self.path = path
        self._lock = threading.Lock()
        self._projects: Dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as data_file:
                self._projects = json.load(data_file)
        except (OSError, ValueError):
            self._projects = {}

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        temporary_path = f"{self.path}.tmp"
        with open(temporary_path, "w", encoding="utf-8") as data_file:
            json.dump(self._projects, data_file, indent=2)
        os.replace(temporary_path, self.path)

    def ingest(self, project_id: str, event: dict) -> dict:
        with self._lock:
            project = self._projects.setdefault(
                project_id,
                {"requests": 0, "attacks": 0, "alerts": []},
            )
            project["attacks"] += 1
            project["alerts"].append(event)
            project["alerts"] = project["alerts"][-1000:]
            self._save()
            return event

    def projects(self) -> list[str]:
        with self._lock:
            return sorted(self._projects)

    def stats(self, project_id: str) -> dict:
        with self._lock:
            project = self._projects.get(project_id, {"requests": 0, "attacks": 0, "alerts": []})
            alerts = list(project["alerts"][-50:])
        attacks = int(project["attacks"])
        return {
            "project_id": project_id,
            "requests": int(project["requests"]),
            "total_requests": int(project["requests"]),
            "attacks": attacks,
            "total_attacks": attacks,
            "alerts": {
                "total": len(alerts),
                "by_label": self._count(alerts, "label"),
                "by_severity": self._count(alerts, "severity"),
            },
            "recent_events": alerts,
            "top_clients": [],
            "threat_level": "CRITICAL" if attacks >= 5 else ("ELEVATED" if attacks else "NOMINAL"),
        }

    def alerts(self, project_id: str) -> list[dict]:
        with self._lock:
            return list(self._projects.get(project_id, {}).get("alerts", [])[-50:])

    @staticmethod
    def _count(items: list[dict], key: str) -> dict:
        counts: dict[str, int] = {}
        for item in items:
            value = str(item.get(key, "unknown"))
            counts[value] = counts.get(value, 0) + 1
        return counts


def create_dashboard_server_app(
    username: str,
    password: str,
    api_key: str = "",
    storage_path: str = "netguard-projects.json",
) -> Starlette:
    """Create a standalone authenticated, multi-project dashboard app."""
    config = NetGuardConfig(auth_username=username, auth_password=password, auth_api_key=api_key)
    config.validate_auth()
    store = DashboardProjectStore(storage_path)
    html_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    sockets: Set[WebSocket] = set()

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if not _authorized(request.headers, config):
                return Response("Dashboard authentication required", status_code=401, headers={"WWW-Authenticate": "Basic"})
            return await call_next(request)

    async def dashboard(request: Request) -> HTMLResponse:
        with open(html_path, "r", encoding="utf-8") as dashboard_file:
            return HTMLResponse(dashboard_file.read())

    async def projects(request: Request) -> JSONResponse:
        return JSONResponse({"projects": store.projects()})

    async def stats(request: Request) -> JSONResponse:
        project_id = request.query_params.get("project_id", "default")
        return JSONResponse(store.stats(project_id))

    async def alerts(request: Request) -> JSONResponse:
        project_id = request.query_params.get("project_id", "default")
        return JSONResponse({"alerts": store.alerts(project_id)})

    async def events(request: Request) -> JSONResponse:
        payload = await request.json()
        project_id = str(payload.pop("project_id", "default"))
        payload.setdefault("client_ip", "remote")
        payload.setdefault("method", "ALERT")
        payload.setdefault("path", payload.get("flow_summary", "remote event"))
        payload.setdefault("is_attack", True)
        event = store.ingest(project_id, payload)
        message = json.dumps({"type": "alert", "project_id": project_id, "data": event})
        for websocket in list(sockets):
            try:
                await websocket.send_text(message)
            except Exception:
                sockets.discard(websocket)
        return JSONResponse({"accepted": True, "project_id": project_id, "event": event})

    async def telemetry(websocket: WebSocket):
        project_id = websocket.query_params.get("project_id", "default")
        api_key_param = websocket.query_params.get("api_key")
        if not (api_key_param and verify_api_key(api_key_param, config)) and not _authorized(websocket.headers, config):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        sockets.add(websocket)
        try:
            while True:
                await websocket.send_text(json.dumps({"type": "telemetry", "data": store.stats(project_id)}))
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            pass
        finally:
            sockets.discard(websocket)

    app = Starlette(
        routes=[
            Route("/", dashboard, methods=["GET"]),
            Route("/api/projects", projects, methods=["GET"]),
            Route("/api/stats", stats, methods=["GET"]),
            Route("/api/alerts", alerts, methods=["GET"]),
            Route("/api/events", events, methods=["POST"]),
            WebSocketRoute("/ws", telemetry),
        ]
    )
    app.add_middleware(AuthMiddleware)
    return app