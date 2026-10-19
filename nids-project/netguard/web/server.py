"""Multi-project standalone NetGuard dashboard server."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Set

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
    """Persist bounded per-project alert state in a concurrent SQLite store."""

    MAX_ALERTS_PER_PROJECT = 1000

    def __init__(self, path: str = "netguard-projects.sqlite3", legacy_json_path: str | None = None):
        self.path = path
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)

        if not os.path.exists(self.path) and legacy_json_path and os.path.exists(legacy_json_path):
            self._import_legacy_json(legacy_json_path)
        elif os.path.exists(self.path) and not self._is_sqlite_file(self.path):
            self._migrate_json_in_place()
        self._initialize()

    @staticmethod
    def _is_sqlite_file(path: str) -> bool:
        with open(path, "rb") as data_file:
            return data_file.read(16) == b"SQLite format 3\x00"

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    requests INTEGER NOT NULL DEFAULT 0,
                    attacks INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    event_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_telemetry (
                    project_id TEXT PRIMARY KEY,
                    stats_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_project_id_id
                    ON alerts(project_id, id DESC);
                """
            )

    def _import_legacy_json(self, source_path: str) -> None:
        """Import the old default JSON store without modifying its source file."""
        with open(source_path, "r", encoding="utf-8") as data_file:
            projects = json.load(data_file)
        if not isinstance(projects, dict):
            raise ValueError(f"Legacy dashboard store must contain a JSON object: {source_path}")
        self._initialize()
        with self._connect() as connection:
            for project_id, project in projects.items():
                if not isinstance(project, dict):
                    continue
                connection.execute(
                    "INSERT OR REPLACE INTO projects(project_id, requests, attacks) VALUES (?, ?, ?)",
                    (str(project_id), int(project.get("requests", 0)), int(project.get("attacks", 0))),
                )
                alerts = project.get("alerts", [])
                for event in alerts[-self.MAX_ALERTS_PER_PROJECT:]:
                    connection.execute(
                        "INSERT INTO alerts(project_id, event_json) VALUES (?, ?)",
                        (str(project_id), json.dumps(event)),
                    )

    def _migrate_json_in_place(self) -> None:
        """Convert a JSON file passed as --storage into SQLite atomically."""
        with open(self.path, "r", encoding="utf-8") as data_file:
            projects = json.load(data_file)
        if not isinstance(projects, dict):
            raise ValueError(f"Legacy dashboard store must contain a JSON object: {self.path}")

        temporary_path = f"{self.path}.{uuid.uuid4().hex}.migration.sqlite3"
        temporary_store = DashboardProjectStore(temporary_path)
        with temporary_store._connect() as connection:
            for project_id, project in projects.items():
                if not isinstance(project, dict):
                    continue
                connection.execute(
                    "INSERT OR REPLACE INTO projects(project_id, requests, attacks) VALUES (?, ?, ?)",
                    (str(project_id), int(project.get("requests", 0)), int(project.get("attacks", 0))),
                )
                for event in project.get("alerts", [])[-self.MAX_ALERTS_PER_PROJECT:]:
                    connection.execute(
                        "INSERT INTO alerts(project_id, event_json) VALUES (?, ?)",
                        (str(project_id), json.dumps(event)),
                    )
        os.replace(temporary_path, self.path)
        for suffix in ("-wal", "-shm"):
            sidecar = temporary_path + suffix
            if os.path.exists(sidecar):
                os.remove(sidecar)

    def ingest(self, project_id: str, event: dict) -> dict:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO projects(project_id, attacks) VALUES (?, 1) "
                "ON CONFLICT(project_id) DO UPDATE SET attacks = attacks + 1",
                (project_id,),
            )
            connection.execute(
                "INSERT INTO alerts(project_id, event_json) VALUES (?, ?)",
                (project_id, json.dumps(event)),
            )
            connection.execute(
                "DELETE FROM alerts WHERE project_id = ? AND id NOT IN "
                "(SELECT id FROM alerts WHERE project_id = ? ORDER BY id DESC LIMIT ?)",
                (project_id, project_id, self.MAX_ALERTS_PER_PROJECT),
            )
        return event

    def ingest_telemetry(self, project_id: str, stats: dict) -> dict:
        """Persist the latest request and client snapshot sent by an SDK app."""
        requests = int(stats.get("total_requests", stats.get("requests", 0)))
        attacks = int(stats.get("total_attacks", stats.get("attacks", 0)))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO projects(project_id, requests, attacks) VALUES (?, ?, ?) "
                "ON CONFLICT(project_id) DO UPDATE SET "
                "requests = excluded.requests, attacks = excluded.attacks",
                (project_id, requests, attacks),
            )
            connection.execute(
                "INSERT INTO project_telemetry(project_id, stats_json) VALUES (?, ?) "
                "ON CONFLICT(project_id) DO UPDATE SET stats_json = excluded.stats_json",
                (project_id, json.dumps(stats)),
            )
        return stats

    def projects(self) -> list[str]:
        with self._connect() as connection:
            return [row[0] for row in connection.execute(
                "SELECT project_id FROM projects ORDER BY project_id"
            )]

    def stats(self, project_id: str) -> dict:
        with self._connect() as connection:
            project = connection.execute(
                "SELECT requests, attacks FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            rows = connection.execute(
                "SELECT event_json FROM alerts WHERE project_id = ? ORDER BY id DESC LIMIT 50",
                (project_id,),
            ).fetchall()
            telemetry_row = connection.execute(
                "SELECT stats_json FROM project_telemetry WHERE project_id = ?", (project_id,)
            ).fetchone()
        alerts = [json.loads(row[0]) for row in reversed(rows)]
        telemetry = json.loads(telemetry_row[0]) if telemetry_row else {}
        requests = int(telemetry.get("total_requests", telemetry.get("requests", project["requests"] if project else 0)))
        attacks = int(telemetry.get("total_attacks", telemetry.get("attacks", project["attacks"] if project else 0)))
        alert_summary = telemetry.get("alerts")
        if not isinstance(alert_summary, dict):
            alert_summary = {
                "total": len(alerts),
                "by_label": self._count(alerts, "label"),
                "by_severity": self._count(alerts, "severity"),
            }
        return {
            "project_id": project_id,
            "requests": requests,
            "total_requests": requests,
            "attacks": attacks,
            "total_attacks": attacks,
            "alerts": alert_summary,
            "attacks_by_label": telemetry.get("attacks_by_label", alert_summary.get("by_label", {})),
            "attacks_by_severity": telemetry.get("attacks_by_severity", alert_summary.get("by_severity", {})),
            "recent_events": telemetry.get("recent_events", alerts),
            "top_clients": telemetry.get("top_clients", []),
            "blocked_ips_count": telemetry.get("blocked_ips_count", 0),
            "threat_level": telemetry.get(
                "threat_level", "CRITICAL" if attacks >= 5 else ("ELEVATED" if attacks else "NOMINAL")
            ),
        }

    def alerts(self, project_id: str) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_json FROM alerts WHERE project_id = ? ORDER BY id DESC LIMIT 50",
                (project_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in reversed(rows)]

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
    storage_path: str = "netguard-projects.sqlite3",
) -> Starlette:
    """Create a standalone authenticated, multi-project dashboard app."""
    config = NetGuardConfig(auth_username=username, auth_password=password, auth_api_key=api_key)
    config.validate_auth()
    legacy_path = "netguard-projects.json" if storage_path == "netguard-projects.sqlite3" else None
    store = DashboardProjectStore(storage_path, legacy_json_path=legacy_path)
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

    async def ingest_telemetry(request: Request) -> JSONResponse:
        payload = await request.json()
        project_id = str(payload.get("project_id", "default"))
        stats = payload.get("stats", payload)
        if not isinstance(stats, dict):
            return JSONResponse({"error": "'stats' must be an object"}, status_code=400)
        store.ingest_telemetry(project_id, stats)
        return JSONResponse({"accepted": True, "project_id": project_id})

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
            Route("/api/telemetry", ingest_telemetry, methods=["POST"]),
            WebSocketRoute("/ws", telemetry),
        ]
    )
    app.add_middleware(AuthMiddleware)
    return app
