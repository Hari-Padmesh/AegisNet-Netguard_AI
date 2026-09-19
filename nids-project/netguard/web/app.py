"""
netguard/web/app.py
-------------------
Embeddable ASGI Dashboard Application for NetGuard AI.
Exposes REST and WebSocket endpoints for real-time monitoring and threat alerts.
Can be mounted on any FastAPI/Starlette app via app.mount("/_netguard", dashboard_app).
"""

import asyncio
import json
import os
from typing import Set

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from netguard.integrations.base import AppTrafficMonitor
from netguard.alerts import Alert


def create_dashboard_app(monitor: AppTrafficMonitor) -> Starlette:
    """
    Factory creating a self-contained Starlette ASGI dashboard app.

    Parameters
    ----------
    monitor : AppTrafficMonitor
        The active in-app traffic monitor instance.
    """
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    html_path = os.path.join(static_dir, "dashboard.html")

    active_websockets: Set[WebSocket] = set()

    async def get_dashboard_html(request: Request) -> HTMLResponse:
        """Serve the dark-mode cyber defense dashboard UI."""
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()
            return HTMLResponse(content)
        return HTMLResponse("<h1>NetGuard Dashboard static file not found</h1>", status_code=404)

    async def api_stats(request: Request) -> JSONResponse:
        """REST endpoint returning aggregated stats."""
        stats = monitor.get_stats()
        return JSONResponse(stats)

    async def api_alerts(request: Request) -> JSONResponse:
        """REST endpoint returning recent alert history."""
        history = [a.to_dict() for a in monitor.alert_manager.history[-50:]]
        return JSONResponse({"alerts": history})

    async def api_block_ip(request: Request) -> JSONResponse:
        """REST endpoint for manual IP blocking/unblocking."""
        try:
            body = await request.json()
            ip = body.get("ip")
            action = body.get("action", "block")
            if not ip:
                return JSONResponse({"error": "Missing 'ip' parameter"}, status_code=400)

            if action == "unblock":
                monitor.unblock_ip(ip)
                return JSONResponse({"status": "unblocked", "ip": ip})
            else:
                monitor.block_ip(ip)
                return JSONResponse({"status": "blocked", "ip": ip})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    async def ws_telemetry(websocket: WebSocket):
        """WebSocket streaming live telemetry and attack alerts."""
        await websocket.accept()
        active_websockets.add(websocket)

        try:
            while True:
                # Stream stats every 1 second
                stats = monitor.get_stats()
                await websocket.send_text(json.dumps({
                    "type": "telemetry",
                    "data": stats
                }))
                await asyncio.sleep(1.0)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            active_websockets.discard(websocket)

    def on_new_alert(alert: Alert) -> None:
        """Callback from AlertManager to broadcast instant alert to connected WebSockets."""
        if not active_websockets:
            return
        payload = json.dumps({
            "type": "alert",
            "data": alert.to_dict()
        })
        for ws in list(active_websockets):
            try:
                asyncio.create_task(ws.send_text(payload))
            except Exception:
                pass

    # Register callback on the monitor's alert manager
    monitor.alert_manager.register_callback(on_new_alert)

    routes = [
        Route("/", endpoint=get_dashboard_html, methods=["GET"]),
        Route("/api/stats", endpoint=api_stats, methods=["GET"]),
        Route("/api/alerts", endpoint=api_alerts, methods=["GET"]),
        Route("/api/block-ip", endpoint=api_block_ip, methods=["POST"]),
        WebSocketRoute("/ws", endpoint=ws_telemetry),
    ]

    return Starlette(routes=routes)
