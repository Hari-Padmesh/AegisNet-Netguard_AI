"""Unprivileged HTTP reverse proxy protected by NetGuard middleware."""

from __future__ import annotations

from typing import Iterable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from netguard.core import NetGuard
from netguard.integrations.fastapi import setup_netguard


def _forward_headers(headers: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {
        key: value
        for key, value in headers
        if key.lower() not in {"host", "content-length", "connection"}
    }


def create_proxy_app(target: str, guard: NetGuard) -> Starlette:
    """Create a reverse proxy app for an HTTP target URL."""
    try:
        import httpx
    except ImportError as exc:
        raise ImportError("Proxy mode requires: pip install 'netguard[web]'") from exc

    async def proxy(request: Request) -> Response:
        target_url = f"{target.rstrip('/')}{request.url.path}"
        if request.url.query:
            target_url = f"{target_url}?{request.url.query}"
        try:
            async with httpx.AsyncClient(follow_redirects=False) as client:
                upstream = await client.request(
                    request.method,
                    target_url,
                    headers=_forward_headers(request.headers.items()),
                    content=await request.body(),
                )
        except httpx.RequestError as exc:
            return Response(
                content=f"NetGuard proxy could not reach upstream: {exc}",
                status_code=502,
                media_type="text/plain",
            )
        response_headers = _forward_headers(upstream.headers.items())
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
        )

    routes = [Route("/{path:path}", proxy, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])]
    app = Starlette(routes=routes)
    setup_netguard(app, guard)
    return app