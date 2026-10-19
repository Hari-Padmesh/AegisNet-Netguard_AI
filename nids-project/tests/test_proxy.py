"""Tests for the unprivileged reverse proxy boundary."""

from unittest.mock import patch

from starlette.testclient import TestClient

from netguard.core import NetGuard
from netguard.proxy import create_proxy_app


class FakeResponse:
    status_code = 200
    content = b"upstream response"
    headers = {"content-type": "text/plain"}


class FakeClient:
    def __init__(self, **kwargs):
        self.options = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def request(self, method, url, **kwargs):
        assert method == "GET"
        assert url == "http://upstream.test/items?q=1"
        return FakeResponse()


class FailingClient(FakeClient):
    async def request(self, method, url, **kwargs):
        import httpx

        raise httpx.ConnectError("upstream unavailable")


def test_proxy_forwards_requests_through_netguard():
    guard = NetGuard(
        project_id="proxy-test",
        auth_username="admin",
        auth_password="secret",
        log_file=None,
        console_alerts=False,
    )
    app = create_proxy_app("http://upstream.test", guard)

    with patch("httpx.AsyncClient", FakeClient):
        response = TestClient(app).get("/items?q=1")

    assert response.status_code == 200
    assert response.text == "upstream response"
    assert guard.request_count == 1


def test_proxy_returns_bad_gateway_when_upstream_is_unavailable():
    guard = NetGuard(
        project_id="proxy-test",
        auth_username="admin",
        auth_password="secret",
        log_file=None,
        console_alerts=False,
    )
    app = create_proxy_app("http://upstream.test", guard)

    with patch("httpx.AsyncClient", FailingClient):
        response = TestClient(app).get("/")

    assert response.status_code == 502
    assert "could not reach upstream" in response.text