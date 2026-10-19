"""Tests for NetGuard configuration."""

import json

import pytest

from netguard.config import NetGuardConfig


def test_validate_auth_requires_credentials():
    cfg = NetGuardConfig(auth_username="", auth_password="", auth_api_key="")
    with pytest.raises(ValueError, match="authentication is required"):
        cfg.validate_auth()


def test_validate_auth_accepts_api_key():
    cfg = NetGuardConfig(auth_api_key="test-key-123")
    cfg.validate_auth()


def test_validate_auth_accepts_basic_credentials():
    cfg = NetGuardConfig(auth_username="admin", auth_password="secret")
    cfg.validate_auth()


def test_dashboard_mode_string_override_is_normalized():
    cfg = NetGuardConfig.from_env(
        dashboard_mode="separate",
        auth_username="admin",
        auth_password="secret",
    )
    assert cfg.dashboard_mode.value == "separate"


def test_rule_cooldowns_can_be_configured_from_environment(monkeypatch):
    monkeypatch.setenv("NETGUARD_RULE_COOLDOWNS", json.dumps({"http.sqli": 5, "http.xss": 0}))

    cfg = NetGuardConfig.from_env()

    assert cfg.rule_cooldowns["http.sqli"] == 5.0
    assert cfg.rule_cooldowns["http.xss"] == 0.0
    assert cfg.rule_cooldowns["http.request_burst"] == 30.0
