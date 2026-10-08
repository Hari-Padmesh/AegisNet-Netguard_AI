"""Tests for NetGuard configuration."""

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
