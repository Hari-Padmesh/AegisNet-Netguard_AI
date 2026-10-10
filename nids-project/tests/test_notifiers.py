"""Tests for external alert delivery without making network connections."""

from unittest.mock import MagicMock, patch

from netguard.alerts import Alert, Severity
from netguard.config import NetGuardConfig
from netguard.digest import seconds_until_next_digest
from netguard.notifier.email import EmailNotifier
from netguard.notifier.webhook import WebhookNotifier


def make_alert() -> Alert:
    return Alert(
        timestamp="2026-10-09T12:00:00",
        severity=Severity.HIGH,
        label="PortScan",
        confidence=0.95,
        flow_summary="test flow",
    )


def test_email_notifier_sends_instant_alert_without_real_smtp():
    config = NetGuardConfig(
        project_id="test-app",
        alert_email="owner@example.com",
        smtp_user="sender@example.com",
        smtp_password="app-password",
        smtp_from="sender@example.com",
    )
    smtp = MagicMock()
    with patch("netguard.notifier.email.smtplib.SMTP") as smtp_factory:
        smtp_factory.return_value.__enter__.return_value = smtp
        EmailNotifier(config).notify(make_alert())

    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("sender@example.com", "app-password")
    smtp.send_message.assert_called_once()


def test_email_notifier_sends_digest_without_real_smtp():
    config = NetGuardConfig(
        project_id="test-app",
        alert_email="owner@example.com",
        smtp_user="sender@example.com",
        smtp_password="app-password",
    )
    smtp = MagicMock()
    with patch("netguard.notifier.email.smtplib.SMTP") as smtp_factory:
        smtp_factory.return_value.__enter__.return_value = smtp
        sent = EmailNotifier(config).send_digest([make_alert()])

    assert sent is True
    smtp.send_message.assert_called_once()


def test_webhook_notifier_posts_with_mocked_http():
    notifier = WebhookNotifier("https://example.test/hook", cooldown_seconds=0)
    with patch("netguard.notifier.webhook.requests.post") as post:
        post.return_value.status_code = 204
        notifier.notify(make_alert())

    post.assert_called_once()
    assert post.call_args.kwargs["json"]["attack_type"] == "PortScan"


def test_digest_schedule_calculates_a_future_time():
    import datetime as dt

    now = dt.datetime(2026, 10, 9, 12, 0)  # Friday
    seconds = seconds_until_next_digest("sun", 9, now=now)
    assert seconds == 45 * 60 * 60