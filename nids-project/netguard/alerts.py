"""
netguard/alerts.py
-------------------
Threat scoring and alert management.

Evaluates a PredictionResult and assigns a severity level, then
dispatches the alert to configured outputs (console, log file, callbacks).

Severity levels:
    CRITICAL  — High-confidence DDoS, DoS, Botnet
    HIGH      — High-confidence BruteForce, Infiltration
    MEDIUM    — PortScan, WebAttack, or lower-confidence attacks
    LOW       — Any attack class with confidence < 0.6 (suspicious)
    INFO      — BENIGN traffic (not normally shown)

Usage:
    mgr = AlertManager(log_file="alerts.log")
    mgr.trigger(prediction_result)
"""

import datetime
import json
import os
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional

from rich.console import Console
from rich.panel import Panel

from netguard.detection import PredictionResult


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# Severity style mapping for Rich console output
_SEVERITY_STYLES = {
    Severity.CRITICAL: ("bold red",     "🔴"),
    Severity.HIGH:     ("bold orange3", "🟠"),
    Severity.MEDIUM:   ("bold yellow",  "🟡"),
    Severity.LOW:      ("yellow",       "🟤"),
    Severity.INFO:     ("dim green",    "🟢"),
}

# Attack class → base severity (before confidence adjustment)
_CLASS_SEVERITY = {
    "DDoS":        Severity.CRITICAL,
    "DoS":         Severity.CRITICAL,
    "Botnet":      Severity.CRITICAL,
    "BruteForce":  Severity.HIGH,
    "Infiltration":Severity.HIGH,
    "PortScan":    Severity.MEDIUM,
    "WebAttack":   Severity.MEDIUM,
    "BENIGN":      Severity.INFO,
}

# Confidence threshold below which severity is downgraded to LOW (suspicious)
LOW_CONFIDENCE_THRESHOLD = 0.60


@dataclass
class Alert:
    """A single triggered alert."""
    timestamp: str
    severity: Severity
    label: str
    confidence: float
    flow_summary: str
    probabilities: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp":    self.timestamp,
            "severity":     self.severity.value,
            "label":        self.label,
            "confidence":   round(self.confidence, 4),
            "flow_summary": self.flow_summary,
        }


def score_severity(result: PredictionResult) -> Severity:
    """
    Determine alert severity from a prediction result.

    Logic:
      - BENIGN → INFO
      - Low confidence (< threshold) attack → LOW
      - Otherwise → look up base severity by class
    """
    if not result.is_attack:
        return Severity.INFO

    if result.confidence < LOW_CONFIDENCE_THRESHOLD:
        return Severity.LOW

    # Match known families; fallback to MEDIUM for any unknown class
    return _CLASS_SEVERITY.get(result.label, Severity.MEDIUM)


class AlertManager:
    """
    Receives PredictionResult objects, scores them, and dispatches alerts.

    Parameters
    ----------
    log_file : str, optional
        Path to a JSON-lines log file. If None, disk logging is disabled.
    min_severity : Severity
        Minimum severity level to display/log (anything below is silently dropped).
    show_benign : bool
        If True, also print INFO-level BENIGN results (very noisy, off by default).
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        min_severity: Severity = Severity.LOW,
        show_benign: bool = False,
    ):
        self._console = Console()
        self._log_file = log_file
        self._min_severity = min_severity
        self._show_benign = show_benign
        self._lock = threading.Lock()
        self._history: List[Alert] = []
        self._callbacks: List[Callable[[Alert], None]] = []

        # Severity ordering for comparison
        self._severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

        if log_file:
            os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)

    def register_callback(self, fn: Callable[[Alert], None]) -> None:
        """Register a function to be called on every alert (e.g., dashboard update)."""
        self._callbacks.append(fn)

    def _severity_rank(self, s: Severity) -> int:
        try:
            return self._severity_order.index(s)
        except ValueError:
            return 0

    def trigger(self, result: PredictionResult) -> Optional[Alert]:
        """
        Score a prediction and dispatch an alert if severity meets threshold.

        Returns the Alert object if dispatched, else None.
        """
        severity = score_severity(result)

        if self._severity_rank(severity) < self._severity_rank(self._min_severity):
            return None
        if severity == Severity.INFO and not self._show_benign:
            return None

        ts = datetime.datetime.now().isoformat(timespec="seconds")
        alert = Alert(
            timestamp=ts,
            severity=severity,
            label=result.label,
            confidence=result.confidence,
            flow_summary=result.flow_summary,
            probabilities=result.probabilities,
        )

        with self._lock:
            self._history.append(alert)
            self._print_alert(alert)
            if self._log_file:
                self._write_log(alert)
            for cb in self._callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass

        return alert

    def _print_alert(self, alert: Alert) -> None:
        style, icon = _SEVERITY_STYLES[alert.severity]
        msg = (
            f"{icon} [{style}]{alert.severity.value}[/{style}] "
            f"[bold]{alert.label}[/bold] "
            f"({alert.confidence:.1%} confidence)\n"
            f"[dim]{alert.flow_summary}[/dim]\n"
            f"[dim]{alert.timestamp}[/dim]"
        )
        self._console.print(Panel(msg, border_style=style.split()[0] if ' ' in style else style))

    def _write_log(self, alert: Alert) -> None:
        with open(self._log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.to_dict()) + "\n")

    @property
    def history(self) -> List[Alert]:
        """All alerts seen so far (thread-safe copy)."""
        with self._lock:
            return list(self._history)

    @property
    def attack_count(self) -> int:
        """Number of non-BENIGN alerts dispatched."""
        return sum(1 for a in self._history if a.severity != Severity.INFO)

    def stats(self) -> dict:
        """Return aggregated alert statistics."""
        counts = {s.value: 0 for s in Severity}
        label_counts: dict = {}
        with self._lock:
            for a in self._history:
                counts[a.severity.value] += 1
                label_counts[a.label] = label_counts.get(a.label, 0) + 1
        return {"by_severity": counts, "by_label": label_counts, "total": len(self._history)}
