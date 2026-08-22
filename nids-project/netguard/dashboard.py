"""
netguard/dashboard.py
----------------------
Interactive terminal UI dashboard for NetGuard AI.

Built with Textual (https://textual.textualize.io/) — a rich TUI framework.

Layout:
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  HEADER: NetGuard AI — Network Intrusion Detection System               │
  ├──────────────────────┬─────────────────────────┬────────────────────────┤
  │  STATS PANEL         │  LIVE ALERTS FEED        │  FLOW INSPECTOR        │
  │  (top metrics)       │  (scrollable log)        │  (selected alert)      │
  ├──────────────────────┴─────────────────────────┴────────────────────────┤
  │  FOOTER: key bindings                                                    │
  └─────────────────────────────────────────────────────────────────────────┘

Usage:
    netguard dashboard
    # or programmatically:
    from netguard.dashboard import run_dashboard
    run_dashboard()
"""

import json
import os
import time
import threading
from datetime import datetime
from typing import Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header,
    Footer,
    Static,
    Label,
    ListView,
    ListItem,
    DataTable,
    Digits,
    RichLog,
    TabbedContent,
    TabPane,
)
from textual.reactive import reactive
from textual.timer import Timer

from netguard.alerts import Alert, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "red",
    Severity.HIGH:     "orange3",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "gold3",
    Severity.INFO:     "green",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟤",
    Severity.INFO:     "🟢",
}


class StatBox(Static):
    """A single stat number box in the top metrics panel."""

    def __init__(self, label: str, value: str = "0", color: str = "cyan", **kwargs):
        super().__init__(**kwargs)
        self._label = label
        self._value = value
        self._color = color

    def compose(self) -> ComposeResult:
        yield Label(self._label, id="stat-label")
        yield Label(self._value, id="stat-value")

    def update_value(self, value: str) -> None:
        self.query_one("#stat-value", Label).update(value)


class AlertRow(ListItem):
    """A single row in the alerts feed list."""

    def __init__(self, alert: Alert, **kwargs):
        super().__init__(**kwargs)
        self.alert = alert

    def compose(self) -> ComposeResult:
        color = _SEVERITY_COLOR.get(self.alert.severity, "white")
        icon = _SEVERITY_ICON.get(self.alert.severity, "⚪")
        ts = self.alert.timestamp.split("T")[-1]  # Just the time part
        text = Text.assemble(
            (f"{icon} ", ""),
            (f"[{self.alert.severity.value}] ", f"bold {color}"),
            (f"{self.alert.label}", "bold white"),
            (f"  {self.alert.confidence:.0%}", "dim white"),
            (f"  {ts}", "dim"),
        )
        yield Label(text)


class NetGuardDashboard(App):
    """
    The main Textual TUI application.
    """

    CSS = """
    Screen {
        background: #0d0d1a;
    }

    Header {
        background: #1a1a3e;
        color: $accent;
    }

    Footer {
        background: #1a1a3e;
    }

    #stats-bar {
        height: 7;
        layout: horizontal;
        padding: 0 1;
        background: #12122a;
        border-bottom: solid #2a2a5a;
    }

    StatBox {
        width: 1fr;
        height: 5;
        margin: 1;
        border: round #2a2a5a;
        background: #16163a;
        content-align: center middle;
        padding: 0 1;
    }

    StatBox #stat-label {
        color: #8888cc;
        text-style: bold;
        content-align: center middle;
        width: 100%;
    }

    StatBox #stat-value {
        color: $accent;
        text-style: bold;
        content-align: center middle;
        width: 100%;
        text-align: center;
    }

    #main-area {
        layout: horizontal;
        height: 1fr;
    }

    #alerts-panel {
        width: 2fr;
        border-right: solid #2a2a5a;
        background: #0d0d1a;
    }

    #alerts-title {
        background: #1a1a3e;
        padding: 0 1;
        height: 2;
        color: $accent;
        text-style: bold;
        content-align: left middle;
    }

    #alerts-log {
        height: 1fr;
        scrollbar-color: #2a2a5a;
        background: #0d0d1a;
        border: none;
        padding: 0 1;
    }

    #inspector-panel {
        width: 1fr;
        background: #0d0d1a;
        padding: 0 1;
    }

    #inspector-title {
        background: #1a1a3e;
        padding: 0 1;
        height: 2;
        color: $accent;
        text-style: bold;
        content-align: left middle;
    }

    #inspector-content {
        height: 1fr;
        padding: 1;
    }

    DataTable {
        background: #0d0d1a;
        border: round #2a2a5a;
        height: auto;
    }

    .no-alerts {
        color: #555577;
        text-align: center;
        content-align: center middle;
        height: 100%;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("c", "clear_alerts", "Clear Alerts"),
    ]

    TITLE = "NetGuard AI — Network Intrusion Detection System"
    SUB_TITLE = "Real-Time Threat Monitor"

    # Reactive counters — Textual will re-render on change
    total_flows:   reactive[int] = reactive(0)
    attack_count:  reactive[int] = reactive(0)
    benign_count:  reactive[int] = reactive(0)

    def __init__(self, model_dir: str = "models", **kwargs):
        super().__init__(**kwargs)
        self._model_dir = model_dir
        self._alerts_queue: list[Alert] = []
        self._queue_lock = threading.Lock()
        self._refresh_timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        yield Header()

        # ── Top stats bar ────────────────────────────────────────────────────
        with Container(id="stats-bar"):
            yield StatBox("TOTAL FLOWS",   "0",  id="stat-flows")
            yield StatBox("🚨 ATTACKS",    "0",  id="stat-attacks")
            yield StatBox("✅ BENIGN",     "0",  id="stat-benign")
            yield StatBox("UPTIME",        "0s", id="stat-uptime")

        # ── Main two-panel area ───────────────────────────────────────────────
        with Horizontal(id="main-area"):
            # Left: alerts feed
            with Vertical(id="alerts-panel"):
                yield Label("⚡ Live Alerts Feed", id="alerts-title")
                yield RichLog(id="alerts-log", highlight=True, markup=True, wrap=True)

            # Right: model info inspector
            with Vertical(id="inspector-panel"):
                yield Label("🔍 Model Info", id="inspector-title")
                yield Static(self._build_model_info(), id="inspector-content")

        yield Footer()

    def on_mount(self) -> None:
        """Called when the app is ready. Start the periodic refresh timer."""
        self._start_time = time.time()
        self._refresh_timer = self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        """Called every second to flush queued alerts and update stats."""
        with self._queue_lock:
            pending = list(self._alerts_queue)
            self._alerts_queue.clear()

        for alert in pending:
            self._render_alert(alert)

        uptime = int(time.time() - self._start_time)
        m, s = divmod(uptime, 60)
        h, m = divmod(m, 60)
        uptime_str = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
        self.query_one("#stat-uptime", StatBox).update_value(uptime_str)

    def push_alert(self, alert: Alert) -> None:
        """Thread-safe: called from the AlertManager callback."""
        with self._queue_lock:
            self._alerts_queue.append(alert)

        if alert.severity != Severity.INFO:
            self.total_flows += 1
            self.attack_count += 1
        else:
            self.total_flows += 1
            self.benign_count += 1

    def watch_attack_count(self, value: int) -> None:
        self.query_one("#stat-attacks", StatBox).update_value(str(value))

    def watch_benign_count(self, value: int) -> None:
        self.query_one("#stat-benign", StatBox).update_value(str(value))

    def watch_total_flows(self, value: int) -> None:
        self.query_one("#stat-flows", StatBox).update_value(str(value))

    def _render_alert(self, alert: Alert) -> None:
        log = self.query_one("#alerts-log", RichLog)
        color = _SEVERITY_COLOR.get(alert.severity, "white")
        icon  = _SEVERITY_ICON.get(alert.severity, "⚪")
        ts    = alert.timestamp.split("T")[-1]
        line  = (
            f"{icon} [bold {color}][{alert.severity.value}][/bold {color}] "
            f"[bold white]{alert.label}[/bold white] "
            f"[dim]({alert.confidence:.0%})[/dim] "
            f"[dim]{ts}[/dim]\n"
            f"  [dim]{alert.flow_summary}[/dim]"
        )
        log.write(line)

    def _build_model_info(self) -> str:
        meta_path = os.path.join(self._model_dir, "metadata.json")
        if not os.path.exists(meta_path):
            return "[dim red]No model loaded.\nRun: netguard train[/dim red]"
        with open(meta_path) as f:
            meta = json.load(f)
        lines = [
            f"[bold cyan]Model[/bold cyan]       {meta['model_name']}",
            f"[bold cyan]F1 Macro[/bold cyan]    {meta['test_f1_macro']:.4f}",
            f"[bold cyan]Classes[/bold cyan]     {len(meta['classes'])}",
            "",
            "[bold cyan]Attack Classes:[/bold cyan]",
        ]
        for cls in meta["classes"]:
            color = "red" if cls != "BENIGN" else "green"
            lines.append(f"  [{color}]• {cls}[/{color}]")
        lines += [
            "",
            f"[bold cyan]Features:[/bold cyan] {len(meta['features'])} selected",
        ]
        for feat in meta["features"]:
            lines.append(f"  [dim]• {feat}[/dim]")
        return "\n".join(lines)

    def action_clear_alerts(self) -> None:
        """Clear the alerts log panel."""
        self.query_one("#alerts-log", RichLog).clear()
        self.notify("Alert log cleared.", severity="information")


def run_dashboard(model_dir: str = "models") -> None:
    """Entry point for the dashboard command."""
    app = NetGuardDashboard(model_dir=model_dir)
    app.run()
