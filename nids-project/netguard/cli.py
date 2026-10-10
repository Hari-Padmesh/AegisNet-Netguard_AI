"""
netguard/cli.py
----------------
Unified Click-based command-line interface for NetGuard AI.

Commands:
    netguard train   -- Train or retrain the NIDS model
    netguard scan    -- Analyze an offline PCAP file
    netguard monitor -- Live packet capture (requires admin terminal on Windows)
    netguard dashboard -- Launch the interactive TUI dashboard
    netguard info    -- Show loaded model information
"""

import os
import sys

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


@click.group()
@click.version_option("0.2.0", prog_name="NetGuard AI")
def cli():
    """
    \b
    ╔═══════════════════════════════════════╗
    ║      NetGuard AI — NIDS v0.2.0        ║
    ║  ML-powered Network Intrusion Detector ║
    ╚═══════════════════════════════════════╝

    Use one of the commands below to get started.
    """
    pass


# ──────────────────────────────────────────────────────────────────────────────
#  netguard info
# ──────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--model-dir", default="models", show_default=True, help="Model artifacts directory.")
def info(model_dir):
    """Display information about the currently loaded model."""
    from netguard.detection import DetectionEngine

    console.print(Panel("[bold cyan]NetGuard AI — Model Info[/bold cyan]", expand=False))
    try:
        engine = DetectionEngine(model_dir=model_dir).load()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    import json
    meta_path = os.path.join(model_dir, "metadata.json")
    with open(meta_path) as f:
        meta = json.load(f)

    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")
    table.add_row("Model",        meta["model_name"])
    table.add_row("Test macro-F1", f"{meta['test_f1_macro']:.4f}")
    table.add_row("Classes",      ", ".join(meta["classes"]))
    table.add_row("Features",     str(len(meta["features"])))
    console.print(table)

    feat_table = Table(title="Selected Features", box=box.SIMPLE, show_lines=True)
    feat_table.add_column("#", style="dim", width=4)
    feat_table.add_column("Feature Name", style="cyan")
    for i, feat in enumerate(meta["features"], 1):
        feat_table.add_row(str(i), feat)
    console.print(feat_table)


# ──────────────────────────────────────────────────────────────────────────────
#  netguard train
# ──────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--data-dir",        default="data/raw/", show_default=True, help="Raw CSV directory.")
@click.option("--top-n-features",  default=20,          show_default=True, help="Features to select.")
@click.option("--cv-folds",        default=5,           show_default=True, help="Cross-validation folds.")
@click.option("--cv-jobs",         default=2,           show_default=True, help="Parallel CV jobs.")
@click.option("--model-dir",       default="models",    show_default=True, help="Where to save artifacts.")
@click.option("--no-collapse",     is_flag=True,        default=False,     help="Keep fine-grained attack labels.")
def train(data_dir, top_n_features, cv_folds, cv_jobs, model_dir, no_collapse):
    """Train and compare NIDS models on CICIDS2017-style CSV data."""
    from netguard.train import train_pipeline

    console.print(Panel("[bold cyan]NetGuard AI — Training Pipeline[/bold cyan]", expand=False))
    try:
        train_pipeline(
            data_dir=data_dir,
            top_n_features=top_n_features,
            cv_folds=cv_folds,
            cv_jobs=cv_jobs,
            collapse_families=not no_collapse,
            model_dir=model_dir,
        )
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
#  netguard evaluate
# ──────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--model-dir",    default="models",         show_default=True)
@click.option("--figures-dir",  default="reports/figures", show_default=True)
def evaluate(model_dir, figures_dir):
    """Run full evaluation: per-class metrics, FPR, confusion matrix, ROC curves."""
    from netguard.evaluate import run_evaluation

    console.print(Panel("[bold cyan]NetGuard AI — Model Evaluation[/bold cyan]", expand=False))
    try:
        run_evaluation(model_dir=model_dir, figures_dir=figures_dir)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
#  netguard scan
# ──────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--model-dir",     default="models", show_default=True)
@click.option("--idle-timeout",  default=30.0,     show_default=True, help="Flow idle timeout (seconds).")
@click.option("--log-file",      default=None,     help="Path to write JSON-lines alert log.")
@click.option("--quiet",         is_flag=True,     help="Suppress per-flow output.")
def scan(pcap_file, model_dir, idle_timeout, log_file, quiet):
    """
    Analyze an offline PCAP file and report detected threats.

    PCAP_FILE: Path to the .pcap or .pcapng file to analyze.
    """
    from netguard.pcap_analyzer import PcapAnalyzer

    console.print(Panel("[bold cyan]NetGuard AI — PCAP Scanner[/bold cyan]", expand=False))
    try:
        analyzer = PcapAnalyzer(
            pcap_file,
            model_dir=model_dir,
            idle_timeout=idle_timeout,
        )
        report = analyzer.run(verbose=not quiet)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    # Print final report table
    table = Table(title="PCAP Scan Summary", box=box.ROUNDED)
    table.add_column("Metric",   style="bold cyan")
    table.add_column("Value",    style="white")
    table.add_row("File",         report.pcap_path)
    table.add_row("Packets",      str(report.total_packets))
    table.add_row("Flows",        str(report.total_flows))
    table.add_row("Benign",       f"[green]{report.benign_flows}[/green]")
    table.add_row("Attacks",      f"[red]{report.attack_flows}[/red]")
    console.print(table)


# ──────────────────────────────────────────────────────────────────────────────
#  netguard monitor  (live capture)
# ──────────────────────────────────────────────────────────────────────────────
@cli.command()
@click.option("--interface", "-i",  default=None,    help="Network interface to sniff (default: first available).")
@click.option("--model-dir",        default="models", show_default=True)
@click.option("--idle-timeout",     default=30.0,    show_default=True)
@click.option("--log-file",         default="alerts.log", show_default=True)
@click.option("--count",            default=0,       help="Stop after N packets (0 = run indefinitely).")
def monitor(interface, model_dir, idle_timeout, log_file, count):
    """
    Live packet capture and real-time intrusion detection.

    ⚠️  Requires an elevated (Admin) terminal on Windows.
    Uses Layer 3 raw sockets (no external drivers needed).
    """
    # Gracefully check for Scapy availability before doing anything
    try:
        from scapy.all import IP, TCP, UDP, conf
    except ImportError:
        console.print("[red]Error:[/red] Scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    # Configure to use Layer 3 sockets (no WinPcap needed)
    conf.use_pcap = False

    try:
        import socket
    except ImportError:
        console.print("[red]Error:[/red] socket module not available")
        sys.exit(1)

    console.print(Panel(
        f"[bold cyan]NetGuard AI — Live Monitor[/bold cyan]\n"
        f"Mode      : [yellow]Layer 3 Raw Sockets[/yellow]\n"
        f"Log file  : [dim]{log_file}[/dim]\n"
        f"Press [bold]Ctrl+C[/bold] to stop.",
        expand=False,
    ))

    from netguard.detection import DetectionEngine
    from netguard.flow_generator import FlowTracker
    from netguard.alerts import AlertManager

    try:
        engine = DetectionEngine(model_dir=model_dir).load()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    tracker = FlowTracker(idle_timeout=idle_timeout)
    alert_mgr = AlertManager(log_file=log_file)
    pkt_counter = {"n": 0}

    def _process_packet(pkt):
        pkt_counter["n"] += 1
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        ip_header_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            header_len = float(ip_header_len + (tcp.dataofs * 4 if hasattr(tcp, 'dataofs') else 20))
            flags = int(tcp.flags) if tcp.flags else 0
            payload_len = float(len(tcp.payload)) if tcp.payload else 0.0
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            header_len = float(ip_header_len + 8)
            flags = 0
            payload_len = float(len(udp.payload)) if udp.payload else 0.0
        else:
            return

        ts = float(pkt.time) if hasattr(pkt, "time") else None
        finished = tracker.add_packet(
            ip.src, ip.dst, sport, dport, ip.proto,
            payload_len, header_len, flags, ts
        )
        idle = tracker.collect_idle_flows()

        for flow in finished + idle:
            fv = flow.to_feature_vector()
            result = engine.predict(fv, flow_summary=flow.summary())
            if result.is_attack:
                alert_mgr.trigger(result)

    # Windows Layer 3 raw socket packet capture (no WinPcap needed)
    try:
        # Create a raw socket for capturing all incoming IP packets
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))
        # Enable receiving all packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        pkt_count = 0
        while True:
            if count > 0 and pkt_count >= count:
                break
            
            try:
                raw_data = sniffer.recvfrom(65535)[0]
                # Parse raw bytes as IP packet using Scapy
                pkt = IP(raw_data)
                _process_packet(pkt)
                pkt_count += 1
            except Exception as e:
                # Skip packets that can't be parsed
                continue
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Capture stopped by user.[/bold yellow]")
    except PermissionError:
        console.print(
            "[red]Permission denied.[/red] "
            "Run the terminal as Administrator on Windows."
        )
    finally:
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
        except:
            pass

    stats = alert_mgr.stats()
    console.print(
        f"\n[bold]Session summary:[/bold] "
        f"{pkt_counter['n']} packets, "
        f"{stats['total']} alerts triggered."
    )


# ──────────────────────────────────────────────────────────────────────────────
#  netguard monitor-dashboard  (live capture + interactive dashboard)
# ──────────────────────────────────────────────────────────────────────────────
@cli.command("monitor-dashboard")
@click.option("--model-dir",    default="models", show_default=True)
@click.option("--idle-timeout", default=30.0,    show_default=True)
def monitor_dashboard(model_dir, idle_timeout):
    """
    Live monitoring with interactive dashboard.
    
    Captures packets and displays real-time alerts on an interactive TUI dashboard.

    ⚠️  Requires an elevated (Admin) terminal on Windows.
    Uses Layer 3 raw sockets (no external drivers needed).
    """
    import socket
    import threading
    from datetime import datetime
    from netguard.detection import DetectionEngine
    from netguard.flow_generator import FlowTracker
    from netguard.alerts import AlertManager, Alert, Severity
    from netguard.dashboard import NetGuardDashboard
    from scapy.all import IP, TCP, UDP, conf

    # Configure to use Layer 3 sockets
    conf.use_pcap = False

    try:
        engine = DetectionEngine(model_dir=model_dir).load()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

    # Create the dashboard app
    dashboard_app = NetGuardDashboard(model_dir=model_dir)

    # Monitoring state
    monitor_state = {"running": True, "pkt_count": 0}
    tracker = FlowTracker(idle_timeout=idle_timeout)

    def _monitor_thread():
        """Background thread that captures packets and pushes alerts to dashboard."""
        try:
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            while monitor_state["running"]:
                try:
                    raw_data = sniffer.recvfrom(65535)[0]
                    pkt = IP(raw_data)

                    if not pkt.haslayer(IP):
                        continue

                    ip = pkt[IP]
                    ip_header_len = ip.ihl * 4 if hasattr(ip, "ihl") else 20

                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        sport, dport = tcp.sport, tcp.dport
                        header_len = float(
                            ip_header_len + (tcp.dataofs * 4 if hasattr(tcp, "dataofs") else 20)
                        )
                        flags = int(tcp.flags) if tcp.flags else 0
                        payload_len = float(len(tcp.payload)) if tcp.payload else 0.0
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        sport, dport = udp.sport, udp.dport
                        header_len = float(ip_header_len + 8)
                        flags = 0
                        payload_len = float(len(udp.payload)) if udp.payload else 0.0
                    else:
                        continue

                    ts = float(pkt.time) if hasattr(pkt, "time") else None
                    finished = tracker.add_packet(
                        ip.src, ip.dst, sport, dport, ip.proto, payload_len, header_len, flags, ts
                    )
                    idle = tracker.collect_idle_flows()

                    for flow in finished + idle:
                        fv = flow.to_feature_vector()
                        result = engine.predict(fv, flow_summary=flow.summary())
                        
                        # Convert PredictionResult to Alert for dashboard
                        if result.is_attack:
                            if result.confidence >= 0.9:
                                severity = Severity.CRITICAL
                            elif result.confidence >= 0.75:
                                severity = Severity.HIGH
                            else:
                                severity = Severity.MEDIUM
                        else:
                            severity = Severity.INFO
                        
                        alert = Alert(
                            severity=severity,
                            timestamp=datetime.utcnow().isoformat() + "Z",
                            label=result.label,
                            confidence=result.confidence,
                            flow_summary=result.flow_summary,
                        )
                        dashboard_app.push_alert(alert)

                    monitor_state["pkt_count"] += 1

                except Exception:
                    continue

        except PermissionError:
            console.print(
                "[red]Permission denied.[/red] "
                "Run the terminal as Administrator on Windows."
            )
        finally:
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                sniffer.close()
            except:
                pass
            monitor_state["running"] = False

    # Start monitoring in background thread
    thread = threading.Thread(target=_monitor_thread, daemon=True)
    thread.start()

    # Run the dashboard (blocks until user quits)
    try:
        dashboard_app.run()
    finally:
        monitor_state["running"] = False
        thread.join(timeout=2)


@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True)
@click.option("--auth-username", required=True)
@click.option("--auth-password", required=True)
@click.option("--api-key", default=None)
@click.option("--storage", default="netguard-projects.json", show_default=True)
def serve(host, port, auth_username, auth_password, api_key, storage):
    """Run the authenticated standalone web dashboard."""
    try:
        import uvicorn
    except ImportError:
        raise click.ClickException("Uvicorn is required. Install with: pip install 'netguard[web]'")

    from netguard.web.server import create_dashboard_server_app

    console.print(f"[bold cyan]NetGuard dashboard:[/bold cyan] http://{host}:{port}/")
    uvicorn.run(
        create_dashboard_server_app(auth_username, auth_password, api_key or "", storage),
        host=host,
        port=port,
    )


@cli.command("digest")
@click.option("--send", "send_now", is_flag=True, help="Send the digest immediately.")
def digest(send_now):
    """Inspect or send the configured weekly email digest."""
    if not send_now:
        console.print("Use --send to deliver the current alert history.")
        return
    from netguard.core import NetGuard

    try:
        guard = NetGuard()
    except ValueError as exc:
        raise click.ClickException(str(exc))
    if not guard.send_weekly_digest():
        raise click.ClickException("SMTP is not fully configured for digest delivery.")
    console.print("Weekly digest sent.")


@cli.command("proxy")
@click.option("--target", required=True, help="Upstream HTTP URL, e.g. http://127.0.0.1:3000")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8080, show_default=True)
@click.option("--project-id", required=True)
@click.option("--auth-username", required=True)
@click.option("--auth-password", required=True)
@click.option("--api-key", default=None)
@click.option("--model-dir", default="models", show_default=True)
def proxy(target, host, port, project_id, auth_username, auth_password, api_key, model_dir):
    """Run an unprivileged HTTP reverse proxy with NetGuard protection."""
    try:
        import uvicorn
    except ImportError:
        raise click.ClickException("Uvicorn is required. Install with: pip install 'netguard[web]'")

    from netguard.config import NetGuardConfig
    from netguard.core import NetGuard
    from netguard.proxy import create_proxy_app

    guard = NetGuard(
        config=NetGuardConfig(
            project_id=project_id,
            model_dir=model_dir,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_api_key=api_key or "",
            log_file="alerts.log",
        )
    )
    console.print(f"[bold cyan]NetGuard proxy:[/bold cyan] http://{host}:{port} -> {target}")
    uvicorn.run(create_proxy_app(target, guard), host=host, port=port)


@cli.command()
@click.option("--model-dir", default=None, help="Model artifacts directory.")
def dashboard(model_dir):
    """Launch the interactive Textual TUI dashboard."""
    from netguard.dashboard import run_dashboard
    run_dashboard(model_dir=model_dir if model_dir else "models")


# ──────────────────────────────────────────────────────────────────────────────
#  netguard dashboard-web
# ──────────────────────────────────────────────────────────────────────────────
@cli.command("dashboard-web")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
@click.option("--port", default=8888, show_default=True, help="Port to listen on.")
@click.option("--model-dir", default=None, help="Model artifacts directory.")
@click.option("--project-id", default="dashboard", show_default=True)
@click.option("--auth-username", envvar="NETGUARD_AUTH_USERNAME", required=True)
@click.option("--auth-password", envvar="NETGUARD_AUTH_PASSWORD", required=True)
@click.option("--api-key", envvar="NETGUARD_AUTH_API_KEY", default=None)
def dashboard_web(host, port, model_dir, project_id, auth_username, auth_password, api_key):
    """Launch the modern real-time Web Dashboard (accessible via browser)."""
    import uvicorn
    from netguard.config import DashboardMode, NetGuardConfig
    from netguard.core import NetGuard
    from netguard.web.app import create_dashboard_app

    console.print(Panel(
        f"[bold cyan]NetGuard AI — Web Defense Dashboard[/bold cyan]\n"
        f"Dashboard URL : [bold green]http://{host}:{port}[/bold green]\n"
        f"Security Mode : [yellow]Zero-Admin Web Guard[/yellow]\n"
        f"Press [bold]Ctrl+C[/bold] to stop.",
        expand=False,
    ))

    guard = NetGuard(
        config=NetGuardConfig(
            project_id=project_id,
            model_dir=model_dir or "models",
            dashboard_mode=DashboardMode.EMBEDDED,
            dashboard_port=port,
            auth_username=auth_username,
            auth_password=auth_password,
            auth_api_key=api_key or "",
            log_file="alerts.log",
        )
    )
    dash_app = create_dashboard_app(guard)

    uvicorn.run(dash_app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    cli()

