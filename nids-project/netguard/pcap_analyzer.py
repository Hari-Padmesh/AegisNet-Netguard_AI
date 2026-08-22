"""
netguard/pcap_analyzer.py
--------------------------
Offline PCAP file analyzer.

Reads a .pcap or .pcapng file packet-by-packet using Scapy, builds
bidirectional network flows via FlowTracker, classifies each completed
flow via DetectionEngine, and produces a structured report.

No admin/sniff privileges required — just a .pcap file on disk.

Usage:
    from netguard.pcap_analyzer import PcapAnalyzer
    analyzer = PcapAnalyzer("capture.pcap")
    report = analyzer.run()
    print(report.summary())
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from netguard.flow_generator import FlowTracker
from netguard.detection import DetectionEngine, PredictionResult
from netguard.alerts import AlertManager

console = Console()


@dataclass
class PcapReport:
    """Results of analyzing a PCAP file."""
    pcap_path: str
    total_packets: int = 0
    total_flows: int = 0
    attack_flows: int = 0
    benign_flows: int = 0
    results: List[PredictionResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"PCAP Analysis Report: {self.pcap_path}",
            f"  Total packets : {self.total_packets}",
            f"  Total flows   : {self.total_flows}",
            f"  Benign flows  : {self.benign_flows}",
            f"  Attack flows  : {self.attack_flows}",
        ]
        if self.attack_flows > 0:
            attack_types = {}
            for r in self.results:
                if r.is_attack:
                    attack_types[r.label] = attack_types.get(r.label, 0) + 1
            lines.append("\n  Attack breakdown:")
            for label, count in sorted(attack_types.items(), key=lambda x: -x[1]):
                lines.append(f"    {label:<20s} {count} flows")
        return "\n".join(lines)


class PcapAnalyzer:
    """
    Analyzes a PCAP file and classifies network flows.

    Parameters
    ----------
    pcap_path : str
        Path to the .pcap or .pcapng file.
    model_dir : str
        Directory containing trained model artifacts.
    idle_timeout : float
        Seconds of inactivity before a flow is considered complete.
    """

    def __init__(
        self,
        pcap_path: str,
        model_dir: str = "models",
        idle_timeout: float = 30.0,
    ):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        self.pcap_path = pcap_path
        self.model_dir = model_dir
        self.idle_timeout = idle_timeout

    def run(self, verbose: bool = True) -> PcapReport:
        """
        Process the PCAP file and return a PcapReport.
        """
        try:
            from scapy.all import PcapReader, IP, TCP, UDP
        except ImportError:
            raise ImportError("Scapy is required: pip install scapy")

        engine = DetectionEngine(model_dir=self.model_dir).load()
        tracker = FlowTracker(idle_timeout=self.idle_timeout)
        alert_mgr = AlertManager()
        report = PcapReport(pcap_path=self.pcap_path)

        def _classify_flows(flows):
            for flow in flows:
                fv = flow.to_feature_vector()
                result = engine.predict(fv, flow_summary=flow.summary())
                report.results.append(result)
                report.total_flows += 1
                if result.is_attack:
                    report.attack_flows += 1
                    alert_mgr.trigger(result)
                else:
                    report.benign_flows += 1

        if verbose:
            console.print(f"\n[bold cyan]📂 Analyzing PCAP:[/bold cyan] {self.pcap_path}")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed} pkts"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Reading packets...", total=None)

            with PcapReader(self.pcap_path) as reader:
                for pkt in reader:
                    report.total_packets += 1
                    progress.update(task, advance=1)

                    if not pkt.haslayer(IP):
                        continue

                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    proto = ip.proto
                    ip_header_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20

                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        sport = tcp.sport
                        dport = tcp.dport
                        tcp_header_len = tcp.dataofs * 4 if hasattr(tcp, 'dataofs') else 20
                        header_len = float(ip_header_len + tcp_header_len)
                        flags = int(tcp.flags) if tcp.flags else 0
                        payload_len = float(len(tcp.payload)) if tcp.payload else 0.0
                    elif pkt.haslayer(UDP):
                        from scapy.all import UDP as ScapyUDP
                        udp = pkt[UDP]
                        sport = udp.sport
                        dport = udp.dport
                        header_len = float(ip_header_len + 8)
                        flags = 0
                        payload_len = float(len(udp.payload)) if udp.payload else 0.0
                    else:
                        continue

                    ts = float(pkt.time) if hasattr(pkt, "time") else None
                    finished = tracker.add_packet(
                        src_ip, dst_ip, sport, dport, proto,
                        payload_len, header_len, flags, ts
                    )
                    _classify_flows(finished)

        # Score remaining active flows
        remaining = tracker.flush_all()
        _classify_flows(remaining)

        if verbose:
            console.print(report.summary())
            if report.attack_flows > 0:
                console.print(f"\n[bold red]⚠️  {report.attack_flows} attack flows detected![/bold red]")
            else:
                console.print("\n[bold green]✅ No attacks detected.[/bold green]")

        return report
