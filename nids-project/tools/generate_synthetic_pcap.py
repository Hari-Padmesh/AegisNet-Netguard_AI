"""
tools/generate_synthetic_pcap.py
---------------------------------
Generates a small synthetic .pcap file for testing NetGuard AI
without needing real network captures or Npcap/admin privileges.

Creates flows that mimic:
  - Normal HTTPS browsing (BENIGN)
  - SYN port scan pattern (PortScan)
  - Small-packet flood (DoS/DDoS signature)

Run:
    python tools/generate_synthetic_pcap.py
    # Creates: data/test_capture.pcap
"""

import os
import sys
import time

def main():
    
    try:
        from scapy.all import (
            IP, TCP, UDP, Ether,
            wrpcap, RandShort,
        )
    except ImportError:
        print("Error: Scapy is required. Run: pip install scapy")
        sys.exit(1)

    output_path = os.path.join("data", "test_capture.pcap")
    os.makedirs("data", exist_ok=True)

    packets = []
    base_ts = time.time()
    t = base_ts

    print("Generating synthetic PCAP...")

    # ── 1. Normal HTTPS browsing (BENIGN) ─────────────────────────────────────
    # Simulates a client connecting to a web server on port 443
    print("  Adding BENIGN HTTPS flows...")
    for i in range(5):
        client_port = 50000 + i
        for seq in range(8):
            # Client → Server (fwd): varying payload sizes
            pkt = (
                Ether() /
                IP(src="192.168.1.10", dst="93.184.216.34") /
                TCP(sport=client_port, dport=443, flags="PA", seq=seq * 1460) /
                (b"X" * (800 + i * 100))
            )
            pkt.time = t
            packets.append(pkt)
            t += 0.01

            # Server → Client (bwd): typical response
            pkt = (
                Ether() /
                IP(src="93.184.216.34", dst="192.168.1.10") /
                TCP(sport=443, dport=client_port, flags="PA", seq=seq * 512) /
                (b"X" * 512)
            )
            pkt.time = t
            packets.append(pkt)
            t += 0.005

        # FIN to close flow
        fin = (
            Ether() /
            IP(src="192.168.1.10", dst="93.184.216.34") /
            TCP(sport=client_port, dport=443, flags="FA")
        )
        fin.time = t
        packets.append(fin)
        t += 0.1

    # ── 2. Port scan (many SYN packets to different ports) ────────────────────
    print("  Adding PortScan pattern flows...")
    for port in range(20, 80):
        # SYN only (scanner never completes handshake)
        syn = (
            Ether() /
            IP(src="10.10.10.5", dst="192.168.1.100") /
            TCP(sport=RandShort(), dport=port, flags="S")
        )
        syn.time = t
        packets.append(syn)
        t += 0.001

        # RST response from target
        rst = (
            Ether() /
            IP(src="192.168.1.100", dst="10.10.10.5") /
            TCP(sport=port, dport=int(syn[TCP].sport), flags="RA")
        )
        rst.time = t
        packets.append(rst)
        t += 0.001

    # ── 3. Small-packet UDP flood (DoS signature) ──────────────────────────────
    print("  Adding DoS UDP flood flows...")
    for _ in range(200):
        pkt = (
            Ether() /
            IP(src="172.16.0.99", dst="192.168.1.200") /
            UDP(sport=RandShort(), dport=80) /
            (b"\x00" * 50)   # tiny payload, very high rate
        )
        pkt.time = t
        packets.append(pkt)
        t += 0.0005   # 2000 pps rate

    # ── 4. SSH Brute Force (many short TCP connections to port 22) ────────────
    print("  Adding BruteForce SSH flows...")
    for attempt in range(15):
        sport = 60000 + attempt
        for step in range(3):
            pkt = (
                Ether() /
                IP(src="10.20.30.40", dst="192.168.1.50") /
                TCP(sport=sport, dport=22, flags="PA") /
                (b"SSH-2.0-scanner" + bytes([attempt]))
            )
            pkt.time = t
            packets.append(pkt)
            t += 0.05
        # RST after failed auth
        rst = (
            Ether() /
            IP(src="192.168.1.50", dst="10.20.30.40") /
            TCP(sport=22, dport=sport, flags="RA")
        )
        rst.time = t
        packets.append(rst)
        t += 0.1

    print(f"\nWriting {len(packets)} packets to {output_path} ...")
    wrpcap(output_path, packets)
    print(f"Done. PCAP saved to: {output_path}")
    print(f"\nTo analyze it, run:")
    print(f"  netguard scan {output_path}")


if __name__ == "__main__":
    main()
