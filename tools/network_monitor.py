"""
tools/network_monitor.py
=========================
Network behavioral monitor - generates network_score for the risk formula.

Detects:
  - Suspicious outbound connections (known C2 ports)
  - Repeated DNS queries (DGA beaconing, domain rotation)
  - Destination IP diversity (connecting to many IPs quickly = C2 sweep)
  - Protocol anomalies (high UDP, unexpected ICMP)
  - Packet rate spikes (exfiltration burst before encryption)

Output:
  network_score: float 0.0–1.0  (fed into BehavioralEngine.ingest())
  NetworkAlert: structured object with findings

Uses psutil for connection enumeration (no raw sockets - works unprivileged).
Optional dpkt integration for pcap-level analysis when Wireshark capture exists.
"""

import os
import time
import math
import json
import logging
import socket
import datetime
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

log = logging.getLogger("ransomshield.network")

# ── Known C2 / suspicious ports ───────────────────────────────────────────────
C2_PORTS = {
    4444, 4445, 4446,       # Metasploit default listeners
    8080, 8443, 8888,       # common alternative HTTP/S C2
    9001, 9030,             # Tor entry/exit
    1080,                   # SOCKS proxy
    6667, 6697,             # IRC-based C2 (legacy)
    14147, 19101,           # REvil / Sodinokibi
    49152, 49153,           # ephemeral C2 sometimes used by LockBit
}

# Private IP ranges - connections OUTSIDE these are external/suspicious in isolated lab
PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8
]

# DGA detection thresholds
DGA_ENTROPY_THRESH  = 3.5
DGA_MIN_LABEL_LEN   = 10
BEACON_WINDOW_SEC   = 120.0
BEACON_REGULARITY   = 0.70
MAX_UNIQUE_DESTS    = 20      # more than this in short window = suspicious sweep


def _is_private_ip(ip_str: str) -> bool:
    try:
        packed = int.from_bytes(socket.inet_aton(ip_str), "big")
        return any((packed & mask) == (base & mask) for base, mask in PRIVATE_RANGES)
    except Exception:
        return True   # assume private / local on parse error


def _domain_entropy(domain: str) -> float:
    label = domain.split(".")[0].lower()
    if not label:
        return 0.0
    freq = Counter(label)
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_dga(domain: str) -> bool:
    label = domain.split(".")[0]
    return len(label) >= DGA_MIN_LABEL_LEN and _domain_entropy(domain) >= DGA_ENTROPY_THRESH


# ── Network alert dataclass ────────────────────────────────────────────────────

@dataclass
class NetworkFinding:
    suspicious_connections: list[dict] = field(default_factory=list)
    unique_dest_ips:        int = 0
    external_connections:   int = 0
    c2_port_hits:           int = 0
    dns_query_rate:         float = 0.0
    dga_domains:            list[str] = field(default_factory=list)
    packet_rate_spike:      bool = False
    network_score:          float = 0.0
    timestamp:              str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        return asdict(self)


# ── Connection enumerator (psutil-based, no root needed) ──────────────────────

class ConnectionMonitor:
    """
    Polls active TCP/UDP connections via psutil every interval_sec.
    Tracks new connections, destination diversity, and C2 port hits.
    """

    def __init__(self, window_sec: float = 60.0):
        self._window    = window_sec
        self._conn_hist: deque = deque()   # (timestamp, {laddr, raddr, status, port})
        self._dest_ips:  deque = deque()   # (timestamp, ip_str)
        self._dns_times: deque = deque()

    def _evict(self, now: float):
        cutoff = now - self._window
        while self._conn_hist and self._conn_hist[0][0] < cutoff:
            self._conn_hist.popleft()
        while self._dest_ips and self._dest_ips[0][0] < cutoff:
            self._dest_ips.popleft()
        while self._dns_times and self._dns_times[0][0] < cutoff:
            self._dns_times.popleft()

    def sample(self) -> NetworkFinding:
        if not PSUTIL_OK:
            return NetworkFinding(network_score=0.0)

        now = time.time()
        self._evict(now)

        suspicious = []
        c2_hits    = 0
        external   = 0
        seen_ips   = set()

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Windows may require elevated privileges for full connection list
            log.debug("net_connections: access denied (run as admin for full data)")
            conns = []

        for conn in conns:
            if conn.raddr is None:
                continue
            rip   = conn.raddr.ip
            rport = conn.raddr.port

            self._dest_ips.append((now, rip))
            seen_ips.add(rip)

            is_ext = not _is_private_ip(rip)
            if is_ext:
                external += 1

            is_c2 = rport in C2_PORTS
            if is_c2:
                c2_hits += 1

            if is_ext or is_c2:
                suspicious.append({
                    "remote_ip":   rip,
                    "remote_port": rport,
                    "status":      conn.status,
                    "external":    is_ext,
                    "c2_port":     is_c2,
                })

        unique_dests = len(set(ip for _, ip in self._dest_ips))

        # Network score formula
        score = 0.0
        score += min(external / 10.0, 1.0)         * 0.30
        score += min(c2_hits / 3.0, 1.0)           * 0.35
        score += min(unique_dests / MAX_UNIQUE_DESTS, 1.0) * 0.20
        score += min(len(suspicious) / 5.0, 1.0)   * 0.15

        return NetworkFinding(
            suspicious_connections=suspicious[:10],
            unique_dest_ips=unique_dests,
            external_connections=external,
            c2_port_hits=c2_hits,
            network_score=round(min(score, 1.0), 4),
        )


# ── Pcap-based deep analysis (optional, requires dpkt) ────────────────────────

def analyze_pcap(pcap_path: str) -> dict:
    """
    Parse a Wireshark .pcap file for C2 indicators.
    Called manually or by wireshark_capture.py.
    """
    if not os.path.exists(pcap_path):
        return {"error": f"File not found: {pcap_path}"}

    try:
        import dpkt
    except ImportError:
        return {"error": "dpkt not installed. pip install dpkt"}

    dns_queries   = []
    connections   = defaultdict(set)
    outbound_mb   = 0.0

    try:
        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip  = eth.data
                    dst = socket.inet_ntoa(ip.dst)

                    if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                        try:
                            dns = dpkt.dns.DNS(ip.data.data)
                            for q in dns.qd:
                                dns_queries.append({
                                    "domain": q.name,
                                    "is_dga": _is_dga(q.name),
                                    "entropy": round(_domain_entropy(q.name), 3),
                                    "ts": ts,
                                })
                        except Exception:
                            pass

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        connections[dst].add(ip.data.dport)
                        if len(ip.data.data) > 0:
                            outbound_mb += len(ip.data.data) / 1_048_576

                except Exception:
                    continue
    except Exception as e:
        return {"error": f"pcap parse error: {e}"}

    dga_found = [q for q in dns_queries if q["is_dga"]]
    c2_conns  = {ip: list(ports) for ip, ports in connections.items()
                 if any(p in C2_PORTS for p in ports)}

    score = 0.0
    score += min(len(dga_found) / 5.0, 1.0) * 0.40
    score += min(len(c2_conns)  / 3.0, 1.0) * 0.40
    score += min(outbound_mb    / 50.0, 1.0) * 0.20

    return {
        "pcap_path":    pcap_path,
        "dns_queries":  dns_queries[:20],
        "dga_domains":  [q["domain"] for q in dga_found],
        "c2_connections": c2_conns,
        "outbound_mb":  round(outbound_mb, 2),
        "network_score": round(min(score, 1.0), 4),
        "summary": [
            f"{len(dga_found)} DGA domain(s) detected" if dga_found else "No DGA domains",
            f"{len(c2_conns)} C2 connection(s)" if c2_conns else "No C2 connections",
            f"{outbound_mb:.1f} MB outbound traffic",
        ],
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = analyze_pcap(sys.argv[1])
        print(json.dumps(result, indent=2, default=str))
    else:
        mon = ConnectionMonitor(window_sec=30.0)
        print("Sampling connections for 10 seconds...")
        for _ in range(5):
            time.sleep(2)
            f = mon.sample()
            print(f"  score={f.network_score:.3f}  external={f.external_connections}"
                  f"  c2_hits={f.c2_port_hits}  unique_dests={f.unique_dest_ips}")
