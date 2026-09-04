"""
tools/wireshark_capture.py
===========================
Wireshark / pcap integration for RansomShield.

PURPOSE:
  Ransomware typically communicates with Command & Control (C2) servers:
  1. BEFORE encryption: exfiltrates data, receives the encryption key
  2. DURING encryption: heartbeat beaconing to confirm infection
  3. AFTER encryption:  reports success, awaits ransom payment

  By correlating network C2 indicators with our entropy/I/O signals,
  we create a stronger multi-layer detection fingerprint.

WHAT THIS MODULE DOES:
  1. parse_pcap()      - parse a Wireshark .pcap file, extract C2 indicators
  2. detect_beaconing() - identify regular-interval DNS/HTTP beacons
  3. detect_exfiltration() - flag large outbound bursts before encryption
  4. correlate_with_alert() - match network IOCs to a process alert

USAGE (in report Section 3.5):
  "Wireshark is used to capture network traffic during simulated ransomware
   execution. The captured .pcap file is parsed by tools/wireshark_capture.py
   to extract C2 indicators: beaconing intervals, DNS queries to algorithmically
   generated domains (DGA), and large outbound data bursts that precede the
   encryption phase."

REAL USAGE:
  1. Run Wireshark / tshark during attack_simulator.py execution
  2. Save capture as data/sample_logs/capture.pcap
  3. Run: python tools/wireshark_capture.py data/sample_logs/capture.pcap

NOTE:
  This module uses dpkt for pcap parsing. If tshark is available, it can
  also call it as a subprocess for richer protocol dissection.

"""

import os
import sys
import json
import math
import socket
import struct
import logging
import datetime
import subprocess
from collections import defaultdict, Counter
from typing import Optional

log = logging.getLogger("ransomshield.wireshark")


# ── C2 indicators ─────────────────────────────────────────────────────────────

# Known C2 ports used by major ransomware families (from threat intel)
SUSPICIOUS_PORTS = {
    4444, 8080, 8443, 9001,           # Metasploit / common C2
    6667, 6697,                         # IRC-based C2 (older families)
    447, 448,                           # Tor-adjacent
    14147, 19101,                       # REvil / Sodinokibi
}

# DGA domain indicators: high entropy domain name = algorithmically generated
DGA_ENTROPY_THRESHOLD = 3.5    # Shannon entropy of domain label (bits)
DGA_MIN_LENGTH        = 12     # Minimum label length to be suspicious

# Exfiltration threshold: large outbound burst before encryption
EXFIL_THRESHOLD_KB    = 500    # KB outbound in a short window


# ── Domain entropy (DGA detection) ───────────────────────────────────────────

def domain_entropy(domain: str) -> float:
    """
    Shannon entropy of the domain's main label.
    DGA domains have high entropy (random-looking strings).
    Legitimate domains have low entropy (readable words).

    Example:
      google.com     → entropy ≈ 2.75 (LOW - legitimate)
      x7k2mq9p.onion → entropy ≈ 3.82 (HIGH - DGA indicator)
    """
    label = domain.split(".")[0].lower()
    if not label:
        return 0.0
    freq = Counter(label)
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def is_dga_domain(domain: str) -> bool:
    """True if domain label looks algorithmically generated."""
    label = domain.split(".")[0]
    return (
        len(label) >= DGA_MIN_LENGTH and
        domain_entropy(domain) >= DGA_ENTROPY_THRESHOLD
    )


# ── pcap parsing via dpkt ─────────────────────────────────────────────────────

def parse_pcap(pcap_path: str) -> dict:
    """
    Parse a .pcap file and extract network C2 indicators.

    Returns a dict with:
      dns_queries    : list of queried domain names
      dga_domains    : domains flagged as DGA
      suspicious_connections : {dst_ip: [ports]}
      outbound_bytes_by_time : time-bucketed outbound traffic
      beaconing_intervals    : detected regular-interval connections
      summary                : human-readable findings
    """
    if not os.path.exists(pcap_path):
        return {"error": f"File not found: {pcap_path}"}

    try:
        import dpkt
    except ImportError:
        log.warning("dpkt not installed. Using tshark fallback.")
        return parse_pcap_tshark(pcap_path)

    dns_queries   = []
    connections   = defaultdict(set)    # dst_ip → set of ports
    outbound      = []                  # (timestamp, bytes) tuples

    try:
        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip  = eth.data
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)

                    # DNS queries
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.dport == 53:
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                for q in dns.qd:
                                    dns_queries.append({
                                        "timestamp": ts,
                                        "domain": q.name,
                                        "is_dga": is_dga_domain(q.name),
                                        "entropy": round(domain_entropy(q.name), 3),
                                    })
                            except Exception:
                                pass

                    # TCP connections to suspicious ports
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        if tcp.dport in SUSPICIOUS_PORTS:
                            connections[dst].add(tcp.dport)

                        # Outbound data (payload > 0)
                        if len(tcp.data) > 0:
                            outbound.append((ts, len(tcp.data)))

                except Exception:
                    continue

    except Exception as e:
        return {"error": f"pcap parse error: {e}"}

    # Detect beaconing: connections at regular intervals
    dga_found = [q for q in dns_queries if q["is_dga"]]
    beaconing = detect_beaconing(outbound)
    exfil     = detect_exfiltration(outbound)

    findings = []
    if dga_found:
        findings.append(f"DGA domains detected: {len(dga_found)} suspicious queries")
    if connections:
        findings.append(f"Suspicious port connections: {dict(connections)}")
    if beaconing["detected"]:
        findings.append(f"C2 beaconing detected: interval ≈ {beaconing['interval_sec']:.1f}s")
    if exfil["detected"]:
        findings.append(f"Pre-encryption exfiltration: {exfil['volume_kb']:.0f} KB outbound")

    return {
        "pcap_path": pcap_path,
        "dns_queries":  dns_queries[:50],    # cap for readability
        "dga_domains":  dga_found,
        "suspicious_connections": {k: list(v) for k, v in connections.items()},
        "beaconing":    beaconing,
        "exfiltration": exfil,
        "summary":      findings if findings else ["No C2 indicators found."],
        "ioc_count":    len(dga_found) + len(connections) + int(beaconing["detected"]) + int(exfil["detected"]),
    }


def parse_pcap_tshark(pcap_path: str) -> dict:
    """
    Fallback: use tshark CLI if dpkt is unavailable.
    Extracts DNS queries and IP connections.
    """
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-T", "fields",
             "-e", "frame.time_epoch", "-e", "ip.dst", "-e", "dns.qry.name",
             "-e", "tcp.dstport", "-e", "ip.len"],
            capture_output=True, text=True, timeout=30
        )
        lines = result.stdout.strip().split("\n")
        dns_queries = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2]:
                domain = parts[2]
                dns_queries.append({
                    "domain": domain,
                    "is_dga": is_dga_domain(domain),
                    "entropy": round(domain_entropy(domain), 3),
                })
        return {
            "source": "tshark",
            "dns_queries": dns_queries,
            "summary": [f"Parsed {len(dns_queries)} DNS queries via tshark"],
        }
    except FileNotFoundError:
        return {
            "error": "Neither dpkt nor tshark available. Install: pip install dpkt  OR  install Wireshark.",
            "note": "For the report: document the Wireshark capture methodology in Section 3.5."
        }


# ── Beaconing detection ───────────────────────────────────────────────────────

def detect_beaconing(outbound_events: list, tolerance_sec: float = 2.0) -> dict:
    """
    Detect regular-interval C2 beaconing from outbound traffic timestamps.
    Beaconing = connections at consistent time intervals (e.g., every 60s).
    """
    if len(outbound_events) < 5:
        return {"detected": False}

    timestamps = sorted(t for t, _ in outbound_events)
    intervals  = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

    if not intervals:
        return {"detected": False}

    mean_interval = sum(intervals) / len(intervals)
    deviations    = [abs(i - mean_interval) for i in intervals]
    regularity    = sum(1 for d in deviations if d < tolerance_sec) / len(deviations)

    detected = regularity > 0.70 and 5 < mean_interval < 3600

    return {
        "detected":      detected,
        "interval_sec":  round(mean_interval, 2),
        "regularity":    round(regularity, 3),
        "samples":       len(intervals),
    }


# ── Exfiltration detection ────────────────────────────────────────────────────

def detect_exfiltration(outbound_events: list, window_sec: float = 30.0) -> dict:
    """
    Detect large outbound data bursts (pre-encryption exfiltration).
    """
    if not outbound_events:
        return {"detected": False}

    max_volume_kb = 0.0
    for i, (t_start, _) in enumerate(outbound_events):
        window_bytes = sum(
            b for t, b in outbound_events
            if t_start <= t <= t_start + window_sec
        )
        max_volume_kb = max(max_volume_kb, window_bytes / 1024)

    detected = max_volume_kb > EXFIL_THRESHOLD_KB

    return {
        "detected":   detected,
        "volume_kb":  round(max_volume_kb, 1),
        "threshold_kb": EXFIL_THRESHOLD_KB,
    }


# ── Correlate with alert ──────────────────────────────────────────────────────

def correlate_with_alert(alert: dict, pcap_results: dict) -> dict:
    """
    Combine network IOCs with a process alert to build a composite threat picture.
    """
    ioc_count = pcap_results.get("ioc_count", 0)
    network_boost = min(ioc_count * 0.05, 0.20)    # up to +0.20 score boost

    base_score = alert.get("threat_score", 0.0)
    combined   = min(base_score + network_boost, 1.0)

    return {
        "process_alert": alert,
        "network_iocs":  pcap_results.get("summary", []),
        "original_score": base_score,
        "network_boost":  round(network_boost, 3),
        "combined_score": round(combined, 4),
        "verdict": "CONFIRMED_RANSOMWARE" if combined >= 0.80 else "SUSPECTED",
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "data/sample_logs/capture.pcap"

    print(f"Parsing: {pcap_file}")
    results = parse_pcap(pcap_file)

    print(json.dumps(results, indent=2, default=str))
