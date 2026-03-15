#!/usr/bin/env python3
"""Agent for performing OT vulnerability scanning safely — passive and rate-limited approaches."""

import json
import argparse
import subprocess
import socket
import time
from datetime import datetime


OT_SAFE_PORTS = {
    502: {"protocol": "Modbus", "risk": "LOW", "safe_scan": True},
    102: {"protocol": "S7Comm", "risk": "MEDIUM", "safe_scan": True},
    4840: {"protocol": "OPC-UA", "risk": "LOW", "safe_scan": True},
    44818: {"protocol": "EtherNet/IP", "risk": "MEDIUM", "safe_scan": True},
    47808: {"protocol": "BACnet", "risk": "LOW", "safe_scan": True},
    20000: {"protocol": "DNP3", "risk": "HIGH", "safe_scan": False},
    2404: {"protocol": "IEC 60870-5-104", "risk": "HIGH", "safe_scan": False},
}


def passive_discovery(interface="eth0", duration=60):
    """Perform passive network discovery without sending packets."""
    cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}",
           "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "eth.src", "-e", "frame.protocols", "-Y", "ip"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
        hosts = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                src, dst, port = parts[0], parts[1], parts[2]
                for ip in (src, dst):
                    if ip and ip not in hosts:
                        hosts[ip] = {"ports": set(), "protocols": set(), "mac": ""}
                    if ip == dst and port:
                        hosts[ip]["ports"].add(port)
                if len(parts) > 3 and parts[3]:
                    hosts.get(src, {}).setdefault("mac", parts[3])
                if len(parts) > 4:
                    hosts.get(dst, {}).setdefault("protocols", set()).add(parts[4])
        return {
            "method": "passive", "interface": interface, "duration_sec": duration,
            "hosts_discovered": len(hosts),
            "hosts": [{
                "ip": ip, "ports": sorted(list(d.get("ports", set())))[:20],
                "mac": d.get("mac", ""),
            } for ip, d in list(hosts.items())[:50]],
        }
    except FileNotFoundError:
        return {"error": "tshark not found — install Wireshark"}
    except Exception as e:
        return {"error": str(e)}


def safe_tcp_scan(target, ports=None, rate_limit=0.5):
    """Perform rate-limited TCP SYN scan safe for OT environments."""
    if ports is None:
        ports = list(OT_SAFE_PORTS.keys()) + [80, 443, 22, 8080]
    results = []
    for port in ports:
        ot_info = OT_SAFE_PORTS.get(port, {})
        if ot_info.get("safe_scan") is False:
            results.append({"port": port, "protocol": ot_info.get("protocol", ""), "status": "SKIPPED_UNSAFE"})
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((target, port))
            results.append({"port": port, "status": "open", "protocol": ot_info.get("protocol", "")})
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()
        time.sleep(rate_limit)
    return {
        "target": target, "method": "rate_limited_tcp",
        "rate_limit_sec": rate_limit, "ports_scanned": len(ports),
        "open_ports": [r for r in results if r.get("status") == "open"],
        "skipped_unsafe": [r for r in results if r.get("status") == "SKIPPED_UNSAFE"],
        "timestamp": datetime.utcnow().isoformat(),
    }


def nmap_safe_scan(target, timing="T1"):
    """Run nmap with OT-safe settings (low timing, no scripts)."""
    ot_ports = ",".join(str(p) for p in OT_SAFE_PORTS.keys())
    cmd = ["nmap", f"-{timing}", "-sV", "--version-light", "-p", ot_ports,
           "--max-retries", "1", "--host-timeout", "60s",
           "--scan-delay", "500ms", "-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr = host.find("address").get("addr", "") if host.find("address") is not None else ""
            ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                if state is not None and state.get("state") == "open":
                    ports.append({
                        "port": int(port.get("portid", 0)),
                        "service": service.get("name", "") if service is not None else "",
                        "product": service.get("product", "") if service is not None else "",
                    })
            if ports:
                hosts.append({"ip": addr, "services": ports})
        return {"target": target, "timing": timing, "hosts": hosts, "scan_settings": "OT-safe: low timing, version-light, max-retries 1"}
    except FileNotFoundError:
        return {"error": "nmap not found"}
    except Exception as e:
        return {"error": str(e)}


def pre_scan_checklist(target):
    """Generate pre-scan safety checklist for OT environments."""
    return {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "checklist": [
            {"step": 1, "task": "Obtain written authorization from asset owner and OT team", "required": True},
            {"step": 2, "task": "Identify all safety-critical systems (SIS/ESD) — exclude from scanning", "required": True},
            {"step": 3, "task": "Review OT asset inventory for fragile devices (legacy PLCs)", "required": True},
            {"step": 4, "task": "Schedule scan during planned maintenance window", "required": True},
            {"step": 5, "task": "Configure scan with T1/T2 timing — NEVER use T4/T5", "required": True},
            {"step": 6, "task": "Disable aggressive service detection scripts", "required": True},
            {"step": 7, "task": "Set maximum rate limit (500ms+ between probes)", "required": True},
            {"step": 8, "task": "Have OT engineer monitoring process during scan", "required": True},
            {"step": 9, "task": "Prepare rollback/emergency shutdown procedures", "required": True},
            {"step": 10, "task": "Start with passive discovery before active scanning", "required": True},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Safe OT Vulnerability Scanning Agent")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("passive", help="Passive network discovery")
    p.add_argument("--interface", default="eth0")
    p.add_argument("--duration", type=int, default=60)
    t = sub.add_parser("tcp", help="Safe rate-limited TCP scan")
    t.add_argument("--target", required=True)
    t.add_argument("--rate", type=float, default=0.5, help="Seconds between probes")
    n = sub.add_parser("nmap", help="OT-safe nmap scan")
    n.add_argument("--target", required=True)
    n.add_argument("--timing", default="T1", choices=["T0", "T1", "T2"])
    c = sub.add_parser("checklist", help="Pre-scan safety checklist")
    c.add_argument("--target", required=True)
    args = parser.parse_args()
    if args.command == "passive":
        result = passive_discovery(args.interface, args.duration)
    elif args.command == "tcp":
        result = safe_tcp_scan(args.target, rate_limit=args.rate)
    elif args.command == "nmap":
        result = nmap_safe_scan(args.target, args.timing)
    elif args.command == "checklist":
        result = pre_scan_checklist(args.target)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
