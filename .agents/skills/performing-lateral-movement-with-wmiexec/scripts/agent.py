#!/usr/bin/env python3
"""Agent for performing lateral movement detection and simulation with WMIExec — authorized testing only."""

import json
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path


def detect_wmiexec_artifacts_evtx(evtx_file):
    """Detect WMIExec lateral movement artifacts in Windows Event Logs."""
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        return {"error": "python-evtx not installed — pip install python-evtx"}
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    indicators = {
        "wmi_process_creation": [],
        "network_logon": [],
        "service_install": [],
    }
    with evtx.Evtx(evtx_file) as log:
        for record in log.records():
            try:
                xml = record.xml()
                root = ET.fromstring(xml)
                eid_elem = root.find(".//e:EventID", ns)
                if eid_elem is None:
                    continue
                eid = eid_elem.text
                data = {d.get("Name"): d.text for d in root.findall(".//e:Data", ns)}
                if eid == "1":
                    parent = data.get("ParentImage", "").lower()
                    cmdline = data.get("CommandLine", "")
                    if "wmiprvse.exe" in parent:
                        indicators["wmi_process_creation"].append({
                            "image": data.get("Image"), "cmdline": cmdline[:200],
                            "user": data.get("User"), "parent": data.get("ParentImage"),
                        })
                elif eid == "4624":
                    logon_type = data.get("LogonType", "")
                    if logon_type == "3":
                        indicators["network_logon"].append({
                            "user": data.get("TargetUserName"),
                            "source_ip": data.get("IpAddress"),
                            "workstation": data.get("WorkstationName"),
                        })
                elif eid == "7045":
                    svc_name = data.get("ServiceName", "")
                    if re.search(r"(BTOBTO|wmiprvse|wmi_|cmd\.exe)", svc_name, re.I):
                        indicators["service_install"].append({
                            "service": svc_name,
                            "path": data.get("ImagePath", "")[:200],
                        })
            except Exception:
                continue
    total = sum(len(v) for v in indicators.values())
    return {
        "evtx_file": evtx_file, "total_indicators": total,
        "wmi_process_creations": len(indicators["wmi_process_creation"]),
        "network_logons": len(indicators["network_logon"]),
        "service_installs": len(indicators["service_install"]),
        "indicators": {k: v[:15] for k, v in indicators.items()},
        "finding": "WMIEXEC_DETECTED" if total > 0 else "NO_INDICATORS",
    }


def run_wmiexec_impacket(target, domain, username, command="whoami"):
    """Execute command via Impacket wmiexec (authorized pentest use)."""
    cmd = ["python3", "-m", "impacket.examples.wmiexec",
           f"{domain}/{username}@{target}", command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "target": target, "domain": domain, "user": username,
            "command": command, "output": result.stdout[:500],
            "success": result.returncode == 0,
            "stderr": result.stderr[:200] if result.stderr else "",
        }
    except FileNotFoundError:
        return {"error": "Impacket not installed — pip install impacket"}
    except Exception as e:
        return {"error": str(e)}


def detect_wmi_network_traffic(pcap_file):
    """Analyze PCAP for WMI lateral movement network indicators."""
    cmd = ["tshark", "-r", pcap_file, "-Y",
           "dcerpc.cn_bind_uuid == 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57 || tcp.port == 135 || dcom",
           "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
           "-e", "dcerpc.cn_bind_uuid", "-e", "frame.time"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        connections = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                connections.append({"src": parts[0], "dst": parts[1], "port": parts[2],
                                    "uuid": parts[3] if len(parts) > 3 else "", "time": parts[4] if len(parts) > 4 else ""})
        dcom_uuid = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57"
        wmi_traffic = [c for c in connections if c.get("uuid") == dcom_uuid or c.get("port") == "135"]
        return {
            "pcap_file": pcap_file, "total_connections": len(connections),
            "wmi_related": len(wmi_traffic), "connections": wmi_traffic[:20],
        }
    except FileNotFoundError:
        return {"error": "tshark not found — install Wireshark"}
    except Exception as e:
        return {"error": str(e)}


def check_wmi_persistence():
    """Check for WMI-based persistence mechanisms on local system."""
    checks = {
        "event_subscriptions": ["wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "/format:list"],
        "consumers": ["wmic", "/namespace:\\\\root\\subscription", "path", "CommandLineEventConsumer", "get", "/format:list"],
        "bindings": ["wmic", "/namespace:\\\\root\\subscription", "path", "__FilterToConsumerBinding", "get", "/format:list"],
    }
    results = {}
    for name, cmd in checks.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            entries = [line.strip() for line in result.stdout.splitlines() if "=" in line]
            results[name] = {"count": len(entries), "entries": entries[:10]}
        except Exception as e:
            results[name] = {"error": str(e)}
    total = sum(r.get("count", 0) for r in results.values() if isinstance(r.get("count"), int))
    return {"wmi_persistence": results, "total_subscriptions": total,
            "finding": "WMI_PERSISTENCE_FOUND" if total > 0 else "NO_WMI_PERSISTENCE"}


def main():
    parser = argparse.ArgumentParser(description="WMIExec Lateral Movement Agent (Authorized Testing Only)")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("detect", help="Detect WMIExec in EVTX logs")
    d.add_argument("--evtx", required=True)
    e = sub.add_parser("exec", help="Execute via wmiexec (pentest)")
    e.add_argument("--target", required=True)
    e.add_argument("--domain", required=True)
    e.add_argument("--user", required=True)
    e.add_argument("--cmd", default="whoami")
    n = sub.add_parser("network", help="Analyze PCAP for WMI traffic")
    n.add_argument("--pcap", required=True)
    sub.add_parser("persistence", help="Check WMI persistence")
    args = parser.parse_args()
    if args.command == "detect":
        result = detect_wmiexec_artifacts_evtx(args.evtx)
    elif args.command == "exec":
        result = run_wmiexec_impacket(args.target, args.domain, args.user, args.cmd)
    elif args.command == "network":
        result = detect_wmi_network_traffic(args.pcap)
    elif args.command == "persistence":
        result = check_wmi_persistence()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
