#!/usr/bin/env python3
"""
NTLM Relay Detection via Event Correlation Script
Parses Windows Security event logs to detect NTLM relay attacks through
IP-hostname mismatch analysis, NTLMv1 downgrade detection, rapid multi-host
authentication patterns, and machine account relay indicators.

MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)

Usage:
    python detect_ntlm_relay.py --evtx <security.evtx>
    python detect_ntlm_relay.py --evtx <security.evtx> --inventory hosts.csv
    python detect_ntlm_relay.py --evtx <security.evtx> --json --output results.json

Requirements:
    pip install python-evtx lxml
"""

import argparse
import csv
import json
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import Evtx.Evtx as evtx
    from lxml import etree
except ImportError:
    print("[!] Required packages not found. Install with: pip install python-evtx lxml")
    sys.exit(1)


EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Default time window for rapid authentication detection (seconds)
RAPID_AUTH_WINDOW = 120
# Minimum number of unique targets to flag rapid authentication
RAPID_AUTH_THRESHOLD = 3


def parse_security_event(record_xml):
    """Parse a Windows Security event record XML into a dictionary."""
    try:
        root = etree.fromstring(record_xml)
    except etree.XMLSyntaxError:
        return None

    ns = {"e": EVENT_NS}
    event = {}

    system = root.find(".//e:System", ns)
    if system is not None:
        event_id_elem = system.find("e:EventID", ns)
        event["EventID"] = int(event_id_elem.text) if event_id_elem is not None else 0
        time_elem = system.find("e:TimeCreated", ns)
        if time_elem is not None:
            event["TimeCreated"] = time_elem.get("SystemTime", "")
        computer_elem = system.find("e:Computer", ns)
        event["Computer"] = computer_elem.text if computer_elem is not None else ""

    event_data = root.find(".//e:EventData", ns)
    if event_data is not None:
        for data in event_data.findall("e:Data", ns):
            name = data.get("Name", "")
            value = data.text or ""
            event[name] = value

    return event


def load_host_inventory(csv_path):
    """
    Load hostname-to-IP mapping from CSV file.
    Expected columns: hostname,ip_address
    """
    inventory = {}
    try:
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                hostname = row.get("hostname", "").strip().upper()
                ip = row.get("ip_address", "").strip()
                if hostname and ip:
                    inventory[hostname] = ip
    except Exception as e:
        print(f"[!] Error loading inventory from {csv_path}: {e}")
    return inventory


def is_internal_ip(ip):
    """Check if an IP address is in RFC1918 private ranges."""
    if not ip or ip in ("-", "::1", "127.0.0.1"):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
    except ValueError:
        return False
    return False


def detect_ip_hostname_mismatch(events, inventory):
    """
    Detect NTLM relay by finding Event 4624 LogonType 3 entries where
    the WorkstationName does not match the expected IP for that hostname.
    """
    findings = []

    for event in events:
        if event.get("EventID") != 4624:
            continue
        if event.get("LogonType") != "3":
            continue
        if event.get("AuthenticationPackageName") != "NTLM":
            continue

        target_user = event.get("TargetUserName", "")
        workstation = event.get("WorkstationName", "").strip().upper()
        source_ip = event.get("IpAddress", "")
        computer = event.get("Computer", "")
        timestamp = event.get("TimeCreated", "")
        lm_package = event.get("LmPackageName", "")

        # Skip machine accounts and anonymous logons
        if target_user.endswith("$") or target_user in ("ANONYMOUS LOGON", "-", ""):
            continue
        if source_ip in ("-", "::1", "127.0.0.1", ""):
            continue

        # Check against inventory
        if workstation in inventory:
            expected_ip = inventory[workstation]
            if source_ip != expected_ip:
                findings.append({
                    "timestamp": timestamp,
                    "detection_type": "IP-Hostname Mismatch (NTLM Relay Indicator)",
                    "severity": "CRITICAL",
                    "mitre": "T1557.001",
                    "target_host": computer,
                    "target_user": target_user,
                    "workstation_name": workstation,
                    "actual_source_ip": source_ip,
                    "expected_source_ip": expected_ip,
                    "lm_package": lm_package,
                    "explanation": (
                        f"Event 4624 shows {target_user} authenticating from "
                        f"workstation '{workstation}' but source IP is {source_ip} "
                        f"(expected {expected_ip}). This IP mismatch is a primary "
                        f"indicator of NTLM relay."
                    ),
                })

    return findings


def detect_rapid_multi_host_auth(events, window_seconds=RAPID_AUTH_WINDOW,
                                  threshold=RAPID_AUTH_THRESHOLD):
    """
    Detect rapid NTLM authentication to multiple targets from the same source,
    indicating relay spraying or credential relay.
    """
    findings = []

    # Group events by source IP and user
    auth_by_source = defaultdict(list)

    for event in events:
        if event.get("EventID") != 4624:
            continue
        if event.get("LogonType") != "3":
            continue
        if event.get("AuthenticationPackageName") != "NTLM":
            continue

        target_user = event.get("TargetUserName", "")
        source_ip = event.get("IpAddress", "")

        if target_user.endswith("$") or target_user in ("ANONYMOUS LOGON", "-", ""):
            continue
        if source_ip in ("-", "::1", "127.0.0.1", ""):
            continue

        try:
            ts = datetime.fromisoformat(event["TimeCreated"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            continue

        key = (source_ip, target_user)
        auth_by_source[key].append({
            "timestamp": ts,
            "target_host": event.get("Computer", ""),
            "workstation": event.get("WorkstationName", ""),
        })

    # Analyze each source for rapid multi-host authentication
    for (source_ip, target_user), auth_list in auth_by_source.items():
        auth_list.sort(key=lambda x: x["timestamp"])

        # Sliding window analysis
        for i in range(len(auth_list)):
            window_start = auth_list[i]["timestamp"]
            window_end = window_start + timedelta(seconds=window_seconds)

            targets_in_window = set()
            events_in_window = []

            for j in range(i, len(auth_list)):
                if auth_list[j]["timestamp"] <= window_end:
                    targets_in_window.add(auth_list[j]["target_host"])
                    events_in_window.append(auth_list[j])
                else:
                    break

            if len(targets_in_window) >= threshold:
                findings.append({
                    "timestamp": window_start.isoformat(),
                    "detection_type": "Rapid Multi-Host NTLM Authentication (Relay Spraying)",
                    "severity": "HIGH",
                    "mitre": "T1557.001",
                    "source_ip": source_ip,
                    "target_user": target_user,
                    "unique_targets": len(targets_in_window),
                    "target_hosts": sorted(targets_in_window),
                    "event_count": len(events_in_window),
                    "window_seconds": window_seconds,
                    "explanation": (
                        f"User '{target_user}' authenticated via NTLM from {source_ip} "
                        f"to {len(targets_in_window)} unique targets in {window_seconds}s. "
                        f"Rapid multi-host authentication is consistent with ntlmrelayx spraying."
                    ),
                })
                break  # One finding per source/user pair

    return findings


def detect_ntlmv1_downgrade(events):
    """
    Detect NTLMv1 authentication which indicates a downgrade attack.
    NTLMv1 is weaker and should not be in use in modern environments.
    """
    findings = []
    ntlmv1_by_user = defaultdict(list)

    for event in events:
        if event.get("EventID") != 4624:
            continue
        if event.get("LogonType") != "3":
            continue

        lm_package = event.get("LmPackageName", "")
        if "NTLM V1" not in lm_package:
            continue

        target_user = event.get("TargetUserName", "")
        if target_user.endswith("$") or target_user in ("ANONYMOUS LOGON", "-", ""):
            continue

        ntlmv1_by_user[target_user].append({
            "timestamp": event.get("TimeCreated", ""),
            "computer": event.get("Computer", ""),
            "source_ip": event.get("IpAddress", ""),
            "workstation": event.get("WorkstationName", ""),
        })

    for user, auth_list in ntlmv1_by_user.items():
        targets = set(a["computer"] for a in auth_list)
        source_ips = set(a["source_ip"] for a in auth_list)
        findings.append({
            "timestamp": auth_list[0]["timestamp"],
            "detection_type": "NTLMv1 Authentication Detected (Downgrade Attack Indicator)",
            "severity": "HIGH",
            "mitre": "T1557.001",
            "target_user": user,
            "ntlmv1_event_count": len(auth_list),
            "source_ips": sorted(source_ips),
            "target_hosts": sorted(targets),
            "explanation": (
                f"User '{user}' authenticated {len(auth_list)} times using NTLMv1. "
                f"NTLMv1 is deprecated and should not be in use. This may indicate "
                f"a downgrade attack or misconfigured LmCompatibilityLevel."
            ),
        })

    return findings


def detect_machine_account_relay(events):
    """
    Detect machine account NTLM authentication from unexpected IPs,
    indicating PetitPotam, DFSCoerce, or PrinterBug coercion + relay.
    """
    findings = []
    machine_auths = defaultdict(list)

    for event in events:
        if event.get("EventID") != 4624:
            continue
        if event.get("LogonType") != "3":
            continue
        if event.get("AuthenticationPackageName") != "NTLM":
            continue

        target_user = event.get("TargetUserName", "")
        source_ip = event.get("IpAddress", "")

        # Only machine accounts (ending in $)
        if not target_user.endswith("$"):
            continue
        if source_ip in ("-", "::1", "127.0.0.1", ""):
            continue

        machine_auths[target_user].append({
            "timestamp": event.get("TimeCreated", ""),
            "target_host": event.get("Computer", ""),
            "source_ip": source_ip,
            "workstation": event.get("WorkstationName", ""),
            "lm_package": event.get("LmPackageName", ""),
        })

    for machine_account, auth_list in machine_auths.items():
        source_ips = set(a["source_ip"] for a in auth_list)
        target_hosts = set(a["target_host"] for a in auth_list)

        # Flag if machine account authenticates from multiple source IPs
        # or if source IP does not match expected machine IP
        if len(source_ips) > 1:
            findings.append({
                "timestamp": auth_list[0]["timestamp"],
                "detection_type": "Machine Account NTLM Auth from Multiple Sources (Coercion + Relay)",
                "severity": "CRITICAL",
                "mitre": "T1557.001",
                "machine_account": machine_account,
                "source_ips": sorted(source_ips),
                "target_hosts": sorted(target_hosts),
                "auth_count": len(auth_list),
                "explanation": (
                    f"Machine account '{machine_account}' authenticated via NTLM from "
                    f"{len(source_ips)} different source IPs: {', '.join(sorted(source_ips))}. "
                    f"This indicates the machine's NTLM authentication was coerced "
                    f"(PetitPotam/DFSCoerce/PrinterBug) and relayed to "
                    f"{', '.join(sorted(target_hosts))}."
                ),
            })

    return findings


def detect_anonymous_ntlm_logons(events):
    """
    Detect ANONYMOUS LOGON via NTLM which can indicate null session relay
    or Responder activity.
    """
    findings = []
    anon_by_ip = defaultdict(list)

    for event in events:
        if event.get("EventID") != 4624:
            continue
        if event.get("LogonType") != "3":
            continue
        if event.get("AuthenticationPackageName") != "NTLM":
            continue

        target_user = event.get("TargetUserName", "")
        if target_user != "ANONYMOUS LOGON":
            continue

        source_ip = event.get("IpAddress", "")
        if source_ip in ("-", "::1", "127.0.0.1", ""):
            continue

        anon_by_ip[source_ip].append({
            "timestamp": event.get("TimeCreated", ""),
            "target_host": event.get("Computer", ""),
        })

    for source_ip, auth_list in anon_by_ip.items():
        targets = set(a["target_host"] for a in auth_list)
        if len(auth_list) >= 3:
            findings.append({
                "timestamp": auth_list[0]["timestamp"],
                "detection_type": "Excessive ANONYMOUS NTLM Logons (Responder/Relay Probe)",
                "severity": "MEDIUM",
                "mitre": "T1557.001",
                "source_ip": source_ip,
                "anonymous_logon_count": len(auth_list),
                "target_hosts": sorted(targets),
                "explanation": (
                    f"Source IP {source_ip} performed {len(auth_list)} anonymous NTLM "
                    f"logons to {len(targets)} hosts. Excessive anonymous NTLM "
                    f"authentication may indicate Responder probing or null session relay."
                ),
            })

    return findings


def parse_evtx_file(filepath):
    """Parse a .evtx file and return list of parsed events."""
    events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    event = parse_security_event(record.xml())
                    if event and event.get("EventID") in (4624, 4625, 4648, 4776):
                        events.append(event)
                except Exception:
                    continue
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}")
    return events


def print_findings(findings, title):
    """Print findings in a formatted table."""
    if not findings:
        print(f"\n[+] {title}: No findings")
        return

    print(f"\n{'=' * 80}")
    print(f"  {title} ({len(findings)} findings)")
    print(f"{'=' * 80}")

    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "N/A")
        severity_marker = {
            "CRITICAL": "[!!!]",
            "HIGH": "[!!]",
            "MEDIUM": "[!]",
            "LOW": "[.]",
        }.get(severity, "[?]")

        print(f"\n  {severity_marker} [{i}] {finding.get('detection_type', 'Unknown')}")
        print(f"      Severity: {severity}")
        print(f"      Time: {finding.get('timestamp', 'N/A')}")

        if "target_user" in finding:
            print(f"      User: {finding['target_user']}")
        if "machine_account" in finding:
            print(f"      Machine: {finding['machine_account']}")
        if "source_ip" in finding:
            print(f"      Source IP: {finding['source_ip']}")
        if "actual_source_ip" in finding:
            print(f"      Actual Source IP: {finding['actual_source_ip']}")
            print(f"      Expected Source IP: {finding.get('expected_source_ip', 'N/A')}")
        if "workstation_name" in finding:
            print(f"      Workstation: {finding['workstation_name']}")
        if "target_hosts" in finding:
            hosts = finding["target_hosts"]
            if len(hosts) <= 5:
                print(f"      Targets: {', '.join(hosts)}")
            else:
                print(f"      Targets: {', '.join(hosts[:5])} ... (+{len(hosts)-5} more)")
        if "source_ips" in finding:
            print(f"      Source IPs: {', '.join(finding['source_ips'])}")

        print(f"      Detail: {finding.get('explanation', 'N/A')}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect NTLM relay attacks via Windows Security event log correlation"
    )
    parser.add_argument(
        "--evtx", required=True,
        help="Path to Windows Security .evtx log file"
    )
    parser.add_argument(
        "--inventory",
        help="Path to CSV file with hostname,ip_address columns for mismatch detection"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--rapid-window", type=int, default=RAPID_AUTH_WINDOW,
        help=f"Time window for rapid auth detection in seconds (default: {RAPID_AUTH_WINDOW})"
    )
    parser.add_argument(
        "--rapid-threshold", type=int, default=RAPID_AUTH_THRESHOLD,
        help=f"Min unique targets for rapid auth alert (default: {RAPID_AUTH_THRESHOLD})"
    )
    args = parser.parse_args()

    if not os.path.exists(args.evtx):
        print(f"[!] File not found: {args.evtx}")
        sys.exit(1)

    # Load host inventory if provided
    inventory = {}
    if args.inventory:
        if os.path.exists(args.inventory):
            inventory = load_host_inventory(args.inventory)
            print(f"[*] Loaded {len(inventory)} hosts from inventory")
        else:
            print(f"[!] Inventory file not found: {args.inventory}")

    print(f"[*] Parsing Security events from: {args.evtx}")
    events = parse_evtx_file(args.evtx)
    print(f"[*] Parsed {len(events)} relevant Security events (4624, 4625, 4648, 4776)")

    ntlm_4624 = [e for e in events if e.get("EventID") == 4624
                  and e.get("AuthenticationPackageName") == "NTLM"]
    print(f"[*] Found {len(ntlm_4624)} NTLM LogonType 3 events for analysis")

    print("[*] Running NTLM relay detection modules...")

    # Run all detection modules
    mismatch_findings = detect_ip_hostname_mismatch(events, inventory) if inventory else []
    rapid_auth_findings = detect_rapid_multi_host_auth(
        events, args.rapid_window, args.rapid_threshold
    )
    ntlmv1_findings = detect_ntlmv1_downgrade(events)
    machine_relay_findings = detect_machine_account_relay(events)
    anon_findings = detect_anonymous_ntlm_logons(events)

    all_findings = (
        mismatch_findings + rapid_auth_findings + ntlmv1_findings
        + machine_relay_findings + anon_findings
    )

    all_results = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "security_log": args.evtx,
        "inventory_file": args.inventory or "Not provided",
        "inventory_hosts": len(inventory),
        "total_events_parsed": len(events),
        "ntlm_logon_events": len(ntlm_4624),
        "detection_modules": {
            "ip_hostname_mismatch": {
                "enabled": bool(inventory),
                "findings": mismatch_findings,
                "count": len(mismatch_findings),
            },
            "rapid_multi_host_auth": {
                "enabled": True,
                "findings": rapid_auth_findings,
                "count": len(rapid_auth_findings),
                "window_seconds": args.rapid_window,
                "threshold": args.rapid_threshold,
            },
            "ntlmv1_downgrade": {
                "enabled": True,
                "findings": ntlmv1_findings,
                "count": len(ntlmv1_findings),
            },
            "machine_account_relay": {
                "enabled": True,
                "findings": machine_relay_findings,
                "count": len(machine_relay_findings),
            },
            "anonymous_ntlm_logons": {
                "enabled": True,
                "findings": anon_findings,
                "count": len(anon_findings),
            },
        },
        "summary": {
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
            "low": len([f for f in all_findings if f.get("severity") == "LOW"]),
        },
    }

    if args.json:
        output = json.dumps(all_results, indent=2, default=str)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"[*] JSON results written to: {args.output}")
        else:
            print(output)
    else:
        print("\n[*] NTLM Relay Detection Report")
        print(f"[*] Scan Time: {all_results['scan_time']}")
        print(f"[*] Events Analyzed: {all_results['total_events_parsed']}")
        print(f"[*] NTLM Network Logons: {all_results['ntlm_logon_events']}")

        if not inventory:
            print("\n[!] WARNING: No host inventory provided (--inventory).")
            print("    IP-hostname mismatch detection is DISABLED.")
            print("    Provide a CSV with hostname,ip_address columns for full detection.")

        print_findings(mismatch_findings, "IP-Hostname Mismatch Detection")
        print_findings(rapid_auth_findings, "Rapid Multi-Host Authentication")
        print_findings(ntlmv1_findings, "NTLMv1 Downgrade Detection")
        print_findings(machine_relay_findings, "Machine Account Relay (Coercion)")
        print_findings(anon_findings, "Anonymous NTLM Logon Analysis")

        print(f"\n{'=' * 80}")
        print("  SUMMARY")
        print(f"{'=' * 80}")
        s = all_results["summary"]
        print(f"  Total Findings:  {s['total_findings']}")
        print(f"  Critical:        {s['critical']}")
        print(f"  High:            {s['high']}")
        print(f"  Medium:          {s['medium']}")
        print(f"  Low:             {s['low']}")

        if s["critical"] > 0:
            print("\n  [!!!] CRITICAL findings detected -- NTLM relay attack likely in progress!")
            print("        Recommended: Isolate source IPs, reset affected credentials,")
            print("        enforce SMB/LDAP signing, disable LLMNR/NBT-NS.")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(all_results, f, indent=2, default=str)
            print(f"\n[*] Full results written to: {args.output}")


if __name__ == "__main__":
    main()
