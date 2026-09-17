#!/usr/bin/env python3
"""
DCOM Lateral Movement Detection Script
Parses Windows Security and Sysmon event logs to detect DCOM-based lateral movement
via MMC20.Application, ShellWindows, and ShellBrowserWindow COM object abuse.

MITRE ATT&CK: T1021.003 (Remote Services: Distributed Component Object Model)

Usage:
    python detect_dcom_lateral_movement.py --evtx <path_to_sysmon_evtx>
    python detect_dcom_lateral_movement.py --evtx <sysmon.evtx> --security <security.evtx>
    python detect_dcom_lateral_movement.py --evtx <sysmon.evtx> --json --output results.json

Requirements:
    pip install python-evtx lxml
"""

import argparse
import json
import sys
import os
from datetime import datetime

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    from lxml import etree
except ImportError:
    print("[!] Required packages not found. Install with: pip install python-evtx lxml")
    sys.exit(1)


# DCOM-related COM object CLSIDs
DCOM_CLSIDS = {
    "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}": "MMC20.Application",
    "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}": "ShellWindows",
    "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}": "ShellBrowserWindow",
    "{00024500-0000-0000-C000-000000000046}": "Excel.Application",
    "{0006F03A-0000-0000-C000-000000000046}": "Outlook.Application",
}

# Suspicious child processes when spawned by DCOM parent processes
SUSPICIOUS_CHILDREN = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msbuild.exe",
]

# DCOM parent processes that spawn child processes during lateral movement
DCOM_PARENTS = ["mmc.exe", "dllhost.exe", "explorer.exe", "svchost.exe"]

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse_sysmon_event(record_xml):
    """Parse a Sysmon event record XML into a dictionary."""
    try:
        root = etree.fromstring(record_xml)
    except etree.XMLSyntaxError:
        return None

    ns = {"e": SYSMON_NS}
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


def is_dcom_parent(image_path):
    """Check if the process image is a known DCOM parent."""
    if not image_path:
        return False
    image_lower = image_path.lower()
    return any(parent in image_lower for parent in DCOM_PARENTS)


def is_suspicious_child(image_path):
    """Check if the process image is a suspicious child for DCOM context."""
    if not image_path:
        return False
    image_lower = image_path.lower()
    return any(child in image_lower for child in SUSPICIOUS_CHILDREN)


def check_dcomllaunch_parent(command_line):
    """Check if the parent command line indicates DcomLaunch service."""
    if not command_line:
        return False
    return "dcomlaunch" in command_line.lower()


def detect_dcom_process_creation(events):
    """
    Detect DCOM lateral movement via Sysmon Event ID 1 (Process Create).
    Looks for DCOM parent processes spawning suspicious children.
    """
    findings = []

    for event in events:
        if event.get("EventID") != 1:
            continue

        parent_image = event.get("ParentImage", "")
        image = event.get("Image", "")
        parent_cmdline = event.get("ParentCommandLine", "")
        cmdline = event.get("CommandLine", "")
        user = event.get("User", "")
        time_created = event.get("TimeCreated", "")
        computer = event.get("Computer", "")

        # Pattern 1: mmc.exe spawning suspicious child (MMC20.Application)
        if "mmc.exe" in parent_image.lower() and is_suspicious_child(image):
            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "MMC20.Application DCOM Lateral Movement",
                "dcom_object": "MMC20.Application",
                "clsid": "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}",
                "parent_image": parent_image,
                "parent_commandline": parent_cmdline,
                "child_image": image,
                "child_commandline": cmdline,
                "user": user,
                "severity": "HIGH",
                "mitre": "T1021.003",
            })

        # Pattern 2: DcomLaunch svchost spawning dllhost or mmc
        if check_dcomllaunch_parent(parent_cmdline) and is_suspicious_child(image):
            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "DcomLaunch Service Spawning Suspicious Process",
                "dcom_object": "Unknown (DcomLaunch)",
                "clsid": "N/A",
                "parent_image": parent_image,
                "parent_commandline": parent_cmdline,
                "child_image": image,
                "child_commandline": cmdline,
                "user": user,
                "severity": "HIGH",
                "mitre": "T1021.003",
            })

        # Pattern 3: explorer.exe spawning cmd/powershell on servers
        # (ShellWindows/ShellBrowserWindow)
        if "explorer.exe" in parent_image.lower() and is_suspicious_child(image):
            # Check if this might be interactive (less suspicious) or DCOM (more suspicious)
            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "ShellWindows/ShellBrowserWindow DCOM Lateral Movement (Requires Correlation)",
                "dcom_object": "ShellWindows or ShellBrowserWindow",
                "clsid": "{9BA05972-F6A8-11CF-A442-00A0C90A8F39} or {C08AFD90-F2A1-11D1-8455-00A0C91F3880}",
                "parent_image": parent_image,
                "parent_commandline": parent_cmdline,
                "child_image": image,
                "child_commandline": cmdline,
                "user": user,
                "severity": "MEDIUM",
                "mitre": "T1021.003",
            })

        # Pattern 4: dllhost.exe spawning suspicious children
        if "dllhost.exe" in parent_image.lower() and is_suspicious_child(image):
            # Extract CLSID from dllhost command line if present
            detected_clsid = "Unknown"
            if "/Processid:" in parent_cmdline:
                clsid_start = parent_cmdline.find("/Processid:") + len("/Processid:")
                detected_clsid = parent_cmdline[clsid_start:].strip().strip("{}")
                detected_clsid = "{" + detected_clsid + "}"

            dcom_name = DCOM_CLSIDS.get(detected_clsid.upper(), "Unknown DCOM Object")

            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "DCOM Object Execution via dllhost.exe",
                "dcom_object": dcom_name,
                "clsid": detected_clsid,
                "parent_image": parent_image,
                "parent_commandline": parent_cmdline,
                "child_image": image,
                "child_commandline": cmdline,
                "user": user,
                "severity": "HIGH",
                "mitre": "T1021.003",
            })

    return findings


def detect_dcom_network_connections(events):
    """
    Detect DCOM-related network connections via Sysmon Event ID 3.
    Looks for inbound RPC connections (port 135) to DCOM processes.
    """
    findings = []

    for event in events:
        if event.get("EventID") != 3:
            continue

        image = event.get("Image", "")
        dest_port = event.get("DestinationPort", "")
        source_ip = event.get("SourceIp", "")
        dest_ip = event.get("DestinationIp", "")
        initiated = event.get("Initiated", "")
        time_created = event.get("TimeCreated", "")
        computer = event.get("Computer", "")

        # Inbound RPC connection (port 135) -- DCOM always starts here
        if dest_port == "135" and initiated.lower() == "false":
            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "Inbound RPC Endpoint Mapper Connection",
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "process_image": image,
                "severity": "MEDIUM",
                "mitre": "T1021.003",
                "note": "DCOM communication begins with RPC endpoint mapper query on port 135",
            })

        # DCOM process making outbound connection on high port (dynamic RPC)
        if is_dcom_parent(image) and dest_port and int(dest_port) > 49151:
            findings.append({
                "timestamp": time_created,
                "computer": computer,
                "detection_type": "DCOM Process Dynamic RPC Connection",
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "process_image": image,
                "severity": "LOW",
                "mitre": "T1021.003",
                "note": "DCOM process communicating on dynamic RPC port range",
            })

    return findings


def correlate_network_and_process(process_findings, network_findings, window_seconds=60):
    """
    Correlate network connections with process creation events.
    A network connection to port 135 followed by DCOM process creation
    within the time window is a strong indicator of lateral movement.
    """
    correlated = []

    for proc in process_findings:
        proc_time = proc.get("timestamp", "")
        proc_computer = proc.get("computer", "")

        if not proc_time:
            continue

        try:
            proc_dt = datetime.fromisoformat(proc_time.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        for net in network_findings:
            net_time = net.get("timestamp", "")
            net_computer = net.get("computer", "")

            if not net_time or net_computer != proc_computer:
                continue

            try:
                net_dt = datetime.fromisoformat(net_time.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            time_diff = abs((proc_dt - net_dt).total_seconds())

            if time_diff <= window_seconds and net_dt <= proc_dt:
                correlated.append({
                    "correlation_type": "DCOM Lateral Movement Chain",
                    "severity": "CRITICAL",
                    "mitre": "T1021.003",
                    "computer": proc_computer,
                    "network_event": {
                        "timestamp": net_time,
                        "source_ip": net.get("source_ip"),
                        "destination_port": net.get("destination_port"),
                    },
                    "process_event": {
                        "timestamp": proc_time,
                        "dcom_object": proc.get("dcom_object"),
                        "parent_image": proc.get("parent_image"),
                        "child_image": proc.get("child_image"),
                        "child_commandline": proc.get("child_commandline"),
                        "user": proc.get("user"),
                    },
                    "time_delta_seconds": round(time_diff, 2),
                })

    return correlated


def parse_evtx_file(filepath):
    """Parse a .evtx file and return list of parsed events."""
    events = []
    try:
        with evtx.Evtx(filepath) as log:
            for record in log.records():
                try:
                    event = parse_sysmon_event(record.xml())
                    if event:
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
        print(f"\n  [{i}] {finding.get('detection_type', 'Unknown')}")
        print(f"      Severity: {finding.get('severity', 'N/A')}")
        print(f"      MITRE: {finding.get('mitre', 'N/A')}")
        print(f"      Time: {finding.get('timestamp', 'N/A')}")
        print(f"      Computer: {finding.get('computer', 'N/A')}")

        if "dcom_object" in finding:
            print(f"      DCOM Object: {finding['dcom_object']}")
            print(f"      CLSID: {finding.get('clsid', 'N/A')}")
        if "parent_image" in finding:
            print(f"      Parent: {finding['parent_image']}")
            print(f"      Child: {finding.get('child_image', 'N/A')}")
            print(f"      Command: {finding.get('child_commandline', 'N/A')[:120]}")
        if "source_ip" in finding:
            print(f"      Source IP: {finding['source_ip']}")
            print(f"      Dest Port: {finding.get('destination_port', 'N/A')}")
        if "note" in finding:
            print(f"      Note: {finding['note']}")


def print_correlated(correlated):
    """Print correlated findings."""
    if not correlated:
        print("\n[+] Correlated DCOM Chains: No findings")
        return

    print(f"\n{'=' * 80}")
    print(f"  CORRELATED DCOM LATERAL MOVEMENT CHAINS ({len(correlated)} findings)")
    print(f"{'=' * 80}")

    for i, c in enumerate(correlated, 1):
        net = c["network_event"]
        proc = c["process_event"]
        print(f"\n  [{i}] {c['correlation_type']}")
        print(f"      Severity: {c['severity']}")
        print(f"      Target: {c['computer']}")
        print(f"      Source IP: {net['source_ip']} -> port {net['destination_port']}")
        print(f"      Time Delta: {c['time_delta_seconds']}s")
        print(f"      DCOM Object: {proc['dcom_object']}")
        print(f"      Process Chain: {proc['parent_image']} -> {proc['child_image']}")
        print(f"      Command: {proc.get('child_commandline', 'N/A')[:120]}")
        print(f"      User: {proc.get('user', 'N/A')}")


def main():
    parser = argparse.ArgumentParser(
        description="Detect DCOM lateral movement from Sysmon and Security event logs"
    )
    parser.add_argument(
        "--evtx", required=True,
        help="Path to Sysmon .evtx log file"
    )
    parser.add_argument(
        "--security",
        help="Path to Windows Security .evtx log file (optional, for 4624 correlation)"
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
        "--correlation-window", type=int, default=60,
        help="Time window in seconds for correlating network and process events (default: 60)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.evtx):
        print(f"[!] File not found: {args.evtx}")
        sys.exit(1)

    print(f"[*] Parsing Sysmon events from: {args.evtx}")
    events = parse_evtx_file(args.evtx)
    print(f"[*] Parsed {len(events)} Sysmon events")

    security_events = []
    if args.security:
        if os.path.exists(args.security):
            print(f"[*] Parsing Security events from: {args.security}")
            security_events = parse_evtx_file(args.security)
            print(f"[*] Parsed {len(security_events)} Security events")
        else:
            print(f"[!] Security log not found: {args.security}")

    print("[*] Analyzing for DCOM lateral movement indicators...")

    process_findings = detect_dcom_process_creation(events)
    network_findings = detect_dcom_network_connections(events)
    correlated = correlate_network_and_process(
        process_findings, network_findings, args.correlation_window
    )

    all_results = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "sysmon_log": args.evtx,
        "security_log": args.security or "Not provided",
        "total_events_parsed": len(events) + len(security_events),
        "process_creation_findings": process_findings,
        "network_connection_findings": network_findings,
        "correlated_chains": correlated,
        "summary": {
            "process_detections": len(process_findings),
            "network_detections": len(network_findings),
            "correlated_chains": len(correlated),
            "critical_findings": len([c for c in correlated]),
            "high_findings": len([f for f in process_findings if f.get("severity") == "HIGH"]),
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
        print("\n[*] DCOM Lateral Movement Detection Report")
        print(f"[*] Scan Time: {all_results['scan_time']}")
        print(f"[*] Events Analyzed: {all_results['total_events_parsed']}")

        print_findings(process_findings, "DCOM Process Creation Detections")
        print_findings(network_findings, "DCOM Network Connection Detections")
        print_correlated(correlated)

        print(f"\n{'=' * 80}")
        print("  SUMMARY")
        print(f"{'=' * 80}")
        s = all_results["summary"]
        print(f"  Process Creation Detections: {s['process_detections']}")
        print(f"  Network Connection Detections: {s['network_detections']}")
        print(f"  Correlated Lateral Movement Chains: {s['correlated_chains']}")
        print(f"  Critical Findings: {s['critical_findings']}")
        print(f"  High Findings: {s['high_findings']}")

        if args.output:
            with open(args.output, "w") as f:
                json.dump(all_results, f, indent=2, default=str)
            print(f"\n[*] Full results written to: {args.output}")


if __name__ == "__main__":
    main()
