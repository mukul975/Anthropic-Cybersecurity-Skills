#!/usr/bin/env python3
"""DCOM Lateral Movement Detection Agent - Hunts for DCOM object abuse via Sysmon event correlation."""

import json
import logging
import argparse
import os
import sys
import subprocess
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# DCOM COM object CLSIDs used for lateral movement
DCOM_CLSIDS = {
    "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}": "MMC20.Application",
    "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}": "ShellWindows",
    "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}": "ShellBrowserWindow",
    "{00024500-0000-0000-C000-000000000046}": "Excel.Application",
    "{0006F03A-0000-0000-C000-000000000046}": "Outlook.Application",
}

DCOM_PARENT_PROCESSES = ["mmc.exe", "dllhost.exe", "explorer.exe"]
SUSPICIOUS_CHILDREN = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe",
]

SYSMON_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
EVTX_PARSE_TIMEOUT = 300  # seconds


def parse_evtx_records(evtx_path):
    """Parse Sysmon EVTX file into structured events using python-evtx."""
    try:
        from Evtx.Evtx import FileHeader
        from lxml import etree
    except ImportError:
        logger.error("Required packages missing. Install: pip install python-evtx lxml")
        sys.exit(1)

    events = []
    ns = {"evt": SYSMON_NS}
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                event_id_elem = root.find(".//evt:System/evt:EventID", ns)
                if event_id_elem is None:
                    continue
                eid = int(event_id_elem.text)
                if eid not in (1, 3, 7):
                    continue
                data = {}
                for elem in root.findall(".//evt:EventData/evt:Data", ns):
                    data[elem.get("Name", "")] = elem.text or ""
                time_elem = root.find(".//evt:System/evt:TimeCreated", ns)
                timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""
                comp_elem = root.find(".//evt:System/evt:Computer", ns)
                computer = comp_elem.text if comp_elem is not None else ""
                data["EventID"] = eid
                data["TimeCreated"] = timestamp
                data["Computer"] = computer
                events.append(data)
            except Exception:
                continue
    logger.info("Parsed %d Sysmon events (EID 1,3,7) from %s", len(events), evtx_path)
    return events


def detect_mmc20_lateral(events):
    """Detect MMC20.Application DCOM lateral movement: mmc.exe spawning suspicious children."""
    findings = []
    for ev in events:
        if ev.get("EventID") != 1:
            continue
        parent = ev.get("ParentImage", "").lower()
        image = ev.get("Image", "").lower()
        if "mmc.exe" not in parent:
            continue
        if not any(child in image for child in SUSPICIOUS_CHILDREN):
            continue
        findings.append({
            "detection": "MMC20.Application DCOM Lateral Movement",
            "severity": "HIGH",
            "mitre": "T1021.003",
            "timestamp": ev.get("TimeCreated"),
            "computer": ev.get("Computer"),
            "parent_image": ev.get("ParentImage"),
            "parent_cmdline": ev.get("ParentCommandLine"),
            "child_image": ev.get("Image"),
            "child_cmdline": ev.get("CommandLine"),
            "user": ev.get("User"),
            "clsid": "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}",
        })
    logger.info("MMC20 detections: %d", len(findings))
    return findings


def detect_shell_dcom_lateral(events):
    """Detect ShellWindows/ShellBrowserWindow: explorer.exe spawning cmd/powershell."""
    findings = []
    for ev in events:
        if ev.get("EventID") != 1:
            continue
        parent = ev.get("ParentImage", "").lower()
        image = ev.get("Image", "").lower()
        if "explorer.exe" not in parent:
            continue
        if not any(child in image for child in ["cmd.exe", "powershell.exe", "pwsh.exe",
                                                  "mshta.exe", "wscript.exe", "cscript.exe"]):
            continue
        findings.append({
            "detection": "ShellWindows/ShellBrowserWindow DCOM Lateral Movement",
            "severity": "MEDIUM",
            "mitre": "T1021.003",
            "timestamp": ev.get("TimeCreated"),
            "computer": ev.get("Computer"),
            "parent_image": ev.get("ParentImage"),
            "child_image": ev.get("Image"),
            "child_cmdline": ev.get("CommandLine"),
            "user": ev.get("User"),
            "clsid": "{9BA05972} or {C08AFD90}",
        })
    logger.info("ShellWindows/ShellBrowserWindow detections: %d", len(findings))
    return findings


def detect_dllhost_lateral(events):
    """Detect DCOM via dllhost.exe spawning suspicious children."""
    findings = []
    for ev in events:
        if ev.get("EventID") != 1:
            continue
        parent = ev.get("ParentImage", "").lower()
        image = ev.get("Image", "").lower()
        if "dllhost.exe" not in parent:
            continue
        if not any(child in image for child in SUSPICIOUS_CHILDREN):
            continue
        parent_cmdline = ev.get("ParentCommandLine", "")
        clsid = "Unknown"
        if "/Processid:" in parent_cmdline:
            start = parent_cmdline.find("/Processid:") + len("/Processid:")
            clsid_raw = parent_cmdline[start:].strip().strip("{}")
            clsid = "{" + clsid_raw + "}"
        dcom_name = DCOM_CLSIDS.get(clsid.upper(), "Unknown DCOM Object")
        findings.append({
            "detection": f"DCOM via dllhost.exe ({dcom_name})",
            "severity": "HIGH",
            "mitre": "T1021.003",
            "timestamp": ev.get("TimeCreated"),
            "computer": ev.get("Computer"),
            "parent_image": ev.get("ParentImage"),
            "parent_cmdline": parent_cmdline,
            "child_image": ev.get("Image"),
            "child_cmdline": ev.get("CommandLine"),
            "user": ev.get("User"),
            "clsid": clsid,
            "dcom_object": dcom_name,
        })
    logger.info("dllhost.exe DCOM detections: %d", len(findings))
    return findings


def detect_rpc_connections(events):
    """Detect inbound RPC endpoint mapper connections (port 135) from Sysmon Event ID 3."""
    rpc_connections = []
    for ev in events:
        if ev.get("EventID") != 3:
            continue
        dest_port = ev.get("DestinationPort", "")
        initiated = ev.get("Initiated", "").lower()
        if dest_port == "135" and initiated == "false":
            rpc_connections.append({
                "detection": "Inbound RPC Connection (DCOM Prerequisite)",
                "severity": "LOW",
                "timestamp": ev.get("TimeCreated"),
                "computer": ev.get("Computer"),
                "source_ip": ev.get("SourceIp"),
                "dest_ip": ev.get("DestinationIp"),
                "dest_port": dest_port,
                "image": ev.get("Image"),
            })
    logger.info("Inbound RPC (port 135) connections: %d", len(rpc_connections))
    return rpc_connections


def correlate_rpc_with_process(rpc_events, process_findings, window_seconds=60):
    """Correlate RPC connections with DCOM process creation for high-confidence detections."""
    correlated = []
    for proc in process_findings:
        proc_time_str = proc.get("timestamp", "")
        proc_computer = proc.get("computer", "")
        if not proc_time_str:
            continue
        try:
            proc_dt = datetime.fromisoformat(proc_time_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        for rpc in rpc_events:
            rpc_time_str = rpc.get("timestamp", "")
            rpc_computer = rpc.get("computer", "")
            if not rpc_time_str or rpc_computer != proc_computer:
                continue
            try:
                rpc_dt = datetime.fromisoformat(rpc_time_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            delta = (proc_dt - rpc_dt).total_seconds()
            if 0 <= delta <= window_seconds:
                correlated.append({
                    "detection": "CORRELATED: RPC Connection -> DCOM Process Creation",
                    "severity": "CRITICAL",
                    "mitre": "T1021.003",
                    "computer": proc_computer,
                    "source_ip": rpc.get("source_ip"),
                    "rpc_time": rpc_time_str,
                    "process_time": proc_time_str,
                    "time_delta_seconds": round(delta, 2),
                    "dcom_detection": proc.get("detection"),
                    "child_image": proc.get("child_image"),
                    "child_cmdline": proc.get("child_cmdline"),
                    "user": proc.get("user"),
                })
                break
    logger.info("Correlated RPC->Process chains: %d", len(correlated))
    return correlated


def audit_dcom_config():
    """Audit local DCOM configuration for high-risk COM objects (Windows only)."""
    if sys.platform != "win32":
        logger.info("DCOM config audit only available on Windows")
        return []

    audit_results = []
    for clsid, name in DCOM_CLSIDS.items():
        try:
            result = subprocess.run(
                ["reg", "query", f"HKLM\\SOFTWARE\\Classes\\CLSID\\{clsid}"],
                capture_output=True, text=True, timeout=10
            )
            exists = result.returncode == 0
            audit_results.append({
                "clsid": clsid,
                "name": name,
                "registered": exists,
                "risk": "HIGH" if exists else "N/A",
            })
        except subprocess.TimeoutExpired:
            audit_results.append({"clsid": clsid, "name": name, "registered": "TIMEOUT", "risk": "UNKNOWN"})
        except Exception as e:
            audit_results.append({"clsid": clsid, "name": name, "registered": f"ERROR: {e}", "risk": "UNKNOWN"})

    # Check if DCOM is enabled
    try:
        result = subprocess.run(
            ["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Ole", "/v", "EnableDCOM"],
            capture_output=True, text=True, timeout=10
        )
        dcom_enabled = "Y" in result.stdout if result.returncode == 0 else "UNKNOWN"
        audit_results.append({"check": "DCOM Enabled", "value": dcom_enabled,
                              "risk": "HIGH" if dcom_enabled == "Y" else "LOW"})
    except (subprocess.TimeoutExpired, Exception):
        pass

    return audit_results


def generate_report(all_findings, dcom_audit, output_path):
    """Generate JSON detection report."""
    report = {
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "mitre_technique": "T1021.003",
        "summary": {
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
            "low": len([f for f in all_findings if f.get("severity") == "LOW"]),
        },
        "findings": all_findings,
        "dcom_config_audit": dcom_audit,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", output_path)

    s = report["summary"]
    print("\nDCOM LATERAL MOVEMENT DETECTION REPORT")
    print(f"  Total findings: {s['total_findings']}")
    print(f"  Critical: {s['critical']}, High: {s['high']}, Medium: {s['medium']}, Low: {s['low']}")
    if s["critical"] > 0:
        print("  [!!!] CRITICAL: Correlated RPC + process creation chains detected")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="DCOM Lateral Movement Detection Agent (T1021.003)"
    )
    parser.add_argument("--evtx", required=True, help="Path to Sysmon .evtx log file")
    parser.add_argument("--output", "-o", default="dcom_detection_report.json",
                        help="Output JSON report path (default: dcom_detection_report.json)")
    parser.add_argument("--correlation-window", type=int, default=60,
                        help="Seconds window for RPC-to-process correlation (default: 60)")
    parser.add_argument("--audit-dcom", action="store_true",
                        help="Audit local DCOM object registration (Windows only)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.isfile(args.evtx):
        logger.error("EVTX file not found: %s", args.evtx)
        sys.exit(1)

    logger.info("Parsing Sysmon events from: %s", args.evtx)
    events = parse_evtx_records(args.evtx)

    mmc_findings = detect_mmc20_lateral(events)
    shell_findings = detect_shell_dcom_lateral(events)
    dllhost_findings = detect_dllhost_lateral(events)
    rpc_connections = detect_rpc_connections(events)

    all_process_findings = mmc_findings + shell_findings + dllhost_findings
    correlated = correlate_rpc_with_process(
        rpc_connections, all_process_findings, args.correlation_window
    )

    all_findings = correlated + all_process_findings
    all_findings.sort(key=lambda x: x.get("severity", ""), reverse=True)

    dcom_audit = audit_dcom_config() if args.audit_dcom else []

    generate_report(all_findings, dcom_audit, args.output)


if __name__ == "__main__":
    main()
