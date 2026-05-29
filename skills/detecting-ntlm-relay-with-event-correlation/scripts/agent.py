#!/usr/bin/env python3
"""NTLM Relay Detection Agent - Detects NTLM relay via Event 4624 correlation and signing audit."""

import json
import logging
import argparse
import csv
import os
import sys
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
RAPID_AUTH_WINDOW_DEFAULT = 120
RAPID_AUTH_THRESHOLD_DEFAULT = 3
SUBPROCESS_TIMEOUT = 30


def parse_security_evtx(evtx_path):
    """Parse Windows Security EVTX for Event 4624/4625/4776."""
    try:
        from Evtx.Evtx import FileHeader
        from lxml import etree
    except ImportError:
        logger.error("Required packages missing. Install: pip install python-evtx lxml")
        sys.exit(1)

    events = []
    target_ids = {"4624", "4625", "4776"}
    ns = {"evt": EVTX_NS}
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                eid_elem = root.find(".//evt:System/evt:EventID", ns)
                if eid_elem is None or eid_elem.text not in target_ids:
                    continue
                data = {}
                for elem in root.findall(".//evt:EventData/evt:Data", ns):
                    data[elem.get("Name", "")] = elem.text or ""
                time_elem = root.find(".//evt:System/evt:TimeCreated", ns)
                data["TimeCreated"] = time_elem.get("SystemTime", "") if time_elem is not None else ""
                comp_elem = root.find(".//evt:System/evt:Computer", ns)
                data["Computer"] = comp_elem.text if comp_elem is not None else ""
                data["EventID"] = eid_elem.text
                events.append(data)
            except Exception:
                continue
    logger.info("Parsed %d security events from %s", len(events), evtx_path)
    return events


def load_inventory(csv_path):
    """Load hostname-to-IP inventory from CSV (columns: hostname, ip_address)."""
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
        logger.error("Failed to load inventory: %s", e)
    logger.info("Loaded %d hosts from inventory", len(inventory))
    return inventory


def detect_ip_hostname_mismatch(events, inventory):
    """Detect NTLM relay via IP-hostname mismatch in Event 4624 LogonType 3."""
    findings = []
    for ev in events:
        if ev.get("EventID") != "4624" or ev.get("LogonType") != "3":
            continue
        if ev.get("AuthenticationPackageName") != "NTLM":
            continue
        user = ev.get("TargetUserName", "")
        if user.endswith("$") or user in ("ANONYMOUS LOGON", "-", ""):
            continue
        source_ip = ev.get("IpAddress", "")
        if source_ip in ("-", "::1", "127.0.0.1", ""):
            continue
        workstation = ev.get("WorkstationName", "").strip().upper()
        if workstation in inventory:
            expected = inventory[workstation]
            if source_ip != expected:
                findings.append({
                    "detection": "IP-Hostname Mismatch (NTLM Relay Indicator)",
                    "severity": "CRITICAL",
                    "mitre": "T1557.001",
                    "timestamp": ev.get("TimeCreated"),
                    "target_host": ev.get("Computer"),
                    "target_user": user,
                    "workstation": workstation,
                    "actual_ip": source_ip,
                    "expected_ip": expected,
                    "lm_package": ev.get("LmPackageName"),
                })
    logger.info("IP-hostname mismatch findings: %d", len(findings))
    return findings


def detect_rapid_auth(events, window=RAPID_AUTH_WINDOW_DEFAULT, threshold=RAPID_AUTH_THRESHOLD_DEFAULT):
    """Detect rapid NTLM authentication to multiple targets (relay spraying)."""
    findings = []
    auth_groups = defaultdict(list)
    for ev in events:
        if ev.get("EventID") != "4624" or ev.get("LogonType") != "3":
            continue
        if ev.get("AuthenticationPackageName") != "NTLM":
            continue
        user = ev.get("TargetUserName", "")
        ip = ev.get("IpAddress", "")
        if user.endswith("$") or user in ("ANONYMOUS LOGON", "-", ""):
            continue
        if ip in ("-", "::1", "127.0.0.1", ""):
            continue
        try:
            ts = datetime.fromisoformat(ev["TimeCreated"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            continue
        auth_groups[(ip, user)].append({"ts": ts, "target": ev.get("Computer", "")})

    for (ip, user), auths in auth_groups.items():
        auths.sort(key=lambda x: x["ts"])
        for i in range(len(auths)):
            start = auths[i]["ts"]
            end = start + timedelta(seconds=window)
            targets = set()
            for j in range(i, len(auths)):
                if auths[j]["ts"] <= end:
                    targets.add(auths[j]["target"])
                else:
                    break
            if len(targets) >= threshold:
                findings.append({
                    "detection": "Rapid Multi-Host NTLM Auth (Relay Spraying)",
                    "severity": "HIGH",
                    "mitre": "T1557.001",
                    "timestamp": start.isoformat(),
                    "source_ip": ip,
                    "target_user": user,
                    "unique_targets": len(targets),
                    "targets": sorted(targets),
                    "window_seconds": window,
                })
                break
    logger.info("Rapid auth findings: %d", len(findings))
    return findings


def detect_ntlmv1_downgrade(events):
    """Detect NTLMv1 authentication events indicating downgrade attack."""
    findings = []
    v1_by_user = defaultdict(list)
    for ev in events:
        if ev.get("EventID") != "4624" or ev.get("LogonType") != "3":
            continue
        lm = ev.get("LmPackageName", "")
        if "NTLM V1" not in lm:
            continue
        user = ev.get("TargetUserName", "")
        if user.endswith("$") or user in ("ANONYMOUS LOGON", "-", ""):
            continue
        v1_by_user[user].append({
            "ts": ev.get("TimeCreated"),
            "target": ev.get("Computer"),
            "ip": ev.get("IpAddress"),
        })

    for user, auths in v1_by_user.items():
        findings.append({
            "detection": "NTLMv1 Downgrade Detected",
            "severity": "HIGH",
            "mitre": "T1557.001",
            "timestamp": auths[0]["ts"],
            "target_user": user,
            "ntlmv1_count": len(auths),
            "source_ips": sorted(set(a["ip"] for a in auths)),
            "targets": sorted(set(a["target"] for a in auths)),
        })
    logger.info("NTLMv1 downgrade findings: %d", len(findings))
    return findings


def detect_machine_relay(events):
    """Detect machine account NTLM relay (PetitPotam, DFSCoerce, PrinterBug)."""
    findings = []
    machine_auths = defaultdict(list)
    for ev in events:
        if ev.get("EventID") != "4624" or ev.get("LogonType") != "3":
            continue
        if ev.get("AuthenticationPackageName") != "NTLM":
            continue
        user = ev.get("TargetUserName", "")
        if not user.endswith("$"):
            continue
        ip = ev.get("IpAddress", "")
        if ip in ("-", "::1", "127.0.0.1", ""):
            continue
        machine_auths[user].append({
            "ts": ev.get("TimeCreated"),
            "target": ev.get("Computer"),
            "ip": ip,
        })

    for machine, auths in machine_auths.items():
        ips = set(a["ip"] for a in auths)
        if len(ips) > 1:
            findings.append({
                "detection": "Machine Account Relay (Coercion + NTLM Relay)",
                "severity": "CRITICAL",
                "mitre": "T1557.001",
                "timestamp": auths[0]["ts"],
                "machine_account": machine,
                "source_ips": sorted(ips),
                "targets": sorted(set(a["target"] for a in auths)),
                "auth_count": len(auths),
            })
    logger.info("Machine account relay findings: %d", len(findings))
    return findings


def audit_smb_signing_local():
    """Audit local SMB signing configuration (Windows only)."""
    if sys.platform != "win32":
        logger.info("SMB signing audit only available on Windows")
        return {}

    audit = {}
    checks = {
        "SMB_Server_RequireSign": (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
            "RequireSecuritySignature"
        ),
        "SMB_Client_RequireSign": (
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters",
            "RequireSecuritySignature"
        ),
        "LmCompatibilityLevel": (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "LmCompatibilityLevel"
        ),
        "LLMNR_Disabled": (
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast"
        ),
    }

    for label, (key, value_name) in checks.items():
        try:
            result = subprocess.run(
                ["reg", "query", key, "/v", value_name],
                capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if value_name in line:
                        parts = line.strip().split()
                        audit[label] = parts[-1] if parts else "UNKNOWN"
                        break
            else:
                audit[label] = "NOT_CONFIGURED"
        except subprocess.TimeoutExpired:
            audit[label] = "TIMEOUT"
        except Exception as e:
            audit[label] = f"ERROR: {e}"

    # Evaluate risk
    smb_server = audit.get("SMB_Server_RequireSign", "")
    audit["SMB_Relay_Vulnerable"] = "YES" if smb_server != "0x1" else "NO"

    lm_level = audit.get("LmCompatibilityLevel", "")
    try:
        lm_int = int(lm_level, 0)
        audit["NTLMv1_Vulnerable"] = "YES" if lm_int < 3 else "NO"
    except (ValueError, TypeError):
        audit["NTLMv1_Vulnerable"] = "UNKNOWN"

    llmnr = audit.get("LLMNR_Disabled", "")
    audit["Responder_Vulnerable"] = "NO" if llmnr == "0x0" else "YES"

    return audit


def generate_report(all_findings, smb_audit, output_path):
    """Generate JSON detection report."""
    report = {
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "mitre_technique": "T1557.001",
        "summary": {
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
            "high": len([f for f in all_findings if f.get("severity") == "HIGH"]),
            "medium": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
        },
        "findings": all_findings,
        "smb_signing_audit": smb_audit,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", output_path)

    s = report["summary"]
    print("\nNTLM RELAY DETECTION REPORT")
    print(f"  Total findings: {s['total_findings']}")
    print(f"  Critical: {s['critical']}, High: {s['high']}, Medium: {s['medium']}")
    if s["critical"] > 0:
        print("  [!!!] CRITICAL: IP-hostname mismatch or machine account relay detected")
    if smb_audit.get("SMB_Relay_Vulnerable") == "YES":
        print("  [!] WARNING: SMB signing NOT enforced on this host")
    if smb_audit.get("Responder_Vulnerable") == "YES":
        print("  [!] WARNING: LLMNR enabled - vulnerable to Responder poisoning")
    return report


def main():
    parser = argparse.ArgumentParser(
        description="NTLM Relay Detection Agent (T1557.001)"
    )
    parser.add_argument("--evtx", required=True, help="Path to Windows Security .evtx file")
    parser.add_argument("--inventory", help="CSV file with hostname,ip_address columns for mismatch detection")
    parser.add_argument("--output", "-o", default="ntlm_relay_report.json",
                        help="Output JSON report path (default: ntlm_relay_report.json)")
    parser.add_argument("--rapid-window", type=int, default=RAPID_AUTH_WINDOW_DEFAULT,
                        help=f"Rapid auth detection window in seconds (default: {RAPID_AUTH_WINDOW_DEFAULT})")
    parser.add_argument("--rapid-threshold", type=int, default=RAPID_AUTH_THRESHOLD_DEFAULT,
                        help=f"Min unique targets for rapid auth alert (default: {RAPID_AUTH_THRESHOLD_DEFAULT})")
    parser.add_argument("--audit-signing", action="store_true",
                        help="Audit local SMB/NTLM signing configuration (Windows only)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.path.isfile(args.evtx):
        logger.error("EVTX file not found: %s", args.evtx)
        sys.exit(1)

    inventory = {}
    if args.inventory:
        if os.path.isfile(args.inventory):
            inventory = load_inventory(args.inventory)
        else:
            logger.warning("Inventory file not found: %s", args.inventory)

    logger.info("Parsing security events from: %s", args.evtx)
    events = parse_security_evtx(args.evtx)

    mismatch = detect_ip_hostname_mismatch(events, inventory) if inventory else []
    rapid = detect_rapid_auth(events, args.rapid_window, args.rapid_threshold)
    downgrade = detect_ntlmv1_downgrade(events)
    machine = detect_machine_relay(events)

    if not inventory:
        logger.warning("No inventory provided (--inventory). IP-hostname mismatch detection disabled.")

    all_findings = mismatch + machine + rapid + downgrade
    all_findings.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
        x.get("severity", "LOW"), 4))

    smb_audit = audit_smb_signing_local() if args.audit_signing else {}

    generate_report(all_findings, smb_audit, args.output)


if __name__ == "__main__":
    main()
