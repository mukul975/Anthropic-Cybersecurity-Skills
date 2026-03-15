#!/usr/bin/env python3
"""DCSync Detection Agent - hunts for unauthorized AD replication requests via Event ID 4662 analysis."""

import json
import argparse
import logging
import subprocess
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

DCSYNC_ACCESS_MASK = "0x100"


def get_domain_controllers():
    """Get list of legitimate domain controller machine accounts."""
    cmd = ["powershell", "-Command",
           "Get-ADDomainController -Filter * | Select-Object Name, IPv4Address | ConvertTo-Json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    dcs = []
    try:
        data = json.loads(result.stdout) if result.stdout else []
        if isinstance(data, dict):
            data = [data]
        for dc in data:
            dcs.append({
                "name": dc.get("Name", ""),
                "ip": dc.get("IPv4Address", ""),
                "machine_account": dc.get("Name", "") + "$",
            })
    except json.JSONDecodeError:
        pass
    return dcs


def query_event_4662(evtx_path=None, max_events=5000):
    """Query Windows Event ID 4662 for directory service access events."""
    events = []
    if evtx_path:
        cmd = ["wevtutil", "qe", evtx_path, "/lf:true",
               "/q:*[System[EventID=4662]]", "/f:xml", f"/c:{max_events}"]
    else:
        cmd = ["wevtutil", "qe", "Security",
               "/q:*[System[EventID=4662]]", "/f:xml", f"/c:{max_events}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    for event_xml in re.findall(r"<Event.*?</Event>", result.stdout, re.DOTALL):
        try:
            root = ET.fromstring(event_xml)
            ns = {"s": "http://schemas.microsoft.com/win/2004/08/events/event"}
            data = {}
            for el in root.findall(".//s:Data", ns):
                data[el.get("Name", "")] = el.text or ""
            time_created = root.find(".//s:TimeCreated", ns)
            timestamp = time_created.get("SystemTime", "") if time_created is not None else ""
            events.append({
                "timestamp": timestamp,
                "computer": root.findtext(".//s:Computer", "", ns),
                "subject_user_name": data.get("SubjectUserName", ""),
                "subject_domain_name": data.get("SubjectDomainName", ""),
                "subject_logon_id": data.get("SubjectLogonId", ""),
                "object_server": data.get("ObjectServer", ""),
                "object_type": data.get("ObjectType", ""),
                "object_name": data.get("ObjectName", ""),
                "access_mask": data.get("AccessMask", ""),
                "properties": data.get("Properties", ""),
            })
        except ET.ParseError:
            continue
    logger.info("Parsed %d Event 4662 entries", len(events))
    return events


def filter_replication_events(events):
    """Filter events for DS-Replication GUID access."""
    replication_events = []
    for event in events:
        properties = event.get("properties", "").lower()
        access_mask = event.get("access_mask", "")
        for guid, name in REPLICATION_GUIDS.items():
            if guid.lower() in properties and access_mask == DCSYNC_ACCESS_MASK:
                replication_events.append({
                    **event,
                    "replication_right": name,
                    "guid": guid,
                })
    return replication_events


def identify_dcsync_suspects(replication_events, dc_accounts):
    """Identify non-DC accounts performing replication requests."""
    dc_names = set(dc.get("machine_account", "").lower() for dc in dc_accounts)
    dc_names.update(dc.get("name", "").lower() + "$" for dc in dc_accounts)
    known_legitimate = {"azureadconnect", "sccm", "adconnect", "microsoftdirectorysync"}
    suspects = []
    legitimate = []
    for event in replication_events:
        account = event["subject_user_name"].lower()
        domain = event["subject_domain_name"]
        if account in dc_names:
            legitimate.append(event)
            continue
        if account.endswith("$") and account in dc_names:
            legitimate.append(event)
            continue
        if any(known in account for known in known_legitimate):
            legitimate.append(event)
            continue
        event["severity"] = "critical"
        event["mitre_technique"] = "T1003.006"
        event["indicator"] = "Non-DC account performing directory replication"
        suspects.append(event)
    return suspects, legitimate


def analyze_suspect_patterns(suspects):
    """Analyze patterns in suspected DCSync activity."""
    by_account = defaultdict(lambda: {"count": 0, "computers": set(), "guids": set(), "timestamps": []})
    for event in suspects:
        account = f"{event['subject_domain_name']}\\{event['subject_user_name']}"
        by_account[account]["count"] += 1
        by_account[account]["computers"].add(event["computer"])
        by_account[account]["guids"].add(event.get("replication_right", ""))
        by_account[account]["timestamps"].append(event["timestamp"])
    patterns = []
    for account, data in by_account.items():
        has_both = "DS-Replication-Get-Changes" in data["guids"] and "DS-Replication-Get-Changes-All" in data["guids"]
        patterns.append({
            "account": account,
            "replication_requests": data["count"],
            "source_computers": list(data["computers"]),
            "replication_rights": list(data["guids"]),
            "has_full_dcsync_rights": has_both,
            "severity": "critical" if has_both else "high",
            "first_seen": min(data["timestamps"]) if data["timestamps"] else "",
            "last_seen": max(data["timestamps"]) if data["timestamps"] else "",
        })
    return sorted(patterns, key=lambda x: x["replication_requests"], reverse=True)


def check_replication_acls():
    """Check which accounts have replication rights on the domain object."""
    cmd = ["powershell", "-Command",
           "(Get-Acl 'AD:\\DC=domain,DC=local').Access | "
           "Where-Object {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or "
           "$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'} | "
           "Select-Object IdentityReference, ActiveDirectoryRights | ConvertTo-Json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        acls = json.loads(result.stdout) if result.stdout else []
        if isinstance(acls, dict):
            acls = [acls]
        return [{"identity": a.get("IdentityReference", ""), "rights": a.get("ActiveDirectoryRights", "")} for a in acls]
    except json.JSONDecodeError:
        return []


def generate_report(events, replication_events, suspects, legitimate, patterns, acls):
    """Generate DCSync hunt report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "hunt_type": "DCSync Detection (T1003.006)",
        "events_analyzed": len(events),
        "replication_events": len(replication_events),
        "legitimate_replication": len(legitimate),
        "suspicious_replication": len(suspects),
        "severity": "critical" if suspects else "clear",
        "suspect_patterns": patterns,
        "accounts_with_replication_rights": acls,
        "suspicious_events_detail": suspects[:20],
        "recommendations": [
            "Disable compromised accounts immediately",
            "Reset krbtgt password twice (with 12-hour interval)",
            "Audit all accounts with DS-Replication-Get-Changes rights",
            "Investigate source hosts for additional compromise indicators",
            "Review lateral movement from suspect accounts",
        ] if suspects else ["No DCSync activity detected - continue monitoring"],
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="DCSync Attack Detection Agent")
    parser.add_argument("--evtx", help="Path to exported Security .evtx file")
    parser.add_argument("--max-events", type=int, default=5000, help="Max events to parse (default: 5000)")
    parser.add_argument("--skip-acl-check", action="store_true", help="Skip replication ACL enumeration")
    parser.add_argument("--known-dcs", help="JSON file with known DC hostnames")
    parser.add_argument("--output", default="dcsync_hunt_report.json")
    args = parser.parse_args()

    dc_accounts = get_domain_controllers()
    if args.known_dcs:
        with open(args.known_dcs) as f:
            extra_dcs = json.load(f)
            dc_accounts.extend(extra_dcs)
    logger.info("Known DCs: %d", len(dc_accounts))

    events = query_event_4662(args.evtx, args.max_events)
    replication_events = filter_replication_events(events)
    suspects, legitimate = identify_dcsync_suspects(replication_events, dc_accounts)
    patterns = analyze_suspect_patterns(suspects)

    acls = []
    if not args.skip_acl_check:
        acls = check_replication_acls()

    report = generate_report(events, replication_events, suspects, legitimate, patterns, acls)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)

    if suspects:
        logger.warning("ALERT: %d suspected DCSync events from %d accounts",
                        len(suspects), len(patterns))
    else:
        logger.info("No DCSync suspects found (%d legitimate replication events)", len(legitimate))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
