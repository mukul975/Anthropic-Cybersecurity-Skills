#!/usr/bin/env python3
"""Golden Ticket Detection Agent - Detects forged Kerberos TGTs via Event 4624/4672/4768 analysis."""

import json
import logging
import argparse
from collections import defaultdict
from datetime import datetime

from Evtx.Evtx import FileHeader
from lxml import etree

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

ADMIN_PRIVILEGES = [
    "SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege",
    "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
    "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
]


def parse_event_data(root):
    """Extract EventData fields from an EVTX XML record."""
    data = {}
    for elem in root.findall(".//evt:EventData/evt:Data", NS):
        data[elem.get("Name", "")] = elem.text or ""
    time_elem = root.find(".//evt:System/evt:TimeCreated", NS)
    data["_timestamp"] = time_elem.get("SystemTime", "") if time_elem is not None else ""
    return data


def parse_security_events(evtx_path):
    """Parse Event IDs 4624, 4672, and 4768 from Security EVTX."""
    events = {"4624": [], "4672": [], "4768": []}
    target_ids = {"4624", "4672", "4768"}
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                eid_elem = root.find(".//evt:System/evt:EventID", NS)
                if eid_elem is None or eid_elem.text not in target_ids:
                    continue
                data = parse_event_data(root)
                events[eid_elem.text].append(data)
            except Exception:
                continue
    for eid, evts in events.items():
        logger.info("Parsed %d events for Event ID %s", len(evts), eid)
    return events


def detect_orphan_logons(events):
    """Detect Kerberos logons (4624) with no corresponding TGT request (4768)."""
    tgt_accounts = {e.get("TargetUserName", "").lower() for e in events["4768"]}
    orphan_logons = []
    for logon in events["4624"]:
        if logon.get("AuthenticationPackageName", "") == "Kerberos":
            account = logon.get("TargetUserName", "").lower()
            if account and account not in tgt_accounts and not account.endswith("$"):
                orphan_logons.append({
                    "timestamp": logon["_timestamp"],
                    "account": logon.get("TargetUserName", ""),
                    "source_ip": logon.get("IpAddress", ""),
                    "logon_type": logon.get("LogonType", ""),
                    "workstation": logon.get("WorkstationName", ""),
                    "indicator": "Kerberos logon without TGT request (possible golden ticket)",
                })
    logger.info("Found %d orphan Kerberos logons", len(orphan_logons))
    return orphan_logons


def detect_anomalous_privileges(events, known_admins=None):
    """Detect non-admin accounts receiving admin privileges (Event 4672)."""
    if known_admins is None:
        known_admins = set()
    anomalous = []
    for priv_event in events["4672"]:
        account = priv_event.get("SubjectUserName", "")
        privileges = priv_event.get("PrivilegeList", "")
        if account.lower() not in known_admins and not account.endswith("$"):
            admin_privs = [p for p in ADMIN_PRIVILEGES if p in privileges]
            if admin_privs:
                anomalous.append({
                    "timestamp": priv_event["_timestamp"],
                    "account": account,
                    "domain": priv_event.get("SubjectDomainName", ""),
                    "admin_privileges": admin_privs,
                    "indicator": "Non-admin account with admin privileges (golden ticket indicator)",
                })
    logger.info("Found %d anomalous privilege assignments", len(anomalous))
    return anomalous


def detect_abnormal_tgt_patterns(events):
    """Detect TGT requests with abnormal encryption types or patterns."""
    account_tgts = defaultdict(list)
    for tgt in events["4768"]:
        account = tgt.get("TargetUserName", "")
        account_tgts[account].append(tgt)
    anomalies = []
    for account, tgts in account_tgts.items():
        if account.endswith("$"):
            continue
        rc4_tgts = [t for t in tgts if t.get("TicketEncryptionType", "") in ("0x17", "0x18")]
        if rc4_tgts and len(rc4_tgts) > len(tgts) * 0.5:
            anomalies.append({
                "account": account,
                "total_tgts": len(tgts),
                "rc4_tgts": len(rc4_tgts),
                "indicator": "Majority RC4 TGT requests (possible ticket forging)",
            })
    logger.info("Found %d accounts with abnormal TGT patterns", len(anomalies))
    return anomalies


def detect_logon_privilege_correlation(events):
    """Correlate logon events with privilege assignments for timeline analysis."""
    priv_accounts = defaultdict(list)
    for priv in events["4672"]:
        account = priv.get("SubjectUserName", "").lower()
        priv_accounts[account].append(priv["_timestamp"])
    logon_accounts = defaultdict(list)
    for logon in events["4624"]:
        account = logon.get("TargetUserName", "").lower()
        logon_accounts[account].append({
            "timestamp": logon["_timestamp"],
            "source_ip": logon.get("IpAddress", ""),
            "logon_type": logon.get("LogonType", ""),
        })
    correlations = []
    for account in priv_accounts:
        if account in logon_accounts and not account.endswith("$"):
            correlations.append({
                "account": account,
                "privilege_events": len(priv_accounts[account]),
                "logon_events": len(logon_accounts[account]),
                "source_ips": list({l["source_ip"] for l in logon_accounts[account]}),
            })
    return correlations


def generate_report(orphan_logons, priv_anomalies, tgt_anomalies, correlations):
    """Generate golden ticket detection report."""
    total = len(orphan_logons) + len(priv_anomalies) + len(tgt_anomalies)
    severity = "Critical" if orphan_logons and priv_anomalies else "High" if total > 0 else "Low"
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "orphan_kerberos_logons": orphan_logons[:20],
        "anomalous_privilege_assignments": priv_anomalies[:20],
        "abnormal_tgt_patterns": tgt_anomalies,
        "logon_privilege_correlations": correlations[:20],
        "total_indicators": total,
    }
    print(f"GOLDEN TICKET DETECTION: {total} indicators, Severity: {severity}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Golden Ticket Detection Agent")
    parser.add_argument("--evtx-file", required=True, help="Path to Security EVTX file")
    parser.add_argument("--known-admins", nargs="*", default=[], help="Known admin account names")
    parser.add_argument("--output", default="golden_ticket_report.json")
    args = parser.parse_args()

    events = parse_security_events(args.evtx_file)
    known_admins = {a.lower() for a in args.known_admins}
    orphan_logons = detect_orphan_logons(events)
    priv_anomalies = detect_anomalous_privileges(events, known_admins)
    tgt_anomalies = detect_abnormal_tgt_patterns(events)
    correlations = detect_logon_privilege_correlation(events)

    report = generate_report(orphan_logons, priv_anomalies, tgt_anomalies, correlations)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
