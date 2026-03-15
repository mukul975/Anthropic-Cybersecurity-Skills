#!/usr/bin/env python3
"""Agent for assessing and managing GDPR data protection compliance."""

import json
import csv
import argparse
import re
from datetime import datetime, timedelta
from collections import Counter, defaultdict


GDPR_ARTICLES = {
    "Art5": "Principles of processing",
    "Art6": "Lawful basis",
    "Art13": "Information to data subject (direct collection)",
    "Art14": "Information to data subject (indirect collection)",
    "Art15": "Right of access",
    "Art17": "Right to erasure",
    "Art20": "Right to data portability",
    "Art25": "Data protection by design and by default",
    "Art30": "Records of processing activities",
    "Art32": "Security of processing",
    "Art33": "Breach notification (72h to DPA)",
    "Art34": "Breach communication to data subjects",
    "Art35": "Data Protection Impact Assessment",
    "Art44": "Cross-border transfer principles",
}

PII_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone_eu": r"\b\+?[0-9]{1,3}[\s.-]?[0-9]{6,14}\b",
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "date_of_birth": r"\b\d{2}[/.-]\d{2}[/.-]\d{4}\b",
    "national_id": r"\b\d{3}-\d{2}-\d{4}\b",
    "passport": r"\b[A-Z]{1,2}\d{6,9}\b",
}


def scan_for_pii(file_path, max_bytes=1024 * 1024):
    """Scan a file for GDPR-relevant personal data patterns."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(max_bytes)
    except (OSError, PermissionError):
        return None
    matches = {}
    for pii_type, pattern in PII_PATTERNS.items():
        found = re.findall(pattern, content)
        if found:
            matches[pii_type] = len(found)
    if not matches:
        return None
    return {"file": str(file_path), "pii_types": matches,
            "total_matches": sum(matches.values()),
            "category": classify_data_category(matches)}


def classify_data_category(matches):
    """Classify data into GDPR special categories."""
    if any(k in matches for k in ["national_id", "passport"]):
        return "special_category"
    if "iban" in matches:
        return "financial"
    return "standard_personal_data"


def assess_ropa_completeness(ropa_json):
    """Assess Records of Processing Activities (ROPA) completeness per Art 30."""
    with open(ropa_json) as f:
        ropa = json.load(f)
    required_fields = [
        "controller_name", "purposes", "data_categories", "data_subjects",
        "recipients", "transfers", "retention_periods", "security_measures",
    ]
    findings = []
    activities = ropa if isinstance(ropa, list) else ropa.get("activities", [])
    for activity in activities:
        missing = [f for f in required_fields if not activity.get(f)]
        findings.append({
            "activity": activity.get("name", activity.get("purpose", "unknown")),
            "complete": len(missing) == 0,
            "missing_fields": missing,
            "compliance": "COMPLIANT" if not missing else "NON_COMPLIANT",
        })
    total = len(findings)
    compliant = sum(1 for f in findings if f["compliance"] == "COMPLIANT")
    return {
        "activities_assessed": total,
        "compliant": compliant,
        "compliance_rate": round(compliant / total * 100, 1) if total else 0,
        "details": findings,
    }


def assess_dsr_handling(dsr_log_path):
    """Assess Data Subject Request handling compliance."""
    with open(dsr_log_path) as f:
        requests_log = json.load(f)
    dsrs = requests_log if isinstance(requests_log, list) else requests_log.get("requests", [])
    findings = []
    for dsr in dsrs:
        received = datetime.fromisoformat(dsr.get("received_date", "2024-01-01"))
        completed = dsr.get("completed_date")
        if completed:
            completed_dt = datetime.fromisoformat(completed)
            days = (completed_dt - received).days
        else:
            days = (datetime.utcnow() - received).days
        overdue = days > 30  # GDPR requires response within one month
        findings.append({
            "request_id": dsr.get("id", ""),
            "type": dsr.get("type", dsr.get("right", "")),
            "status": dsr.get("status", "pending"),
            "days_elapsed": days,
            "overdue": overdue,
            "severity": "HIGH" if overdue else "INFO",
        })
    overdue_count = sum(1 for f in findings if f["overdue"])
    return {
        "total_requests": len(findings),
        "overdue": overdue_count,
        "by_type": dict(Counter(f["type"] for f in findings)),
        "details": findings,
    }


def assess_breach_notification_readiness(breach_log_path):
    """Assess breach notification compliance (Art 33/34)."""
    with open(breach_log_path) as f:
        breaches = json.load(f)
    breach_list = breaches if isinstance(breaches, list) else breaches.get("breaches", [])
    findings = []
    for breach in breach_list:
        detected = datetime.fromisoformat(breach.get("detected", "2024-01-01"))
        notified = breach.get("dpa_notified")
        if notified:
            notified_dt = datetime.fromisoformat(notified)
            hours = (notified_dt - detected).total_seconds() / 3600
        else:
            hours = None
        compliant = hours is not None and hours <= 72
        findings.append({
            "breach_id": breach.get("id", ""),
            "detected": str(detected),
            "notification_hours": round(hours, 1) if hours else None,
            "art33_compliant": compliant,
            "data_subjects_affected": breach.get("subjects_affected", 0),
            "severity": breach.get("severity", "HIGH"),
        })
    return {"total_breaches": len(findings), "details": findings,
            "art33_compliance_rate": round(
                sum(1 for f in findings if f["art33_compliant"]) / len(findings) * 100, 1
            ) if findings else 0}


def generate_art32_checklist():
    """Generate Article 32 security measures compliance checklist."""
    return {
        "encryption": {
            "data_at_rest": {"required": True, "standard": "AES-256"},
            "data_in_transit": {"required": True, "standard": "TLS 1.2+"},
            "key_management": {"required": True, "standard": "HSM or KMS"},
        },
        "pseudonymization": {
            "tokenization": {"required": True},
            "key_separation": {"required": True},
        },
        "access_controls": {
            "rbac": {"required": True},
            "mfa": {"required": True},
            "least_privilege": {"required": True},
            "access_reviews": {"required": True, "frequency": "quarterly"},
        },
        "resilience": {
            "backup_strategy": {"required": True},
            "disaster_recovery": {"required": True, "rto": "4h", "rpo": "1h"},
            "business_continuity": {"required": True},
        },
        "testing": {
            "penetration_testing": {"required": True, "frequency": "annual"},
            "vulnerability_scanning": {"required": True, "frequency": "monthly"},
            "security_awareness": {"required": True, "frequency": "annual"},
        },
    }


def main():
    parser = argparse.ArgumentParser(description="GDPR Data Protection Agent")
    parser.add_argument("--scan-pii", help="File or directory to scan for PII")
    parser.add_argument("--ropa", help="ROPA JSON file for completeness check")
    parser.add_argument("--dsr-log", help="Data Subject Request log JSON")
    parser.add_argument("--breach-log", help="Breach notification log JSON")
    parser.add_argument("--action", choices=["scan", "ropa", "dsr", "breach",
                                              "art32", "full"], default="full")
    parser.add_argument("--output", default="gdpr_compliance_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("scan", "full") and args.scan_pii:
        result = scan_for_pii(args.scan_pii)
        report["results"]["pii_scan"] = result
        if result:
            print(f"[+] PII found: {result['total_matches']} matches ({result['category']})")
        else:
            print("[+] No PII detected")

    if args.action in ("ropa", "full") and args.ropa:
        result = assess_ropa_completeness(args.ropa)
        report["results"]["ropa"] = result
        print(f"[+] ROPA compliance: {result['compliance_rate']}%")

    if args.action in ("dsr", "full") and args.dsr_log:
        result = assess_dsr_handling(args.dsr_log)
        report["results"]["dsr"] = result
        print(f"[+] DSRs: {result['total_requests']} total, {result['overdue']} overdue")

    if args.action in ("breach", "full") and args.breach_log:
        result = assess_breach_notification_readiness(args.breach_log)
        report["results"]["breach"] = result
        print(f"[+] Art 33 compliance rate: {result['art33_compliance_rate']}%")

    if args.action in ("art32", "full"):
        checklist = generate_art32_checklist()
        report["results"]["art32_checklist"] = checklist
        print("[+] Article 32 security checklist generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
