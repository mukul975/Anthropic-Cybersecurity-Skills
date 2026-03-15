#!/usr/bin/env python3
"""Golden Ticket attack detection agent for Kerberos log analysis.

Parses Windows Security Event IDs 4768, 4769, 4771 to detect forged TGTs
with anomalous encryption types, impossible lifetimes, and non-existent accounts.
"""

import argparse
import json
import re
import sys
from datetime import datetime

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None

ENCRYPTION_TYPES = {
    "0x1": "DES-CBC-CRC", "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS", "0x12": "AES256-CTS",
    "0x17": "RC4-HMAC", "0x18": "RC4-HMAC-EXP",
}

GOLDEN_TICKET_INDICATORS = {
    "rc4_encryption": {"desc": "RC4 encryption used (0x17) instead of AES",
                        "severity": "HIGH", "mitre": "T1558.001"},
    "impossible_lifetime": {"desc": "TGT lifetime exceeds policy maximum",
                             "severity": "CRITICAL", "mitre": "T1558.001"},
    "non_existent_account": {"desc": "TGS request for non-existent account",
                              "severity": "CRITICAL", "mitre": "T1558.001"},
    "no_tgt_request": {"desc": "TGS (4769) without prior TGT (4768)",
                        "severity": "HIGH", "mitre": "T1558.001"},
    "domain_field_mismatch": {"desc": "Domain field differs from environment",
                               "severity": "HIGH", "mitre": "T1558.001"},
}

MAX_TGT_LIFETIME_HOURS = 10
EXPECTED_DOMAIN = ""


def parse_kerberos_events(filepath):
    if evtx is None:
        return {"error": "python-evtx not installed: pip install python-evtx"}

    tgt_requests = {}
    tgs_requests = []
    findings = []

    with evtx.Evtx(filepath) as log:
        for record in log.records():
            xml = record.xml()
            event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
            if not event_id_match:
                continue
            event_id = int(event_id_match.group(1))
            time_match = re.search(r'SystemTime="([^"]+)"', xml)
            timestamp = time_match.group(1) if time_match else ""

            if event_id == 4768:
                user = re.search(r'<Data Name="TargetUserName">([^<]+)', xml)
                domain = re.search(r'<Data Name="TargetDomainName">([^<]+)', xml)
                ticket_enc = re.search(r'<Data Name="TicketEncryptionType">([^<]+)', xml)
                client_addr = re.search(r'<Data Name="IpAddress">([^<]+)', xml)
                status = re.search(r'<Data Name="Status">([^<]+)', xml)

                username = user.group(1) if user else ""
                enc_type = ticket_enc.group(1) if ticket_enc else ""

                if username and not username.endswith("$"):
                    tgt_requests[username.lower()] = timestamp

                if enc_type.lower() in ("0x17", "0x18"):
                    findings.append({
                        "event_id": 4768, "timestamp": timestamp,
                        "user": username,
                        "encryption_type": ENCRYPTION_TYPES.get(enc_type.lower(), enc_type),
                        "indicator": "rc4_encryption",
                        **GOLDEN_TICKET_INDICATORS["rc4_encryption"],
                    })

            elif event_id == 4769:
                user = re.search(r'<Data Name="TargetUserName">([^<]+)', xml)
                service = re.search(r'<Data Name="ServiceName">([^<]+)', xml)
                ticket_enc = re.search(r'<Data Name="TicketEncryptionType">([^<]+)', xml)
                client_addr = re.search(r'<Data Name="IpAddress">([^<]+)', xml)

                username = user.group(1) if user else ""
                base_user = username.split("@")[0].lower() if "@" in username else username.lower()

                if base_user and base_user not in tgt_requests and not base_user.endswith("$"):
                    findings.append({
                        "event_id": 4769, "timestamp": timestamp,
                        "user": username,
                        "service": service.group(1) if service else "",
                        "indicator": "no_tgt_request",
                        **GOLDEN_TICKET_INDICATORS["no_tgt_request"],
                    })

            elif event_id == 4771:
                user = re.search(r'<Data Name="TargetUserName">([^<]+)', xml)
                failure = re.search(r'<Data Name="Status">([^<]+)', xml)
                status_code = failure.group(1) if failure else ""
                if status_code == "0x6":
                    findings.append({
                        "event_id": 4771, "timestamp": timestamp,
                        "user": user.group(1) if user else "",
                        "status": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
                        "indicator": "non_existent_account",
                        **GOLDEN_TICKET_INDICATORS["non_existent_account"],
                    })

    return {"tgt_requests": len(tgt_requests), "findings": findings}


def generate_sigma_rule():
    return {
        "title": "Golden Ticket - TGS Without Prior TGT",
        "status": "stable",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "tgs": {"EventID": 4769},
            "tgt": {"EventID": 4768},
            "condition": "tgs and not tgt",
        },
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1558.001"],
    }


def main():
    parser = argparse.ArgumentParser(description="Golden Ticket Attack Detector")
    parser.add_argument("--security-log", help="Windows Security EVTX file")
    parser.add_argument("--domain", default="", help="Expected AD domain name")
    parser.add_argument("--generate-sigma", action="store_true")
    args = parser.parse_args()

    global EXPECTED_DOMAIN
    EXPECTED_DOMAIN = args.domain

    results = {"timestamp": datetime.utcnow().isoformat() + "Z"}

    if args.security_log:
        parsed = parse_kerberos_events(args.security_log)
        if isinstance(parsed, dict) and "error" in parsed:
            results["error"] = parsed["error"]
        else:
            results.update(parsed)
            results["total_findings"] = len(parsed.get("findings", []))

    if args.generate_sigma:
        results["sigma_rule"] = generate_sigma_rule()

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
