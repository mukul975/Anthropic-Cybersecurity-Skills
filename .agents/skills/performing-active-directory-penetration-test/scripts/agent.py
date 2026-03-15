#!/usr/bin/env python3
"""Active Directory Penetration Test agent - automates AD enumeration using
ldap3 for LDAP queries, subprocess for impacket tools, and generates a
structured pentest findings report."""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    from ldap3 import Server, Connection, ALL, SUBTREE
except ImportError:
    print("Install ldap3: pip install ldap3", file=sys.stderr)
    sys.exit(1)


def connect_ldap(server_url: str, username: str, password: str, use_ssl: bool = True) -> Connection:
    """Establish authenticated LDAP connection."""
    srv = Server(server_url, get_info=ALL, use_ssl=use_ssl)
    conn = Connection(srv, user=username, password=password, auto_bind=True)
    return conn


def get_domain_info(conn: Connection) -> dict:
    """Extract domain functional level and naming context."""
    info = conn.server.info
    return {
        "default_naming_context": info.other.get("defaultNamingContext", [""])[0],
        "forest_functionality": info.other.get("forestFunctionality", [""])[0],
        "domain_functionality": info.other.get("domainFunctionality", [""])[0],
    }


def enumerate_users(conn: Connection, base_dn: str) -> list[dict]:
    """Enumerate all domain users with security-relevant attributes."""
    conn.search(base_dn, "(&(objectClass=user)(objectCategory=person))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "userAccountControl", "adminCount",
                             "pwdLastSet", "lastLogon", "servicePrincipalName",
                             "memberOf", "description"])
    users = []
    for entry in conn.entries:
        uac = int(str(entry.userAccountControl)) if hasattr(entry, "userAccountControl") else 0
        users.append({
            "username": str(entry.sAMAccountName),
            "admin_count": str(entry.adminCount) if hasattr(entry, "adminCount") else "0",
            "password_not_required": bool(uac & 0x0020),
            "password_never_expires": bool(uac & 0x10000),
            "account_disabled": bool(uac & 0x0002),
            "kerberos_preauth_not_required": bool(uac & 0x400000),
            "has_spn": bool(entry.servicePrincipalName),
            "description": str(entry.description) if hasattr(entry, "description") else "",
        })
    return users


def find_asrep_roastable(users: list[dict]) -> list[dict]:
    """Identify accounts vulnerable to AS-REP Roasting."""
    findings = []
    for user in users:
        if user["kerberos_preauth_not_required"] and not user["account_disabled"]:
            findings.append({
                "type": "asrep_roastable",
                "severity": "high",
                "account": user["username"],
                "detail": "Kerberos pre-authentication disabled - AS-REP Roasting possible",
            })
    return findings


def find_kerberoastable(users: list[dict]) -> list[dict]:
    """Identify accounts vulnerable to Kerberoasting."""
    findings = []
    for user in users:
        if user["has_spn"] and not user["account_disabled"]:
            findings.append({
                "type": "kerberoastable",
                "severity": "high",
                "account": user["username"],
                "detail": "User account with SPN set - Kerberoasting possible",
            })
    return findings


def check_password_policy(conn: Connection, base_dn: str) -> list[dict]:
    """Audit domain password policy."""
    conn.search(base_dn, "(objectClass=domain)", search_scope=SUBTREE,
                attributes=["minPwdLength", "lockoutThreshold", "pwdHistoryLength",
                             "maxPwdAge", "minPwdAge", "lockoutDuration"])
    findings = []
    if conn.entries:
        entry = conn.entries[0]
        min_len = int(str(entry.minPwdLength)) if hasattr(entry, "minPwdLength") else 0
        lockout = int(str(entry.lockoutThreshold)) if hasattr(entry, "lockoutThreshold") else 0
        if min_len < 12:
            findings.append({
                "type": "weak_password_policy",
                "severity": "high",
                "detail": f"Minimum password length is {min_len} (recommended: 12+)",
            })
        if lockout == 0:
            findings.append({
                "type": "no_account_lockout",
                "severity": "critical",
                "detail": "No account lockout policy - brute force attacks possible",
            })
    return findings


def run_impacket_getspns(dc_ip: str, domain: str, username: str, password: str) -> dict:
    """Run impacket GetUserSPNs for Kerberoasting."""
    cmd = ["python3", "-m", "impacket.examples.GetUserSPNs",
           f"{domain}/{username}:{password}", "-dc-ip", dc_ip, "-request"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"success": True, "output": result.stdout[:5000], "errors": result.stderr[:1000]}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"success": False, "error": str(e)}


def generate_report(server_url: str, username: str, password: str,
                    use_ssl: bool, dc_ip: str = None) -> dict:
    """Run full AD pentest enumeration and build report."""
    conn = connect_ldap(server_url, username, password, use_ssl)
    domain_info = get_domain_info(conn)
    base_dn = domain_info["default_naming_context"]

    users = enumerate_users(conn, base_dn)
    findings = []
    findings.extend(find_asrep_roastable(users))
    findings.extend(find_kerberoastable(users))
    findings.extend(check_password_policy(conn, base_dn))

    conn.unbind()

    from collections import Counter
    severity_counts = Counter(f["severity"] for f in findings)
    return {
        "report": "ad_penetration_test",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "domain_info": domain_info,
        "total_users": len(users),
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="AD Penetration Test Agent")
    parser.add_argument("--server", required=True, help="LDAP server URL (ldaps://dc.example.com)")
    parser.add_argument("--username", required=True, help="Domain username (DOMAIN\\\\user)")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL")
    parser.add_argument("--dc-ip", help="DC IP for impacket tools")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.server, args.username, args.password,
                             not args.no_ssl, args.dc_ip)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
