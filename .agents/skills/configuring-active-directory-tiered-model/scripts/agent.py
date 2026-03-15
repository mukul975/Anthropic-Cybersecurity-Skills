#!/usr/bin/env python3
"""Active Directory tiered administration model audit agent using ldap3."""

import json
import sys
import argparse
from datetime import datetime

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM
except ImportError:
    print("Install: pip install ldap3")
    sys.exit(1)


TIER_DEFINITIONS = {
    "Tier 0": {
        "description": "Domain controllers, AD admin accounts, PKI, ADFS",
        "groups": ["Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Administrators", "Account Operators", "Backup Operators"],
    },
    "Tier 1": {
        "description": "Member servers, server admin accounts, applications",
        "groups": ["Server Operators", "Print Operators"],
    },
    "Tier 2": {
        "description": "Workstations, standard user accounts, help desk",
        "groups": ["Help Desk", "Workstation Admins"],
    },
}


def audit_tier0_accounts(conn, base_dn):
    """Audit Tier 0 privileged accounts."""
    findings = []
    for group_name in TIER_DEFINITIONS["Tier 0"]["groups"]:
        conn.search(base_dn, f"(&(objectClass=group)(cn={group_name}))",
                     attributes=["member"])
        for entry in conn.entries:
            members = entry.member.values if hasattr(entry.member, 'values') else []
            for member_dn in members:
                conn.search(member_dn, "(objectClass=*)",
                            attributes=["sAMAccountName", "lastLogonTimestamp",
                                        "userAccountControl", "adminCount"])
                for user in conn.entries:
                    uac = int(str(user.userAccountControl)) if hasattr(user, 'userAccountControl') else 0
                    findings.append({
                        "account": str(user.sAMAccountName),
                        "group": group_name,
                        "tier": "Tier 0",
                        "password_never_expires": bool(uac & 0x10000),
                        "account_disabled": bool(uac & 0x2),
                        "admin_count": True,
                    })
    return findings


def check_tier_violations(conn, base_dn):
    """Check for cross-tier privilege violations."""
    violations = []
    conn.search(base_dn,
                "(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "memberOf", "lastLogon"])
    for entry in conn.entries:
        groups = entry.memberOf.values if hasattr(entry.memberOf, 'values') else []
        tier0 = any("Domain Admins" in str(g) or "Enterprise Admins" in str(g) for g in groups)
        tier1 = any("Server" in str(g) for g in groups)
        if tier0 and tier1:
            violations.append({
                "account": str(entry.sAMAccountName),
                "violation": "Account spans Tier 0 and Tier 1",
                "severity": "CRITICAL",
                "recommendation": "Create separate accounts per tier",
            })
    return violations


def check_paw_compliance(conn, base_dn):
    """Check for Privileged Access Workstation (PAW) deployment indicators."""
    conn.search(base_dn,
                "(&(objectClass=computer)(cn=PAW*))",
                attributes=["cn", "operatingSystem", "lastLogonTimestamp"])
    paws = [{"name": str(e.cn), "os": str(e.operatingSystem)} for e in conn.entries]
    return {
        "paw_count": len(paws),
        "paws": paws,
        "compliant": len(paws) > 0,
        "recommendation": "Deploy PAWs for all Tier 0 admin accounts" if not paws else "PAWs detected",
    }


def run_audit(server_ip, domain, username, password):
    """Execute AD tiered model audit."""
    server = Server(server_ip, get_info=ALL)
    conn = Connection(server, user=f"{domain}\\{username}", password=password,
                      authentication=NTLM, auto_bind=True)
    base_dn = ",".join([f"DC={p}" for p in domain.split(".")])

    print(f"\n{'='*60}")
    print(f"  AD TIERED ADMINISTRATION MODEL AUDIT")
    print(f"  Domain: {domain}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    accounts = audit_tier0_accounts(conn, base_dn)
    print(f"--- TIER 0 ACCOUNTS ({len(accounts)}) ---")
    for a in accounts[:15]:
        flags = []
        if a["password_never_expires"]:
            flags.append("PWD_NEVER_EXPIRES")
        print(f"  {a['account']} in {a['group']} {' '.join(flags)}")

    violations = check_tier_violations(conn, base_dn)
    print(f"\n--- TIER VIOLATIONS ({len(violations)}) ---")
    for v in violations:
        print(f"  [{v['severity']}] {v['account']}: {v['violation']}")

    paw = check_paw_compliance(conn, base_dn)
    print(f"\n--- PAW COMPLIANCE ---")
    print(f"  PAWs found: {paw['paw_count']}")
    print(f"  Compliant: {paw['compliant']}")

    conn.unbind()
    return {"tier0_accounts": accounts, "violations": violations, "paw": paw}


def main():
    parser = argparse.ArgumentParser(description="AD Tiered Model Audit Agent")
    parser.add_argument("--server", required=True, help="Domain controller IP")
    parser.add_argument("--domain", required=True, help="AD domain name")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.server, args.domain, args.username, args.password)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
