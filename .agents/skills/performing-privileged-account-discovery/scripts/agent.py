#!/usr/bin/env python3
"""Privileged Account Discovery agent — enumerates privileged accounts across
Active Directory using ldap3 and flags shadow admin paths."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from ldap3 import Server, Connection, ALL, SUBTREE
except ImportError:
    print("Install ldap3: pip install ldap3", file=sys.stderr)
    sys.exit(1)


PRIVILEGED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "DnsAdmins",
]


def connect_ldap(server_url: str, username: str, password: str, use_ssl: bool = True) -> Connection:
    """Establish LDAP connection."""
    srv = Server(server_url, get_info=ALL, use_ssl=use_ssl)
    conn = Connection(srv, user=username, password=password, auto_bind=True)
    return conn


def get_domain_dn(conn: Connection) -> str:
    """Extract domain distinguished name from RootDSE."""
    return conn.server.info.other.get("defaultNamingContext", [""])[0]


def enumerate_privileged_groups(conn: Connection, base_dn: str) -> list[dict]:
    """Find all privileged group memberships recursively."""
    results = []
    for group_name in PRIVILEGED_GROUPS:
        search_filter = f"(&(objectClass=group)(cn={group_name}))"
        conn.search(base_dn, search_filter, search_scope=SUBTREE,
                    attributes=["cn", "member", "distinguishedName"])
        for entry in conn.entries:
            members = entry.member.values if hasattr(entry.member, "values") else []
            results.append({
                "group": str(entry.cn),
                "dn": str(entry.distinguishedName),
                "member_count": len(members),
                "members": [str(m) for m in members],
            })
    return results


def find_nested_memberships(conn: Connection, base_dn: str, group_dn: str) -> list[str]:
    """Resolve nested group memberships using LDAP_MATCHING_RULE_IN_CHAIN."""
    search_filter = f"(memberOf:1.2.840.113556.1.4.1941:={group_dn})"
    conn.search(base_dn, search_filter, search_scope=SUBTREE,
                attributes=["sAMAccountName", "objectClass"])
    return [str(e.sAMAccountName) for e in conn.entries]


def find_service_accounts(conn: Connection, base_dn: str) -> list[dict]:
    """Discover service accounts via servicePrincipalName."""
    search_filter = "(&(objectClass=user)(servicePrincipalName=*))"
    conn.search(base_dn, search_filter, search_scope=SUBTREE,
                attributes=["sAMAccountName", "servicePrincipalName",
                             "adminCount", "whenChanged", "userAccountControl"])
    accounts = []
    for entry in conn.entries:
        uac = int(str(entry.userAccountControl)) if hasattr(entry, "userAccountControl") else 0
        accounts.append({
            "username": str(entry.sAMAccountName),
            "spns": [str(s) for s in entry.servicePrincipalName.values],
            "admin_count": str(entry.adminCount) if hasattr(entry, "adminCount") else "0",
            "password_never_expires": bool(uac & 0x10000),
            "last_changed": str(entry.whenChanged),
        })
    return accounts


def find_admin_count_users(conn: Connection, base_dn: str) -> list[str]:
    """Find users with adminCount=1 (shadow admins or orphaned flags)."""
    search_filter = "(&(objectClass=user)(adminCount=1))"
    conn.search(base_dn, search_filter, search_scope=SUBTREE,
                attributes=["sAMAccountName"])
    return [str(e.sAMAccountName) for e in conn.entries]


def generate_report(server_url: str, username: str, password: str, use_ssl: bool) -> dict:
    """Run full privileged account discovery and build JSON report."""
    conn = connect_ldap(server_url, username, password, use_ssl)
    base_dn = get_domain_dn(conn)

    priv_groups = enumerate_privileged_groups(conn, base_dn)
    svc_accounts = find_service_accounts(conn, base_dn)
    admin_count_users = find_admin_count_users(conn, base_dn)
    total_priv = sum(g["member_count"] for g in priv_groups)

    conn.unbind()
    return {
        "report": "privileged_account_discovery",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "domain": base_dn,
        "privileged_groups": priv_groups,
        "total_privileged_members": total_priv,
        "service_accounts": svc_accounts,
        "admin_count_users": admin_count_users,
        "summary": {
            "privileged_groups_found": len(priv_groups),
            "service_accounts": len(svc_accounts),
            "admin_count_flagged_users": len(admin_count_users),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Privileged Account Discovery Agent")
    parser.add_argument("--server", required=True, help="LDAP server URL (ldaps://dc.example.com)")
    parser.add_argument("--username", required=True, help="Bind DN or UPN")
    parser.add_argument("--password", required=True, help="Bind password")
    parser.add_argument("--no-ssl", action="store_true", help="Disable SSL")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.server, args.username, args.password, not args.no_ssl)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
