#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""Active Directory attack simulation agent using Impacket and ldap3."""

import argparse
import sys
import json
import logging
from datetime import datetime

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants as krb5_constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.smbconnection import SMBConnection
    from impacket import version as impacket_version
    from impacket.dcerpc.v5 import samr, transport
    from impacket.examples.GetUserSPNs import GetUserSPNs
    from impacket.examples.GetNPUsers import GetNPUsers
except ImportError:
    sys.exit("impacket is required: pip install impacket")

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
except ImportError:
    sys.exit("ldap3 is required: pip install ldap3")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def ldap_enum_users(dc_ip: str, domain: str, username: str, password: str) -> list:
    """Enumerate domain users via LDAP, returning accounts with SPNs and no preauth."""
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    server = Server(dc_ip, get_info=ALL, use_ssl=False)
    conn = Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True)

    conn.search(
        base_dn,
        "(objectClass=user)",
        search_scope=SUBTREE,
        attributes=[
            "sAMAccountName", "servicePrincipalName", "userAccountControl",
            "memberOf", "adminCount", "pwdLastSet", "lastLogon",
        ],
    )
    users = []
    for entry in conn.entries:
        uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
        spn_list = list(entry.servicePrincipalName) if entry.servicePrincipalName else []
        no_preauth = bool(uac & 0x400000)
        users.append({
            "samaccountname": str(entry.sAMAccountName),
            "spns": spn_list,
            "no_preauth": no_preauth,
            "admin_count": str(entry.adminCount) if entry.adminCount else "0",
        })
    conn.unbind()
    logger.info("Enumerated %d domain users via LDAP", len(users))
    return users


def find_kerberoastable(users: list) -> list:
    """Filter users with service principal names set (Kerberoastable)."""
    targets = [u for u in users if u["spns"]]
    logger.info("Found %d Kerberoastable accounts", len(targets))
    return targets


def find_asrep_roastable(users: list) -> list:
    """Filter users with Kerberos pre-authentication disabled."""
    targets = [u for u in users if u["no_preauth"]]
    logger.info("Found %d AS-REP roastable accounts", len(targets))
    return targets


def enum_groups(dc_ip: str, domain: str, username: str, password: str) -> dict:
    """Enumerate high-value group memberships via LDAP."""
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    server = Server(dc_ip, get_info=ALL)
    conn = Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True)

    high_value_groups = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Backup Operators", "Account Operators",
    ]
    results = {}
    for group_name in high_value_groups:
        conn.search(
            base_dn,
            f"(&(objectClass=group)(cn={group_name}))",
            attributes=["member"],
        )
        members = []
        if conn.entries:
            members = list(conn.entries[0].member) if conn.entries[0].member else []
        results[group_name] = members
        logger.info("Group '%s' has %d members", group_name, len(members))

    conn.unbind()
    return results


def check_smb_signing(target_ip: str) -> bool:
    """Check if SMB signing is required on the target host."""
    try:
        smb = SMBConnection(target_ip, target_ip, sess_port=445, timeout=5)
        smb.negotiateSession()
        signing = smb.isSigningRequired()
        smb.close()
        return signing
    except Exception as exc:
        logger.warning("SMB connect failed on %s: %s", target_ip, exc)
        return True


def generate_report(users: list, groups: dict, dc_ip: str) -> dict:
    """Compile AD assessment findings into a structured report."""
    kerberoastable = find_kerberoastable(users)
    asrep = find_asrep_roastable(users)
    smb_signing = check_smb_signing(dc_ip)

    report = {
        "assessment_date": datetime.utcnow().isoformat(),
        "total_users": len(users),
        "kerberoastable_accounts": [u["samaccountname"] for u in kerberoastable],
        "asrep_roastable_accounts": [u["samaccountname"] for u in asrep],
        "high_value_groups": {g: len(m) for g, m in groups.items()},
        "dc_smb_signing_required": smb_signing,
        "risk_summary": [],
    }
    if kerberoastable:
        report["risk_summary"].append(
            f"CRITICAL: {len(kerberoastable)} accounts are Kerberoastable"
        )
    if asrep:
        report["risk_summary"].append(
            f"HIGH: {len(asrep)} accounts lack Kerberos pre-authentication"
        )
    if not smb_signing:
        report["risk_summary"].append("HIGH: SMB signing not required on DC - relay attacks possible")
    return report


def main():
    parser = argparse.ArgumentParser(description="AD Attack Simulation Agent")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP")
    parser.add_argument("--domain", required=True, help="Domain FQDN (e.g., corp.local)")
    parser.add_argument("--username", required=True, help="Low-privilege domain username")
    parser.add_argument("--password", required=True, help="Domain user password")
    parser.add_argument("--output", default="ad_assessment.json", help="Output JSON report path")
    args = parser.parse_args()

    logger.info("Starting AD attack simulation against %s", args.domain)
    users = ldap_enum_users(args.dc_ip, args.domain, args.username, args.password)
    groups = enum_groups(args.dc_ip, args.domain, args.username, args.password)
    report = generate_report(users, groups, args.dc_ip)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
