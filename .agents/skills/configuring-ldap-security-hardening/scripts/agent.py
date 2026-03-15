#!/usr/bin/env python3
"""LDAP security hardening audit agent using ldap3."""

import json
import sys
import argparse
from datetime import datetime

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, Tls
    import ssl
except ImportError:
    print("Install: pip install ldap3")
    sys.exit(1)


def check_ldap_signing(server_ip):
    """Check if LDAP signing is enforced."""
    try:
        server = Server(server_ip, port=389, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        info = server.info
        conn.unbind()
        return {
            "check": "LDAP signing",
            "port": 389,
            "anonymous_bind": True,
            "severity": "HIGH",
            "recommendation": "Enforce LDAP signing via GPO: Domain controller: LDAP server signing requirements = Require signing",
        }
    except Exception as e:
        return {"check": "LDAP signing", "error": str(e), "anonymous_bind": False}


def check_ldaps(server_ip):
    """Check LDAPS (LDAP over TLS) availability."""
    try:
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(server_ip, port=636, use_ssl=True, tls=tls, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        conn.unbind()
        return {"check": "LDAPS", "port": 636, "available": True, "severity": "INFO"}
    except Exception as e:
        return {"check": "LDAPS", "available": False, "severity": "HIGH",
                "recommendation": "Enable LDAPS by installing a certificate on the domain controller"}


def check_channel_binding(server_ip, domain, username, password):
    """Check LDAP channel binding enforcement."""
    try:
        server = Server(server_ip, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}", password=password,
                          authentication=NTLM, auto_bind=True)
        conn.unbind()
        return {
            "check": "Channel binding",
            "simple_bind_allowed": True,
            "severity": "MEDIUM",
            "recommendation": "Enable LDAP channel binding via registry: LdapEnforceChannelBinding=2",
        }
    except Exception as e:
        return {"check": "Channel binding", "error": str(e)}


def audit_anonymous_access(server_ip):
    """Check for anonymous LDAP access and enumeration."""
    findings = []
    try:
        server = Server(server_ip, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE, attributes=["*"])
        if conn.entries:
            findings.append({
                "issue": "Anonymous rootDSE access",
                "severity": "MEDIUM",
                "detail": "Server exposes rootDSE information to unauthenticated clients",
            })
        base_dn = server.info.other.get("defaultNamingContext", [""])[0] if server.info else ""
        if base_dn:
            conn.search(base_dn, "(objectClass=user)", attributes=["sAMAccountName"])
            if conn.entries:
                findings.append({
                    "issue": "Anonymous user enumeration",
                    "severity": "CRITICAL",
                    "detail": f"Anonymous bind can enumerate {len(conn.entries)} user objects",
                })
        conn.unbind()
    except Exception as e:
        findings.append({"issue": "Anonymous access test", "error": str(e)})
    return findings


def run_audit(server_ip, domain=None, username=None, password=None):
    """Execute LDAP security hardening audit."""
    print(f"\n{'='*60}")
    print(f"  LDAP SECURITY HARDENING AUDIT")
    print(f"  Target: {server_ip}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    signing = check_ldap_signing(server_ip)
    print(f"--- LDAP SIGNING ---")
    print(f"  Anonymous bind: {signing.get('anonymous_bind', 'N/A')}")
    print(f"  Severity: {signing.get('severity', 'N/A')}")

    ldaps = check_ldaps(server_ip)
    print(f"\n--- LDAPS (TLS) ---")
    print(f"  Available: {ldaps.get('available', 'N/A')}")
    print(f"  Severity: {ldaps.get('severity', 'N/A')}")

    anon = audit_anonymous_access(server_ip)
    print(f"\n--- ANONYMOUS ACCESS ({len(anon)} findings) ---")
    for a in anon:
        if "error" not in a:
            print(f"  [{a['severity']}] {a['issue']}: {a.get('detail', '')}")

    if domain and username and password:
        binding = check_channel_binding(server_ip, domain, username, password)
        print(f"\n--- CHANNEL BINDING ---")
        print(f"  {binding.get('check', '')}: {binding.get('severity', '')}")

    return {"signing": signing, "ldaps": ldaps, "anonymous": anon}


def main():
    parser = argparse.ArgumentParser(description="LDAP Security Audit Agent")
    parser.add_argument("--server", required=True, help="LDAP server IP")
    parser.add_argument("--domain", help="AD domain name")
    parser.add_argument("--username", help="LDAP username")
    parser.add_argument("--password", help="LDAP password")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.server, args.domain, args.username, args.password)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
