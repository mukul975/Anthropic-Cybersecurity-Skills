#!/usr/bin/env python3
"""Agent for AD forest trust enumeration and security assessment using impacket."""

import json
import argparse
from datetime import datetime

try:
    from impacket.dcerpc.v5 import transport, lsat, lsad
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    from impacket.dcerpc.v5.samr import SID_NAME_USE
    from impacket.smbconnection import SMBConnection
except ImportError:
    transport = None

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, SUBTREE
except ImportError:
    ldap3 = None

TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Downlevel (Windows NT)", 2: "Uplevel (Windows 2000+)", 3: "MIT Kerberos", 4: "DCE"}
TRUST_ATTRIBUTES = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN (SID Filtering Enabled)",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
    0x00000080: "USES_RC4_ENCRYPTION",
    0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    0x00000400: "PIM_TRUST",
}


def enumerate_trusts_ldap(dc_host, domain, username, password):
    """Enumerate AD trust relationships via LDAP trustedDomain objects."""
    if not ldap3:
        return {"error": "ldap3 not installed: pip install ldap3"}
    server = Server(dc_host, get_info=ALL, use_ssl=False)
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    conn = Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True)
    conn.search(
        search_base=f"CN=System,{base_dn}",
        search_filter="(objectClass=trustedDomain)",
        search_scope=SUBTREE,
        attributes=[
            "cn", "trustPartner", "trustDirection", "trustType",
            "trustAttributes", "securityIdentifier", "whenCreated",
            "flatName", "trustPosixOffset",
        ],
    )
    trusts = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        direction_val = int(attrs.get("trustDirection", [0])[0])
        type_val = int(attrs.get("trustType", [0])[0])
        attr_val = int(attrs.get("trustAttributes", [0])[0])
        decoded_attrs = []
        for bit, name in TRUST_ATTRIBUTES.items():
            if attr_val & bit:
                decoded_attrs.append(name)
        sid_filtering = bool(attr_val & 0x00000004)
        forest_trust = bool(attr_val & 0x00000008)
        trusts.append({
            "trust_partner": str(attrs.get("trustPartner", [""])[0]),
            "flat_name": str(attrs.get("flatName", [""])[0]),
            "trust_direction": TRUST_DIRECTION.get(direction_val, str(direction_val)),
            "trust_type": TRUST_TYPE.get(type_val, str(type_val)),
            "trust_attributes_raw": attr_val,
            "trust_attributes": decoded_attrs,
            "sid_filtering_enabled": sid_filtering,
            "forest_transitive": forest_trust,
            "when_created": str(attrs.get("whenCreated", [""])[0]),
        })
    conn.unbind()
    return trusts


def enumerate_foreign_principals(dc_host, domain, username, password):
    """Find foreign security principals (cross-forest members) in the domain."""
    if not ldap3:
        return {"error": "ldap3 not installed"}
    server = Server(dc_host, get_info=ALL, use_ssl=False)
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    conn = Connection(server, user=f"{domain}\\{username}", password=password, auto_bind=True)
    conn.search(
        search_base=f"CN=ForeignSecurityPrincipals,{base_dn}",
        search_filter="(objectClass=foreignSecurityPrincipal)",
        search_scope=SUBTREE,
        attributes=["cn", "objectSid", "whenCreated", "memberOf"],
    )
    principals = []
    for entry in conn.entries:
        attrs = entry.entry_attributes_as_dict
        sid = str(attrs.get("cn", [""])[0])
        member_of = [str(g) for g in attrs.get("memberOf", [])]
        principals.append({
            "sid": sid,
            "member_of_groups": member_of,
            "when_created": str(attrs.get("whenCreated", [""])[0]),
            "is_well_known": sid.startswith("S-1-5-") and sid.count("-") == 3,
        })
    conn.unbind()
    custom_principals = [p for p in principals if not p["is_well_known"]]
    return {
        "total_foreign_principals": len(principals),
        "custom_foreign_principals": len(custom_principals),
        "principals": custom_principals[:30],
    }


def lookup_sid_cross_forest(dc_host, domain, username, password, target_sid):
    """Resolve a SID across forest trust using LSA LookupSids RPC call."""
    if not transport:
        return {"error": "impacket not installed: pip install impacket"}
    rpctransport = transport.SMBTransport(dc_host, filename=r"\lsarpc")
    rpctransport.set_credentials(username, password, domain)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsat.MSRPC_UUID_LSAT)
    resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)
    policy_handle = resp["PolicyHandle"]
    try:
        from impacket.dcerpc.v5.dtypes import RPC_SID
        sid = RPC_SID()
        sid.fromCanonical(target_sid)
        resp = lsat.hLsarLookupSids2(dce, policy_handle, [sid])
        names = []
        for item in resp["TranslatedNames"]["Names"]:
            names.append({
                "name": item["Name"],
                "sid_type": SID_NAME_USE.enumItems(item["Use"]).name if hasattr(SID_NAME_USE, 'enumItems') else str(item["Use"]),
                "domain_index": item["DomainIndex"],
            })
        return {"target_sid": target_sid, "resolved_names": names}
    except Exception as e:
        return {"target_sid": target_sid, "error": str(e)}
    finally:
        dce.disconnect()


def assess_trust_risk(trusts, foreign_principals):
    """Assess security risk of trust relationships."""
    findings = []
    for trust in trusts:
        risk = 0
        issues = []
        if not trust.get("sid_filtering_enabled"):
            risk += 40
            issues.append("SID filtering DISABLED — SID history attacks possible")
        if trust.get("trust_direction") == "Bidirectional":
            risk += 15
            issues.append("Bidirectional trust increases attack surface")
        if trust.get("forest_transitive"):
            risk += 10
            issues.append("Forest transitive trust — all domains reachable")
        if "USES_RC4_ENCRYPTION" in trust.get("trust_attributes", []):
            risk += 20
            issues.append("RC4 encryption — vulnerable to trust key cracking")
        risk = min(risk, 100)
        findings.append({
            "trust_partner": trust.get("trust_partner"),
            "risk_score": risk,
            "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
            "issues": issues,
            "recommendation": "Enable SID filtering and migrate to AES encryption"
                if risk >= 50 else "Review trust configuration",
        })
    return findings


def full_audit(dc_host, domain, username, password):
    """Run comprehensive forest trust security audit."""
    trusts = enumerate_trusts_ldap(dc_host, domain, username, password)
    foreign = enumerate_foreign_principals(dc_host, domain, username, password)
    risk = assess_trust_risk(trusts if isinstance(trusts, list) else [], foreign)
    critical = sum(1 for r in risk if r["risk_level"] == "CRITICAL")
    high = sum(1 for r in risk if r["risk_level"] == "HIGH")
    no_sid_filter = sum(1 for t in (trusts if isinstance(trusts, list) else []) if not t.get("sid_filtering_enabled"))
    return {
        "audit_type": "AD Forest Trust Security Assessment",
        "timestamp": datetime.utcnow().isoformat(),
        "domain": domain,
        "summary": {
            "total_trusts": len(trusts) if isinstance(trusts, list) else 0,
            "trusts_without_sid_filtering": no_sid_filter,
            "foreign_principals": foreign.get("custom_foreign_principals", 0),
            "critical_findings": critical,
            "high_findings": high,
        },
        "trusts": trusts,
        "foreign_principals": foreign,
        "risk_assessment": risk,
    }


def main():
    parser = argparse.ArgumentParser(description="AD Forest Trust Security Audit Agent")
    parser.add_argument("--dc", required=True, help="Domain Controller hostname or IP")
    parser.add_argument("--domain", required=True, help="Domain name (e.g., corp.local)")
    parser.add_argument("--username", required=True, help="Domain username")
    parser.add_argument("--password", required=True, help="Domain password")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("trusts", help="Enumerate trust relationships")
    sub.add_parser("foreign", help="List foreign security principals")
    p_sid = sub.add_parser("lookup-sid", help="Cross-forest SID lookup")
    p_sid.add_argument("--sid", required=True, help="Target SID to resolve")
    sub.add_parser("full", help="Full trust security audit")
    args = parser.parse_args()

    if args.command == "trusts":
        result = enumerate_trusts_ldap(args.dc, args.domain, args.username, args.password)
    elif args.command == "foreign":
        result = enumerate_foreign_principals(args.dc, args.domain, args.username, args.password)
    elif args.command == "lookup-sid":
        result = lookup_sid_cross_forest(args.dc, args.domain, args.username, args.password, args.sid)
    elif args.command == "full" or args.command is None:
        result = full_audit(args.dc, args.domain, args.username, args.password)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
