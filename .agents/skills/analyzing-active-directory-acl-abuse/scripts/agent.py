#!/usr/bin/env python3
"""Active Directory ACL abuse detection using ldap3 to find dangerous permissions."""

import argparse
import json
import struct
import sys
from collections import defaultdict

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.protocol.formatters.formatters import format_sid


DANGEROUS_MASKS = {
    "GenericAll": 0x10000000,
    "GenericWrite": 0x40000000,
    "WriteDACL": 0x00040000,
    "WriteOwner": 0x00080000,
    "WriteProperty": 0x00000020,
    "Self": 0x00000008,
    "ExtendedRight": 0x00000100,
    "DeleteChild": 0x00000002,
    "Delete": 0x00010000,
}

ADMIN_SIDS = {
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-9",
}

ADMIN_RID_SUFFIXES = {
    "-500",
    "-512",
    "-516",
    "-518",
    "-519",
    "-498",
}

ATTACK_PATHS = {
    "GenericAll": {
        "user": "Full control allows password reset, Kerberoasting via SPN, or shadow credential attack",
        "group": "Full control allows adding arbitrary members to the group",
        "computer": "Full control allows resource-based constrained delegation attack",
        "organizationalUnit": "Full control allows linking malicious GPO or moving objects",
    },
    "WriteDACL": {
        "user": "Can modify DACL to grant self GenericAll, then reset password",
        "group": "Can modify DACL to grant self write membership, then add self",
        "computer": "Can modify DACL to grant self full control on machine account",
        "organizationalUnit": "Can modify DACL to gain control over OU child objects",
    },
    "WriteOwner": {
        "user": "Can take ownership then modify DACL to escalate privileges",
        "group": "Can take ownership of group then modify membership",
        "computer": "Can take ownership then configure delegation abuse",
        "organizationalUnit": "Can take ownership then control OU policies",
    },
    "GenericWrite": {
        "user": "Can write scriptPath for logon script execution or modify SPN for Kerberoasting",
        "group": "Can modify group attributes including membership",
        "computer": "Can write msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD attack",
        "organizationalUnit": "Can modify OU attributes and link GPO",
    },
}


def is_admin_sid(sid: str, domain_sid: str) -> bool:
    if sid in ADMIN_SIDS:
        return True
    for suffix in ADMIN_RID_SUFFIXES:
        if sid == domain_sid + suffix:
            return True
    return False


def parse_sid(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    revision = raw[0]
    sub_auth_count = raw[1]
    authority = int.from_bytes(raw[2:8], byteorder="big")
    subs = []
    for i in range(sub_auth_count):
        offset = 8 + i * 4
        if offset + 4 > len(raw):
            break
        subs.append(struct.unpack("<I", raw[offset:offset + 4])[0])
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)


def parse_acl(descriptor_bytes: bytes) -> list:
    aces = []
    if len(descriptor_bytes) < 20:
        return aces
    revision = descriptor_bytes[0]
    control = struct.unpack("<H", descriptor_bytes[2:4])[0]
    dacl_offset = struct.unpack("<I", descriptor_bytes[16:20])[0]
    if dacl_offset == 0 or dacl_offset >= len(descriptor_bytes):
        return aces
    dacl = descriptor_bytes[dacl_offset:]
    if len(dacl) < 8:
        return aces
    acl_size = struct.unpack("<H", dacl[2:4])[0]
    ace_count = struct.unpack("<H", dacl[4:6])[0]
    offset = 8
    for _ in range(ace_count):
        if offset + 4 > len(dacl):
            break
        ace_type = dacl[offset]
        ace_flags = dacl[offset + 1]
        ace_size = struct.unpack("<H", dacl[offset + 2:offset + 4])[0]
        if ace_size < 4 or offset + ace_size > len(dacl):
            break
        if ace_type in (0x00, 0x05):
            if offset + 8 <= len(dacl):
                access_mask = struct.unpack("<I", dacl[offset + 4:offset + 8])[0]
                sid_offset = offset + 8
                if ace_type == 0x05:
                    sid_offset = offset + 8 + 32
                if sid_offset < offset + ace_size:
                    sid_bytes = dacl[sid_offset:offset + ace_size]
                    sid_str = parse_sid(sid_bytes)
                    matched_perms = []
                    for perm_name, mask_val in DANGEROUS_MASKS.items():
                        if access_mask & mask_val:
                            matched_perms.append(perm_name)
                    if matched_perms:
                        aces.append({
                            "ace_type": "ACCESS_ALLOWED" if ace_type in (0x00, 0x05) else "OTHER",
                            "access_mask": f"0x{access_mask:08x}",
                            "trustee_sid": sid_str,
                            "permissions": matched_perms,
                        })
        offset += ace_size
    return aces


def resolve_sid(conn: Connection, base_dn: str, sid: str) -> str:
    try:
        conn.search(base_dn, f"(objectSid={sid})", attributes=["sAMAccountName", "cn"])
        if conn.entries:
            entry = conn.entries[0]
            return str(entry.sAMAccountName) if hasattr(entry, "sAMAccountName") else str(entry.cn)
    except Exception:
        pass
    return sid


def get_domain_sid(conn: Connection, base_dn: str) -> str:
    conn.search(base_dn, "(objectClass=domain)", attributes=["objectSid"])
    if conn.entries:
        raw = conn.entries[0].objectSid.raw_values[0]
        return parse_sid(raw)
    return ""


def analyze_acls(dc_ip: str, domain: str, username: str, password: str,
                 target_ou: str) -> dict:
    server = Server(dc_ip, get_info=ALL, use_ssl=False)
    domain_parts = domain.split(".")
    base_dn = ",".join(f"DC={p}" for p in domain_parts)
    search_base = target_ou if target_ou else base_dn
    ntlm_user = f"{domain}\\{username}"

    conn = Connection(server, user=ntlm_user, password=password,
                      authentication=NTLM, auto_bind=True)
    domain_sid = get_domain_sid(conn, base_dn)

    conn.search(
        search_base,
        "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit))",
        search_scope=SUBTREE,
        attributes=["distinguishedName", "sAMAccountName", "objectClass", "nTSecurityDescriptor"],
    )

    findings = []
    objects_scanned = 0
    sid_cache = {}

    for entry in conn.entries:
        objects_scanned += 1
        dn = str(entry.distinguishedName)
        obj_classes = [str(c) for c in entry.objectClass.values] if hasattr(entry, "objectClass") else []
        obj_type = "unknown"
        for oc in obj_classes:
            if oc.lower() in ("user", "group", "computer", "organizationalunit"):
                obj_type = oc.lower()
                break

        if not hasattr(entry, "nTSecurityDescriptor"):
            continue
        raw_sd = entry.nTSecurityDescriptor.raw_values
        if not raw_sd:
            continue
        sd_bytes = raw_sd[0]
        aces = parse_acl(sd_bytes)

        for ace in aces:
            trustee_sid = ace["trustee_sid"]
            if is_admin_sid(trustee_sid, domain_sid):
                continue
            if trustee_sid not in sid_cache:
                sid_cache[trustee_sid] = resolve_sid(conn, base_dn, trustee_sid)
            trustee_name = sid_cache[trustee_sid]

            for perm in ace["permissions"]:
                if perm in ("Delete", "DeleteChild", "Self", "WriteProperty", "ExtendedRight"):
                    severity = "medium"
                else:
                    severity = "critical"
                attack = ATTACK_PATHS.get(perm, {}).get(obj_type,
                         f"{perm} on {obj_type} may allow privilege escalation")
                findings.append({
                    "severity": severity,
                    "target_object": dn,
                    "target_type": obj_type,
                    "trustee": trustee_name,
                    "trustee_sid": trustee_sid,
                    "permission": perm,
                    "access_mask": ace["access_mask"],
                    "ace_type": ace["ace_type"],
                    "attack_path": attack,
                    "remediation": f"Remove {perm} ACE for {trustee_name} on {dn}",
                })

    conn.unbind()
    findings.sort(key=lambda f: 0 if f["severity"] == "critical" else 1)
    return {
        "domain": domain,
        "domain_sid": domain_sid,
        "search_base": search_base,
        "objects_scanned": objects_scanned,
        "dangerous_aces_found": len(findings),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Active Directory ACL Abuse Analyzer")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address")
    parser.add_argument("--domain", required=True, help="AD domain name (e.g., corp.example.com)")
    parser.add_argument("--username", required=True, help="Domain username for LDAP bind")
    parser.add_argument("--password", required=True, help="Domain user password")
    parser.add_argument("--target-ou", default=None,
                        help="Target OU distinguished name to scope the search")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    result = analyze_acls(args.dc_ip, args.domain, args.username,
                          args.password, args.target_ou)
    report = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
    print(report)


if __name__ == "__main__":
    main()
