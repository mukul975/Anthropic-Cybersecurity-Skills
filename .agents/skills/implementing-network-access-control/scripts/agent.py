#!/usr/bin/env python3
"""Network Access Control (802.1X/NAC) monitoring agent using RADIUS and SNMP."""

import json
import sys
import argparse
import socket
import struct
from datetime import datetime
from collections import Counter

try:
    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    from pyrad import packet
except ImportError:
    print("Install pyrad: pip install pyrad")
    sys.exit(1)

try:
    from pysnmp.hlapi import (getCmd, nextCmd, SnmpEngine, CommunityData,
                               UdpTransportTarget, ContextData, ObjectType, ObjectIdentity)
    HAS_SNMP = True
except ImportError:
    HAS_SNMP = False


def test_radius_auth(server, secret, username, password, port=1812):
    """Test RADIUS authentication for a user credential pair."""
    srv = Client(server=server, secret=secret.encode(),
                 dict=Dictionary(dict_file=None))
    srv.AuthPort = port
    req = srv.CreateAuthPacket(code=packet.AccessRequest, User_Name=username)
    req["User-Password"] = req.PwCrypt(password)
    req["NAS-IP-Address"] = "192.168.1.1"
    req["NAS-Port-Type"] = "Ethernet"
    req["NAS-Port"] = 1
    try:
        reply = srv.SendPacket(req)
        if reply.code == packet.AccessAccept:
            attrs = {}
            for key in reply.keys():
                attrs[key] = reply[key]
            return {"status": "ACCEPT", "user": username, "attributes": str(attrs)}
        elif reply.code == packet.AccessReject:
            return {"status": "REJECT", "user": username, "reason": "Invalid credentials"}
        elif reply.code == packet.AccessChallenge:
            return {"status": "CHALLENGE", "user": username, "reason": "Additional auth required"}
    except Exception as e:
        return {"status": "ERROR", "user": username, "error": str(e)}


def parse_radius_log(log_file, max_lines=1000):
    """Parse FreeRADIUS log file for authentication events."""
    events = []
    try:
        with open(log_file, "r") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                if "Auth:" in line or "Login" in line:
                    parts = line.strip().split()
                    event = {"raw": line.strip(), "timestamp": " ".join(parts[:3]) if len(parts) > 3 else ""}
                    if "Login OK" in line:
                        event["result"] = "SUCCESS"
                    elif "Login incorrect" in line:
                        event["result"] = "FAILURE"
                    elif "Invalid user" in line:
                        event["result"] = "INVALID_USER"
                    else:
                        event["result"] = "OTHER"
                    events.append(event)
    except FileNotFoundError:
        events.append({"error": f"Log file not found: {log_file}"})
    return events


def check_switch_port_status(switch_ip, community="public"):
    """Query switch via SNMP for 802.1X port authentication status."""
    if not HAS_SNMP:
        return [{"error": "pysnmp not installed. Run: pip install pysnmp"}]

    dot1x_auth_oid = "1.3.6.1.2.1.8802.1.1.1.1.2.1.1.1"
    results = []
    iterator = nextCmd(
        SnmpEngine(), CommunityData(community),
        UdpTransportTarget((switch_ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(dot1x_auth_oid)),
        maxRows=100)

    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication or errorStatus:
            results.append({"error": str(errorIndication or errorStatus)})
            break
        for varBind in varBinds:
            oid, value = varBind
            port_index = str(oid).split(".")[-1]
            auth_states = {1: "initialize", 2: "disconnected", 3: "connecting",
                           4: "authenticating", 5: "authenticated",
                           6: "aborting", 7: "held", 8: "forceAuth", 9: "forceUnauth"}
            results.append({
                "port": port_index,
                "state": auth_states.get(int(value), f"unknown({value})"),
                "state_code": int(value)
            })
    return results


def analyze_auth_events(events):
    """Analyze authentication events for security issues."""
    result_counts = Counter(e.get("result", "UNKNOWN") for e in events)
    total = len(events)
    failures = result_counts.get("FAILURE", 0) + result_counts.get("INVALID_USER", 0)
    success_rate = round((result_counts.get("SUCCESS", 0) / max(total, 1)) * 100, 1)

    analysis = {
        "total_events": total,
        "successes": result_counts.get("SUCCESS", 0),
        "failures": failures,
        "invalid_users": result_counts.get("INVALID_USER", 0),
        "success_rate": success_rate,
        "risk_level": "HIGH" if failures > total * 0.3 else "MEDIUM" if failures > total * 0.1 else "LOW",
    }

    if failures > 20:
        analysis["alert"] = "High number of authentication failures - possible brute force attack"

    return analysis


def generate_nac_policy_check():
    """Generate a NAC compliance policy checklist."""
    policies = [
        {"check": "802.1X enforcement", "requirement": "All access ports configured for dot1x",
         "standard": "PCI-DSS 1.2"},
        {"check": "Guest VLAN isolation", "requirement": "Unauthenticated devices on restricted VLAN",
         "standard": "NIST 800-53 AC-4"},
        {"check": "MAB fallback", "requirement": "MAC Authentication Bypass for non-supplicant devices",
         "standard": "Best Practice"},
        {"check": "EAP-TLS certificates", "requirement": "Certificate-based auth for managed devices",
         "standard": "NIST 800-53 IA-5"},
        {"check": "Posture assessment", "requirement": "Endpoint compliance check before full access",
         "standard": "PCI-DSS 5.3"},
        {"check": "Dynamic VLAN assignment", "requirement": "Role-based VLAN via RADIUS attributes",
         "standard": "NIST 800-53 AC-6"},
        {"check": "Re-authentication timer", "requirement": "Periodic re-auth every 3600 seconds",
         "standard": "Best Practice"},
        {"check": "RADIUS accounting", "requirement": "Accounting enabled for audit trail",
         "standard": "SOC 2 CC6.1"},
    ]
    return policies


def run_nac_audit(radius_log=None, switch_ip=None, community="public"):
    """Run NAC security audit."""
    print(f"\n{'='*60}")
    print(f"  NETWORK ACCESS CONTROL AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    policies = generate_nac_policy_check()
    print(f"--- NAC POLICY CHECKLIST ---")
    for p in policies:
        print(f"  [ ] {p['check']}: {p['requirement']} ({p['standard']})")

    if radius_log:
        events = parse_radius_log(radius_log)
        analysis = analyze_auth_events(events)
        print(f"\n--- RADIUS AUTH ANALYSIS ---")
        print(f"  Total Events:  {analysis['total_events']}")
        print(f"  Successes:     {analysis['successes']}")
        print(f"  Failures:      {analysis['failures']}")
        print(f"  Success Rate:  {analysis['success_rate']}%")
        print(f"  Risk Level:    {analysis['risk_level']}")
        if analysis.get("alert"):
            print(f"  ALERT: {analysis['alert']}")

    if switch_ip:
        ports = check_switch_port_status(switch_ip, community)
        print(f"\n--- SWITCH PORT STATUS ({switch_ip}) ---")
        for p in ports[:20]:
            if "error" in p:
                print(f"  Error: {p['error']}")
            else:
                icon = "[OK]" if p["state"] == "authenticated" else "[!!]"
                print(f"  {icon} Port {p['port']}: {p['state']}")

    print(f"\n{'='*60}\n")
    return {"policies": policies}


def main():
    parser = argparse.ArgumentParser(description="Network Access Control Agent")
    parser.add_argument("--audit", action="store_true", help="Run NAC audit")
    parser.add_argument("--radius-log", help="Path to FreeRADIUS log file")
    parser.add_argument("--switch", help="Switch IP for SNMP 802.1X status check")
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument("--test-auth", nargs=4, metavar=("SERVER", "SECRET", "USER", "PASS"),
                        help="Test RADIUS authentication")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.test_auth:
        result = test_radius_auth(*args.test_auth)
        print(json.dumps(result, indent=2))
    elif args.audit:
        report = run_nac_audit(args.radius_log, args.switch, args.community)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
