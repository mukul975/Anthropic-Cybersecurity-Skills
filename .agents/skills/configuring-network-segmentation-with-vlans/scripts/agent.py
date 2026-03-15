#!/usr/bin/env python3
"""VLAN Network Segmentation Agent - Configures and audits VLAN segmentation on managed switches."""

import json
import logging
import argparse
from datetime import datetime

from netmiko import ConnectHandler
from napalm import get_network_driver

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def connect_netmiko(host, username, password, device_type="cisco_ios"):
    """Establish SSH connection to network device via Netmiko."""
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    conn = ConnectHandler(**device)
    logger.info("Connected to %s (%s)", host, device_type)
    return conn


def get_vlan_config(conn):
    """Retrieve current VLAN configuration from the switch."""
    output = conn.send_command("show vlan brief", use_textfsm=True)
    if isinstance(output, list):
        vlans = []
        for entry in output:
            vlans.append({
                "vlan_id": entry.get("vlan_id", ""),
                "name": entry.get("name", ""),
                "status": entry.get("status", ""),
                "interfaces": entry.get("interfaces", []),
            })
        logger.info("Retrieved %d VLANs", len(vlans))
        return vlans
    return []


def create_vlan(conn, vlan_id, vlan_name):
    """Create a new VLAN on the switch."""
    commands = [
        f"vlan {vlan_id}",
        f"name {vlan_name}",
    ]
    output = conn.send_config_set(commands)
    logger.info("Created VLAN %s (%s)", vlan_id, vlan_name)
    return output


def configure_access_port(conn, interface, vlan_id):
    """Configure a switch port as an access port in a specific VLAN."""
    commands = [
        f"interface {interface}",
        "switchport mode access",
        f"switchport access vlan {vlan_id}",
        "switchport port-security",
        "switchport port-security maximum 2",
        "switchport port-security violation restrict",
        "spanning-tree portfast",
        "spanning-tree bpduguard enable",
    ]
    output = conn.send_config_set(commands)
    logger.info("Configured %s as access port in VLAN %s", interface, vlan_id)
    return output


def configure_trunk_port(conn, interface, allowed_vlans):
    """Configure a switch port as a trunk port with specific allowed VLANs."""
    vlan_list = ",".join(str(v) for v in allowed_vlans)
    commands = [
        f"interface {interface}",
        "switchport mode trunk",
        "switchport trunk encapsulation dot1q",
        f"switchport trunk allowed vlan {vlan_list}",
        "switchport trunk native vlan 999",
        "switchport nonegotiate",
    ]
    output = conn.send_config_set(commands)
    logger.info("Configured %s as trunk with VLANs %s", interface, vlan_list)
    return output


def harden_unused_ports(conn, interfaces):
    """Shut down and assign unused ports to a quarantine VLAN."""
    commands = []
    for iface in interfaces:
        commands.extend([
            f"interface {iface}",
            "switchport mode access",
            "switchport access vlan 999",
            "shutdown",
        ])
    output = conn.send_config_set(commands)
    logger.info("Hardened %d unused ports", len(interfaces))
    return output


def configure_inter_vlan_acl(conn, acl_name, rules):
    """Configure access control lists for inter-VLAN routing."""
    commands = [f"ip access-list extended {acl_name}"]
    for rule in rules:
        commands.append(rule)
    output = conn.send_config_set(commands)
    logger.info("Configured ACL %s with %d rules", acl_name, len(rules))
    return output


def audit_vlan_security(conn):
    """Audit VLAN configuration for common security issues."""
    findings = []
    vlan_output = conn.send_command("show vlan brief")
    if "VLAN0001" in vlan_output:
        trunk_output = conn.send_command("show interfaces trunk")
        if "1" in trunk_output:
            findings.append({
                "check": "Native VLAN",
                "finding": "Default VLAN 1 may be used as native VLAN on trunks",
                "severity": "Medium",
                "remediation": "Change native VLAN to unused VLAN (e.g., 999)",
            })

    port_output = conn.send_command("show interfaces status")
    if "notconnect" in port_output.lower():
        findings.append({
            "check": "Unused Ports",
            "finding": "Ports in notconnect state may not be hardened",
            "severity": "Low",
            "remediation": "Assign to quarantine VLAN and shut down",
        })

    dtp_output = conn.send_command("show dtp")
    if "DESIRABLE" in dtp_output or "AUTO" in dtp_output:
        findings.append({
            "check": "DTP Negotiation",
            "finding": "DTP negotiation enabled - VLAN hopping risk",
            "severity": "High",
            "remediation": "Set all access ports to 'switchport nonegotiate'",
        })

    logger.info("Security audit: %d findings", len(findings))
    return findings


def get_napalm_config(host, username, password, driver="ios"):
    """Retrieve device configuration using NAPALM for multi-vendor support."""
    Driver = get_network_driver(driver)
    device = Driver(host, username, password, timeout=30)
    device.open()
    facts = device.get_facts()
    interfaces = device.get_interfaces()
    vlans = device.get_vlans()
    device.close()
    return {"facts": facts, "interfaces": interfaces, "vlans": vlans}


def generate_report(host, vlans, audit_findings, actions):
    """Generate VLAN segmentation audit report."""
    report = {
        "device": host,
        "timestamp": datetime.utcnow().isoformat(),
        "vlans": vlans,
        "security_findings": audit_findings,
        "configuration_actions": actions,
    }
    print(f"VLAN SEGMENTATION REPORT: {len(vlans)} VLANs, {len(audit_findings)} findings")
    return report


def main():
    parser = argparse.ArgumentParser(description="VLAN Network Segmentation Agent")
    parser.add_argument("--host", required=True, help="Switch management IP")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    parser.add_argument("--audit-only", action="store_true", help="Audit without changes")
    parser.add_argument("--output", default="vlan_report.json")
    args = parser.parse_args()

    conn = connect_netmiko(args.host, args.username, args.password, args.device_type)
    vlans = get_vlan_config(conn)
    findings = audit_vlan_security(conn)

    actions = []
    if not args.audit_only:
        logger.info("Audit-only mode not set - configuration changes require explicit commands")

    report = generate_report(args.host, vlans, findings, actions)
    conn.disconnect()

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
