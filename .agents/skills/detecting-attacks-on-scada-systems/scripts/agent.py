#!/usr/bin/env python3
"""SCADA system attack detection agent."""

import json
import sys
import argparse
import socket
import struct
from datetime import datetime

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    ModbusTcpClient = None

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


SCADA_PORTS = {
    502: ("Modbus TCP", "CRITICAL"),
    102: ("Siemens S7comm", "CRITICAL"),
    44818: ("EtherNet/IP CIP", "CRITICAL"),
    20000: ("DNP3", "CRITICAL"),
    4840: ("OPC-UA", "HIGH"),
    47808: ("BACnet", "HIGH"),
    2222: ("EtherNet/IP implicit", "HIGH"),
    1089: ("Foundation Fieldbus HSE", "MEDIUM"),
    34962: ("PROFINET RT", "HIGH"),
}


def scan_scada_services(host):
    """Scan for exposed SCADA protocol ports."""
    results = []
    for port, (proto, severity) in SCADA_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            if sock.connect_ex((host, port)) == 0:
                results.append({
                    "host": host, "port": port, "protocol": proto,
                    "accessible": True, "severity": severity,
                    "finding": f"{proto} service exposed on port {port}",
                })
            sock.close()
        except socket.error:
            pass
    return results


def detect_modbus_anomalies(host, port=502, unit_id=1):
    """Detect Modbus protocol anomalies indicating attack."""
    if ModbusTcpClient is None:
        return {"error": "Install pymodbus: pip install pymodbus"}

    client = ModbusTcpClient(host, port=port, timeout=10)
    findings = []
    try:
        if not client.connect():
            return {"error": "Connection failed"}

        rr = client.read_holding_registers(0, count=10, slave=unit_id)
        if not rr.isError():
            findings.append({
                "check": "Read holding registers",
                "status": "accessible",
                "severity": "HIGH" if unit_id == 0 else "MEDIUM",
                "detail": f"Registers 0-9 readable: {rr.registers}",
            })

        for test_unit in [0, 255]:
            rr = client.read_holding_registers(0, count=1, slave=test_unit)
            if not rr.isError():
                findings.append({
                    "check": f"Broadcast unit ID {test_unit}",
                    "status": "accessible",
                    "severity": "CRITICAL",
                    "detail": f"Unit ID {test_unit} responds — broadcast address accessible",
                })

        rr = client.read_coils(0, count=100, slave=unit_id)
        if not rr.isError():
            findings.append({
                "check": "Bulk coil read",
                "status": "accessible",
                "severity": "MEDIUM",
                "detail": f"100 coils readable from address 0",
            })

    except Exception as e:
        findings.append({"check": "error", "detail": str(e)})
    finally:
        client.close()

    return {"host": host, "findings": findings}


def detect_s7comm_access(host, port=102):
    """Test Siemens S7comm accessibility (basic connection test)."""
    result = {"host": host, "port": port, "protocol": "S7comm"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        cotp_cr = bytes([
            0x03, 0x00, 0x00, 0x16,
            0x11, 0xe0, 0x00, 0x00,
            0x00, 0x01, 0x00, 0xc0,
            0x01, 0x0a, 0xc1, 0x02,
            0x01, 0x00, 0xc2, 0x02,
            0x01, 0x02,
        ])
        sock.send(cotp_cr)
        resp = sock.recv(1024)
        sock.close()
        if len(resp) > 0:
            result["accessible"] = True
            result["finding"] = "S7comm COTP connection accepted — PLC accessible"
            result["severity"] = "CRITICAL"
        else:
            result["accessible"] = False
    except Exception as e:
        result["accessible"] = False
        result["error"] = str(e)
    return result


def query_scada_siem(siem_url, api_key, hours=24):
    """Query SIEM for SCADA-related security events."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = requests.get(f"{siem_url}/api/v1/events", headers=headers,
                            params={"category": "scada", "hours": hours}, timeout=15)
        resp.raise_for_status()
        events = resp.json().get("events", [])
        findings = []
        for evt in events:
            if evt.get("severity", 0) >= 7:
                findings.append({
                    "event_id": evt.get("id", ""),
                    "source": evt.get("source_ip", ""),
                    "target": evt.get("dest_ip", ""),
                    "description": evt.get("description", ""),
                    "severity": "CRITICAL" if evt["severity"] >= 9 else "HIGH",
                })
        return findings
    except Exception as e:
        return [{"error": str(e)}]


def run_audit(args):
    """Execute SCADA attack detection audit."""
    print(f"\n{'='*60}")
    print(f"  SCADA SYSTEM ATTACK DETECTION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.host:
        services = scan_scada_services(args.host)
        report["scada_services"] = services
        print(f"--- SCADA SERVICE SCAN ({args.host}) ---")
        if services:
            for s in services:
                print(f"  [{s['severity']}] {s['protocol']} on port {s['port']}")
        else:
            print("  No SCADA ports detected (good segmentation)")

    if args.modbus_host:
        modbus = detect_modbus_anomalies(args.modbus_host, args.modbus_port or 502)
        report["modbus_audit"] = modbus
        print(f"\n--- MODBUS ANOMALY DETECTION ---")
        for f in modbus.get("findings", []):
            print(f"  [{f.get('severity','')}] {f['check']}: {f.get('detail','')[:80]}")

    if args.s7_host:
        s7 = detect_s7comm_access(args.s7_host)
        report["s7comm_check"] = s7
        print(f"\n--- S7COMM ACCESS CHECK ---")
        print(f"  Accessible: {s7.get('accessible', False)}")
        if s7.get("finding"):
            print(f"  [{s7['severity']}] {s7['finding']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="SCADA Attack Detection Agent")
    parser.add_argument("--host", help="SCADA host to scan for services")
    parser.add_argument("--modbus-host", help="Modbus device to audit")
    parser.add_argument("--modbus-port", type=int, default=502)
    parser.add_argument("--s7-host", help="Siemens S7 PLC to check")
    parser.add_argument("--siem-url", help="SIEM API URL for SCADA events")
    parser.add_argument("--siem-key", help="SIEM API key")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
