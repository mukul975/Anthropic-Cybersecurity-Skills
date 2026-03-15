#!/usr/bin/env python3
"""ICS/SCADA anomaly detection agent for industrial control systems."""

import json
import sys
import argparse
import struct
import socket
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


MODBUS_FUNCTION_CODES = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    43: "Read Device Identification",
}

ANOMALOUS_FUNCTION_CODES = {8, 17, 43, 90, 100}


def scan_modbus_device(host, port=502, unit_id=1):
    """Read Modbus device identification and holding registers."""
    if ModbusTcpClient is None:
        return {"error": "Install pymodbus: pip install pymodbus"}
    client = ModbusTcpClient(host, port=port, timeout=10)
    result = {"host": host, "port": port, "unit_id": unit_id}
    try:
        if not client.connect():
            result["error"] = "Connection failed"
            return result
        rr = client.read_holding_registers(0, count=10, slave=unit_id)
        if not rr.isError():
            result["holding_registers_0_9"] = rr.registers
        rr2 = client.read_device_information(slave=unit_id)
        if hasattr(rr2, "information") and not rr2.isError():
            result["device_info"] = {k: v.decode() if isinstance(v, bytes) else v
                                     for k, v in rr2.information.items()}
    except Exception as e:
        result["error"] = str(e)
    finally:
        client.close()
    return result


def analyze_modbus_traffic(pcap_summary):
    """Analyze Modbus traffic patterns for anomalies from parsed PCAP data."""
    findings = []
    for entry in pcap_summary:
        fc = entry.get("function_code", 0)
        if fc in ANOMALOUS_FUNCTION_CODES:
            findings.append({
                "src": entry.get("src_ip", ""),
                "dst": entry.get("dst_ip", ""),
                "function_code": fc,
                "issue": f"Unusual Modbus function code {fc} — potential reconnaissance",
                "severity": "HIGH",
            })
        if entry.get("write_count", 0) > 100:
            findings.append({
                "src": entry.get("src_ip", ""),
                "issue": f"High write frequency ({entry['write_count']} writes) — possible attack",
                "severity": "CRITICAL",
            })
        if entry.get("exception_code"):
            findings.append({
                "src": entry.get("src_ip", ""),
                "issue": f"Modbus exception code {entry['exception_code']} — device error",
                "severity": "MEDIUM",
            })
    return findings


def check_ics_network_segmentation(host, ics_ports=None):
    """Verify ICS network segmentation by testing connectivity to OT ports."""
    if ics_ports is None:
        ics_ports = [502, 102, 44818, 20000, 4840]
    port_names = {502: "Modbus", 102: "S7comm", 44818: "EtherNet/IP",
                  20000: "DNP3", 4840: "OPC-UA"}
    results = []
    for port in ics_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            open_status = sock.connect_ex((host, port)) == 0
            sock.close()
            result = {
                "host": host, "port": port,
                "protocol": port_names.get(port, "unknown"),
                "accessible": open_status,
            }
            if open_status:
                result["finding"] = f"{port_names.get(port, '')} port accessible from IT network"
                result["severity"] = "CRITICAL"
            results.append(result)
        except socket.error:
            pass
    return results


def query_historian_anomalies(historian_url, api_key, tag_name, hours=24):
    """Query process historian for anomalous sensor readings."""
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = requests.get(f"{historian_url}/api/v1/tags/{tag_name}/values",
                            params={"hours": hours}, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json().get("values", [])
        values = [v["value"] for v in data if "value" in v]
        if not values:
            return {"tag": tag_name, "anomalies": []}
        avg = sum(values) / len(values)
        std = (sum((v - avg) ** 2 for v in values) / len(values)) ** 0.5
        anomalies = [v for v in data if abs(v.get("value", avg) - avg) > 3 * std]
        return {"tag": tag_name, "mean": avg, "std_dev": std,
                "total_readings": len(values), "anomalies": len(anomalies)}
    except Exception as e:
        return {"tag": tag_name, "error": str(e)}


def run_audit(args):
    """Execute ICS anomaly detection audit."""
    print(f"\n{'='*60}")
    print(f"  ICS ANOMALY DETECTION AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.modbus_host:
        device = scan_modbus_device(args.modbus_host, args.modbus_port or 502)
        report["modbus_device"] = device
        print(f"--- MODBUS DEVICE SCAN ---")
        print(f"  Host: {device['host']}:{device['port']}")
        if device.get("holding_registers_0_9"):
            print(f"  Registers 0-9: {device['holding_registers_0_9']}")
        if device.get("error"):
            print(f"  Error: {device['error']}")

    if args.scan_host:
        seg_results = check_ics_network_segmentation(args.scan_host)
        report["segmentation_check"] = seg_results
        print(f"\n--- NETWORK SEGMENTATION CHECK ---")
        for r in seg_results:
            status = "ACCESSIBLE" if r["accessible"] else "BLOCKED"
            print(f"  {r['protocol']} (:{r['port']}): {status}")

    return report


def main():
    parser = argparse.ArgumentParser(description="ICS Anomaly Detection Agent")
    parser.add_argument("--modbus-host", help="Modbus device IP to scan")
    parser.add_argument("--modbus-port", type=int, default=502, help="Modbus port")
    parser.add_argument("--scan-host", help="Host to test ICS segmentation")
    parser.add_argument("--historian-url", help="Process historian API URL")
    parser.add_argument("--historian-key", help="Historian API key")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
