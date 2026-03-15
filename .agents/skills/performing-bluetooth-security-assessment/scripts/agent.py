#!/usr/bin/env python3
"""BLE security assessment using bleak for device scanning and GATT enumeration."""

import argparse
import asyncio
import json
import sys
import time

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic


SENSITIVE_SERVICE_UUIDS = {
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001808-0000-1000-8000-00805f9b34fb": "Glucose",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
}

SENSITIVE_CHAR_UUIDS = {
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a35-0000-1000-8000-00805f9b34fb": "Blood Pressure Measurement",
    "00002a18-0000-1000-8000-00805f9b34fb": "Glucose Measurement",
    "00002a1c-0000-1000-8000-00805f9b34fb": "Temperature Measurement",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
}

VULNERABLE_DEVICE_PATTERNS = [
    "ITAG", "SmartLock", "BLE_Door", "FitBand", "iTag",
    "CC2541", "HM-10", "JDY-08", "AT-09", "MLT-BT05",
]


async def scan_devices(scan_time: float) -> list:
    devices = await BleakScanner.discover(timeout=scan_time, return_adv=True)
    results = []
    for addr, (device, adv_data) in devices.items():
        name = adv_data.local_name or device.name or "Unknown"
        vuln_match = None
        for pattern in VULNERABLE_DEVICE_PATTERNS:
            if pattern.lower() in name.lower():
                vuln_match = pattern
                break
        results.append({
            "address": str(addr),
            "name": name,
            "rssi": adv_data.rssi,
            "service_uuids": [str(u) for u in (adv_data.service_uuids or [])],
            "manufacturer_data": {str(k): v.hex() for k, v in (adv_data.manufacturer_data or {}).items()},
            "known_vulnerable_pattern": vuln_match,
        })
    results.sort(key=lambda d: d["rssi"], reverse=True)
    return results


async def enumerate_gatt(device_address: str) -> dict:
    findings = []
    services_info = []
    total_chars = 0
    async with BleakClient(device_address, timeout=15.0) as client:
        if not client.is_connected:
            return {"error": f"Failed to connect to {device_address}"}
        for service in client.services:
            svc_uuid = str(service.uuid)
            svc_name = SENSITIVE_SERVICE_UUIDS.get(svc_uuid, service.description or "Unknown")
            is_sensitive_svc = svc_uuid in SENSITIVE_SERVICE_UUIDS
            chars_info = []
            for char in service.characteristics:
                total_chars += 1
                char_uuid = str(char.uuid)
                props = char.properties
                char_name = SENSITIVE_CHAR_UUIDS.get(char_uuid, char.description or "Unknown")
                is_sensitive_char = char_uuid in SENSITIVE_CHAR_UUIDS
                char_entry = {
                    "uuid": char_uuid,
                    "name": char_name,
                    "properties": list(props),
                    "handle": char.handle,
                }
                if is_sensitive_char and ("read" in props):
                    findings.append({
                        "severity": "high",
                        "finding": f"{char_name} readable without encryption",
                        "uuid": char_uuid,
                        "service": svc_name,
                        "properties": list(props),
                        "remediation": "Enable encryption requirement on characteristic",
                    })
                if "write-without-response" in props and is_sensitive_svc:
                    findings.append({
                        "severity": "critical",
                        "finding": f"{char_name} writable without response in sensitive service",
                        "uuid": char_uuid,
                        "service": svc_name,
                        "properties": list(props),
                        "remediation": "Remove write-without-response or require authenticated pairing",
                    })
                if "write" in props and not is_sensitive_svc:
                    findings.append({
                        "severity": "medium",
                        "finding": f"{char_name} writable without known authentication",
                        "uuid": char_uuid,
                        "service": svc_name,
                        "properties": list(props),
                        "remediation": "Verify write access requires bonded connection",
                    })
                chars_info.append(char_entry)
            services_info.append({
                "uuid": svc_uuid,
                "name": svc_name,
                "sensitive": is_sensitive_svc,
                "characteristics": chars_info,
            })
    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    risk_total = sum(severity_weights.get(f["severity"], 0) for f in findings)
    risk_score = min(10.0, round(risk_total / max(len(findings), 1), 1))
    return {
        "services_found": len(services_info),
        "characteristics_found": total_chars,
        "services": services_info,
        "findings": findings,
        "risk_score": risk_score,
    }


async def run_audit(device_address: str, scan_time: float) -> dict:
    scan_results = await scan_devices(scan_time)
    target = None
    for dev in scan_results:
        if dev["address"].upper() == device_address.upper():
            target = dev
            break
    if not target:
        return {"error": f"Device {device_address} not found in scan", "scanned_devices": len(scan_results)}
    gatt_result = await enumerate_gatt(device_address)
    return {
        "assessment_type": "ble_security_audit",
        "target_device": target,
        **gatt_result,
    }


def main():
    parser = argparse.ArgumentParser(description="BLE Security Assessment Tool")
    parser.add_argument("--action", choices=["scan", "enumerate", "audit"],
                        required=True, help="Action to perform")
    parser.add_argument("--scan-time", type=float, default=10.0,
                        help="BLE scan duration in seconds")
    parser.add_argument("--device-address", type=str, default=None,
                        help="Target BLE device address (MAC or UUID)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output JSON file path")
    args = parser.parse_args()

    if args.action in ("enumerate", "audit") and not args.device_address:
        print(json.dumps({"error": "Device address required for enumerate/audit"}))
        sys.exit(1)

    start = time.time()
    if args.action == "scan":
        result = asyncio.run(scan_devices(args.scan_time))
        output = {"action": "scan", "devices_found": len(result), "devices": result}
    elif args.action == "enumerate":
        result = asyncio.run(enumerate_gatt(args.device_address))
        output = {"action": "enumerate", "target": args.device_address, **result}
    elif args.action == "audit":
        output = asyncio.run(run_audit(args.device_address, args.scan_time))

    output["elapsed_seconds"] = round(time.time() - start, 2)
    report = json.dumps(output, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
    print(report)


if __name__ == "__main__":
    main()
