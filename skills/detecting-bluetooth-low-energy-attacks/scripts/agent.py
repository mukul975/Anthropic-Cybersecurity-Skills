#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""BLE Attack Detection Agent - Scans, enumerates, and analyzes Bluetooth Low Energy
devices for security vulnerabilities including weak pairing, replay susceptibility,
insecure GATT permissions, and advertising spoofing."""

import argparse
import asyncio
import json
import logging
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Standard BLE service UUIDs for identification
KNOWN_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001812-0000-1000-8000-00805f9b34fb": "HID (Human Interface Device)",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Firmware Update Service",
    "0000fff0-0000-1000-8000-00805f9b34fb": "Vendor-Specific Control",
}

# Properties that indicate potential security concerns
WRITABLE_PROPS = {"write", "write-without-response"}
READABLE_PROPS = {"read"}
NOTIFY_PROPS = {"notify", "indicate"}


async def scan_ble_devices(scan_duration=10.0):
    """Scan for BLE devices and collect advertising data."""
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.error("bleak not installed: pip install bleak")
        return []

    logger.info("Scanning for BLE devices (%0.1fs)...", scan_duration)
    devices_found = []

    devices = await BleakScanner.discover(timeout=scan_duration, return_adv=True)

    for address, (device, adv_data) in devices.items():
        device_info = {
            "address": address,
            "name": device.name or "Unknown",
            "rssi": adv_data.rssi,
            "service_uuids": adv_data.service_uuids or [],
            "manufacturer_data": {
                str(k): v.hex() for k, v in (adv_data.manufacturer_data or {}).items()
            },
            "service_data": {
                k: v.hex() for k, v in (adv_data.service_data or {}).items()
            },
            "tx_power": adv_data.tx_power,
            "connectable": getattr(adv_data, "connectable", None),
        }
        devices_found.append(device_info)
        logger.info("Found: %s (%s) RSSI: %d dBm", device.name or "Unknown", address, adv_data.rssi)

    logger.info("Scan complete: %d devices found", len(devices_found))
    return devices_found


async def enumerate_gatt_services(target_address, timeout=30.0):
    """Connect to a BLE device and enumerate all GATT services, characteristics, and descriptors."""
    try:
        from bleak import BleakClient
    except ImportError:
        logger.error("bleak not installed: pip install bleak")
        return None

    gatt_profile = {
        "address": target_address,
        "services": [],
        "security_findings": [],
    }

    try:
        async with BleakClient(target_address, timeout=timeout) as client:
            if not client.is_connected:
                logger.error("Failed to connect to %s", target_address)
                return gatt_profile

            logger.info("Connected to %s", target_address)

            for service in client.services:
                svc_name = KNOWN_SERVICES.get(service.uuid, "Custom/Vendor Service")
                service_info = {
                    "uuid": service.uuid,
                    "name": svc_name,
                    "characteristics": [],
                }

                for char in service.characteristics:
                    char_info = {
                        "uuid": char.uuid,
                        "properties": list(char.properties),
                        "handle": char.handle,
                        "descriptors": [],
                        "value": None,
                    }

                    # Read characteristic value if readable
                    if READABLE_PROPS & set(char.properties):
                        try:
                            value = await client.read_gatt_char(char.uuid)
                            char_info["value"] = value.hex()

                            # Check for sensitive data exposure
                            try:
                                decoded = value.decode("utf-8", errors="ignore")
                                if any(kw in decoded.lower() for kw in
                                       ["password", "key", "token", "secret", "admin"]):
                                    gatt_profile["security_findings"].append({
                                        "id": "BLE-GATT-001",
                                        "severity": "High",
                                        "title": "Sensitive Data in Readable Characteristic",
                                        "detail": f"Characteristic {char.uuid} contains potentially "
                                                  f"sensitive data readable without authentication: "
                                                  f"{decoded[:50]}",
                                    })
                            except Exception:
                                pass
                        except Exception as e:
                            char_info["value"] = f"read_error: {e}"

                    # Flag writable characteristics without authentication
                    if WRITABLE_PROPS & set(char.properties):
                        gatt_profile["security_findings"].append({
                            "id": "BLE-GATT-002",
                            "severity": "Medium",
                            "title": "Writable Characteristic Without Authentication",
                            "detail": f"Characteristic {char.uuid} in service {svc_name} "
                                      f"allows write operations ({', '.join(char.properties)}). "
                                      "Verify authentication is enforced at the application layer.",
                        })

                    # Flag write-without-response (no confirmation)
                    if "write-without-response" in char.properties:
                        gatt_profile["security_findings"].append({
                            "id": "BLE-GATT-003",
                            "severity": "Medium",
                            "title": "Write-Without-Response Characteristic",
                            "detail": f"Characteristic {char.uuid} supports write-without-response. "
                                      "Commands sent to this characteristic have no delivery "
                                      "confirmation, making replay attacks harder to detect.",
                        })

                    # Read descriptors
                    for desc in char.descriptors:
                        try:
                            desc_val = await client.read_gatt_descriptor(desc.handle)
                            char_info["descriptors"].append({
                                "uuid": desc.uuid,
                                "handle": desc.handle,
                                "value": desc_val.hex(),
                            })
                        except Exception:
                            char_info["descriptors"].append({
                                "uuid": desc.uuid,
                                "handle": desc.handle,
                                "value": "read_error",
                            })

                    service_info["characteristics"].append(char_info)
                gatt_profile["services"].append(service_info)

            logger.info("Enumerated %d services, %d findings",
                        len(gatt_profile["services"]),
                        len(gatt_profile["security_findings"]))

    except Exception as e:
        logger.error("GATT enumeration failed for %s: %s", target_address, e)
        gatt_profile["error"] = str(e)

    return gatt_profile


async def test_replay_vulnerability(target_address, char_uuid, test_payload_hex, read_after=True):
    """Test if a BLE characteristic is vulnerable to replay attacks."""
    try:
        from bleak import BleakClient
    except ImportError:
        logger.error("bleak not installed: pip install bleak")
        return None

    result = {
        "target": target_address,
        "characteristic": char_uuid,
        "test_payload": test_payload_hex,
        "vulnerable": False,
        "detail": "",
    }

    payload = bytes.fromhex(test_payload_hex)

    try:
        async with BleakClient(target_address, timeout=30) as client:
            if not client.is_connected:
                result["detail"] = "Connection failed"
                return result

            # Read initial state if possible
            initial_value = None
            if read_after:
                try:
                    initial_value = await client.read_gatt_char(char_uuid)
                    logger.info("Initial value: %s", initial_value.hex())
                except Exception:
                    pass

            # Write the captured/test payload
            try:
                await client.write_gatt_char(char_uuid, payload)
                logger.info("Wrote replay payload: %s", test_payload_hex)
            except Exception as e:
                result["detail"] = f"Write rejected: {e}"
                return result

            # Small delay for device to process
            await asyncio.sleep(0.5)

            # Write the same payload again (replay)
            try:
                await client.write_gatt_char(char_uuid, payload)
                logger.info("Replayed same payload successfully")
                result["replay_accepted"] = True
            except Exception as e:
                result["detail"] = f"Replay rejected: {e}"
                result["replay_accepted"] = False
                return result

            # Read final state to check if replay had effect
            if read_after:
                try:
                    final_value = await client.read_gatt_char(char_uuid)
                    logger.info("Final value: %s", final_value.hex())
                    if initial_value and final_value != initial_value:
                        result["vulnerable"] = True
                        result["detail"] = (
                            "Device accepted replayed command and state changed. "
                            "No freshness validation detected."
                        )
                    else:
                        result["detail"] = "Replay accepted but no observable state change."
                        result["vulnerable"] = True  # Still accepted, just no visible effect
                except Exception:
                    result["vulnerable"] = True
                    result["detail"] = "Replay accepted; could not verify state change."
            else:
                result["vulnerable"] = True
                result["detail"] = "Replay payload accepted without error."

    except Exception as e:
        result["detail"] = f"Test failed: {e}"

    return result


async def detect_advertising_spoofing(scan_duration=30.0, known_devices=None):
    """Monitor BLE advertising for spoofing indicators."""
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.error("bleak not installed: pip install bleak")
        return []

    findings = []
    device_history = defaultdict(list)

    logger.info("Monitoring BLE advertising for spoofing (%0.1fs)...", scan_duration)

    def detection_callback(device, advertisement_data):
        key = device.name or device.address
        entry = {
            "address": device.address,
            "rssi": advertisement_data.rssi,
            "timestamp": time.time(),
            "service_uuids": advertisement_data.service_uuids or [],
            "manufacturer_data": {
                str(k): v.hex() for k, v in (advertisement_data.manufacturer_data or {}).items()
            },
        }
        device_history[key].append(entry)

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    await asyncio.sleep(scan_duration)
    await scanner.stop()

    # Analyze for spoofing indicators
    for name, entries in device_history.items():
        addresses = set(e["address"] for e in entries)

        # Multiple addresses with same name (possible spoofing)
        if len(addresses) > 1 and name != "Unknown":
            findings.append({
                "id": "BLE-SPOOF-001",
                "severity": "High",
                "title": "Multiple Addresses for Same Device Name",
                "detail": f"Device '{name}' advertised from {len(addresses)} different "
                          f"addresses: {', '.join(addresses)}. This may indicate address "
                          "spoofing or a cloned device (GATTacker-style MITM).",
                "addresses": list(addresses),
            })

        # Check for known device impersonation
        if known_devices:
            for entry in entries:
                if entry["address"] not in known_devices and name in known_devices.values():
                    findings.append({
                        "id": "BLE-SPOOF-002",
                        "severity": "Critical",
                        "title": "Known Device Name from Unknown Address",
                        "detail": f"Device '{name}' is advertising from unknown address "
                                  f"{entry['address']}. Expected address for this device "
                                  f"is in the known device list. Possible impersonation.",
                    })

        # Rapid RSSI fluctuations (possible relay attack)
        if len(entries) >= 5:
            rssi_values = [e["rssi"] for e in entries]
            rssi_range = max(rssi_values) - min(rssi_values)
            if rssi_range > 40:
                findings.append({
                    "id": "BLE-SPOOF-003",
                    "severity": "Medium",
                    "title": "Abnormal RSSI Fluctuation",
                    "detail": f"Device '{name}' ({entries[0]['address']}) shows RSSI range "
                              f"of {rssi_range} dBm (min: {min(rssi_values)}, max: "
                              f"{max(rssi_values)}). Large fluctuations may indicate a "
                              "relay attack or signal amplification.",
                })

    logger.info("Spoofing detection complete: %d findings", len(findings))
    return findings


def analyze_pcap_for_ble_attacks(pcap_path):
    """Analyze a BLE packet capture file for attack indicators using tshark."""
    findings = []

    if not Path(pcap_path).exists():
        logger.error("PCAP file not found: %s", pcap_path)
        return findings

    # Check for Legacy Pairing (vulnerable to crackle)
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y", "btsmp.opcode == 0x01",
             "-T", "fields", "-e", "btsmp.io_capability", "-e", "btsmp.auth_req"],
            capture_output=True, text=True, timeout=60,
        )
        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            for line in lines:
                parts = line.split("\t")
                io_cap = parts[0] if len(parts) > 0 else ""
                auth_req = parts[1] if len(parts) > 1 else ""

                # io_capability 0x03 = NoInputNoOutput (Just Works)
                if io_cap == "0x03" or io_cap == "3":
                    findings.append({
                        "id": "BLE-PAIR-001",
                        "severity": "Critical",
                        "title": "BLE Just Works Pairing Detected",
                        "detail": "Pairing exchange uses NoInputNoOutput IO capability "
                                  "(Just Works). TK=0, trivially crackable with crackle. "
                                  "No MITM protection.",
                    })

                # Check if Secure Connections flag is not set
                if auth_req and not (int(auth_req, 0) & 0x08):
                    findings.append({
                        "id": "BLE-PAIR-002",
                        "severity": "High",
                        "title": "BLE Legacy Pairing (No Secure Connections)",
                        "detail": "Pairing uses Legacy Pairing without SC flag. "
                                  "Vulnerable to passive eavesdropping and LTK recovery "
                                  "via crackle tool.",
                    })
    except FileNotFoundError:
        logger.warning("tshark not found; skipping pcap pairing analysis")
    except subprocess.TimeoutExpired:
        logger.warning("tshark analysis timed out")

    # Count unique connection events
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_path, "-Y",
             "btle.advertising_header.pdu_type == 0x05",
             "-T", "fields", "-e", "btle.master_bd_addr", "-e", "btle.slave_bd_addr"],
            capture_output=True, text=True, timeout=60,
        )
        if result.stdout.strip():
            connections = result.stdout.strip().split("\n")
            unique_pairs = set()
            for conn in connections:
                unique_pairs.add(conn.strip())

            findings.append({
                "id": "BLE-PCAP-001",
                "severity": "Informational",
                "title": "BLE Connection Events Summary",
                "detail": f"Captured {len(connections)} connection requests across "
                          f"{len(unique_pairs)} unique device pairs.",
            })

            # Multiple rapid connections to same device (possible attack)
            if len(connections) > 10 and len(unique_pairs) < 3:
                findings.append({
                    "id": "BLE-PCAP-002",
                    "severity": "Medium",
                    "title": "Excessive Connection Attempts",
                    "detail": f"{len(connections)} connection attempts to "
                              f"{len(unique_pairs)} devices. May indicate brute-force "
                              "pairing or denial-of-service attack.",
                })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Attempt crackle analysis
    try:
        result = subprocess.run(
            ["crackle", "-i", pcap_path],
            capture_output=True, text=True, timeout=120,
        )
        if "LTK" in result.stdout or "key" in result.stdout.lower():
            findings.append({
                "id": "BLE-CRACK-001",
                "severity": "Critical",
                "title": "BLE Encryption Key Recovered",
                "detail": f"crackle successfully recovered encryption key from captured "
                          f"pairing exchange. Encrypted traffic can be decrypted. "
                          f"Output: {result.stdout[:200]}",
            })
        elif "LE Secure Connections" in result.stdout:
            findings.append({
                "id": "BLE-CRACK-002",
                "severity": "Informational",
                "title": "LE Secure Connections Detected",
                "detail": "Pairing uses LE Secure Connections (ECDH). Not vulnerable "
                          "to crackle-based key recovery.",
            })
    except FileNotFoundError:
        logger.info("crackle not installed; skipping encryption analysis")
    except subprocess.TimeoutExpired:
        logger.warning("crackle analysis timed out")

    logger.info("PCAP analysis complete: %d findings", len(findings))
    return findings


def run_ubertooth_capture(output_path, target_address=None, duration=60, pcap_format="pcapng"):
    """Start a BLE packet capture with Ubertooth One."""
    cmd = ["ubertooth-btle"]

    if target_address:
        cmd.extend(["-f", "-t", target_address])  # Follow mode targeting specific device
    else:
        cmd.append("-p")  # Promiscuous mode

    if pcap_format == "pcapng":
        cmd.extend(["-r", output_path])
    elif pcap_format == "ppi":
        cmd.extend(["-c", output_path])  # PCAP/PPI for crackle compatibility
    else:
        cmd.extend(["-q", output_path])  # PCAP with LE pseudoheader

    logger.info("Starting Ubertooth capture: %s", " ".join(cmd))
    logger.info("Capturing for %d seconds...", duration)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=10)
        logger.info("Capture saved to %s", output_path)
        return True
    except FileNotFoundError:
        logger.error("ubertooth-btle not found. Install: apt install ubertooth")
        return False
    except Exception as e:
        logger.error("Ubertooth capture failed: %s", e)
        return False


def generate_report(scan_results, gatt_profiles, replay_results, spoofing_findings,
                    pcap_findings, output_path):
    """Generate comprehensive BLE security assessment report."""
    all_findings = []

    # Collect GATT findings
    for profile in gatt_profiles:
        all_findings.extend(profile.get("security_findings", []))

    # Collect other findings
    for result in replay_results:
        if result and result.get("vulnerable"):
            all_findings.append({
                "id": "BLE-REPLAY-001",
                "severity": "Critical",
                "title": "Replay Attack Vulnerability",
                "detail": f"Device {result['target']} characteristic {result['characteristic']} "
                          f"is vulnerable to replay attacks. {result.get('detail', '')}",
            })

    all_findings.extend(spoofing_findings)
    all_findings.extend(pcap_findings)

    critical = [f for f in all_findings if f.get("severity") == "Critical"]
    high = [f for f in all_findings if f.get("severity") == "High"]
    medium = [f for f in all_findings if f.get("severity") == "Medium"]

    report = {
        "assessment": "BLE Security Assessment",
        "timestamp": datetime.utcnow().isoformat(),
        "devices_scanned": len(scan_results),
        "devices_enumerated": len(gatt_profiles),
        "summary": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "informational": len(all_findings) - len(critical) - len(high) - len(medium),
        },
        "scan_results": scan_results,
        "gatt_profiles": gatt_profiles,
        "replay_tests": replay_results,
        "findings": all_findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s (%d findings)", output_path, len(all_findings))
    return report


def main():
    parser = argparse.ArgumentParser(description="BLE Attack Detection Agent")
    parser.add_argument("--mode", choices=["scan", "enumerate", "replay", "monitor",
                                           "analyze", "full"],
                        default="scan", help="Operating mode")
    parser.add_argument("--target", help="Target BLE device address (AA:BB:CC:DD:EE:FF)")
    parser.add_argument("--scan-duration", type=float, default=10.0,
                        help="BLE scan duration in seconds (default: 10)")
    parser.add_argument("--char-uuid", help="Target GATT characteristic UUID for replay test")
    parser.add_argument("--replay-payload", help="Hex payload for replay test (e.g., 0102030405)")
    parser.add_argument("--pcap", help="Path to BLE pcap/pcapng file for analysis")
    parser.add_argument("--ubertooth-capture", type=int, default=0,
                        help="Capture with Ubertooth for N seconds (0=disabled)")
    parser.add_argument("--pcap-format", choices=["pcapng", "ppi", "le"],
                        default="pcapng", help="Ubertooth capture format")
    parser.add_argument("--known-devices", help="JSON file mapping known device addresses to names")
    parser.add_argument("--output", default="ble_security_report.json",
                        help="Output report file path")
    args = parser.parse_args()

    scan_results = []
    gatt_profiles = []
    replay_results = []
    spoofing_findings = []
    pcap_findings = []

    # Load known devices for spoofing detection
    known_devices = None
    if args.known_devices:
        try:
            with open(args.known_devices) as f:
                known_devices = json.load(f)
        except Exception as e:
            logger.warning("Could not load known devices: %s", e)

    # Ubertooth capture
    if args.ubertooth_capture > 0:
        capture_path = args.pcap or "ubertooth_capture.pcapng"
        run_ubertooth_capture(capture_path, args.target, args.ubertooth_capture, args.pcap_format)
        if not args.pcap:
            args.pcap = capture_path

    if args.mode in ("scan", "full"):
        scan_results = asyncio.run(scan_ble_devices(args.scan_duration))

    if args.mode in ("enumerate", "full") and args.target:
        profile = asyncio.run(enumerate_gatt_services(args.target))
        if profile:
            gatt_profiles.append(profile)

    if args.mode in ("replay", "full") and args.target and args.char_uuid and args.replay_payload:
        result = asyncio.run(
            test_replay_vulnerability(args.target, args.char_uuid, args.replay_payload)
        )
        if result:
            replay_results.append(result)

    if args.mode in ("monitor", "full"):
        spoofing_findings = asyncio.run(
            detect_advertising_spoofing(args.scan_duration, known_devices)
        )

    if args.mode in ("analyze", "full") and args.pcap:
        pcap_findings = analyze_pcap_for_ble_attacks(args.pcap)

    report = generate_report(scan_results, gatt_profiles, replay_results,
                             spoofing_findings, pcap_findings, args.output)

    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
