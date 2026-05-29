#!/usr/bin/env python3
# For authorized OT/ICS security monitoring only
"""Modbus TCP Traffic Anomaly Detector - Monitors SCADA networks for suspicious Modbus activity."""

import json
import logging
import argparse
import struct
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODBUS_PORT = 502
MBAP_HEADER_SIZE = 7

FUNCTION_CODE_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Slave ID",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}

WRITE_FUNCTION_CODES = {5, 6, 15, 16, 22, 23}
READ_FUNCTION_CODES = {1, 2, 3, 4}
DIAGNOSTIC_FUNCTION_CODES = {7, 8, 17, 43}


def parse_mbap_header(data):
    """Parse 7-byte Modbus Application Protocol header from raw TCP payload."""
    if len(data) < MBAP_HEADER_SIZE:
        return None
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", data[:7])
    if protocol_id != 0:
        return None
    return {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
    }


def parse_modbus_pdu(data):
    """Parse Modbus PDU to extract function code, register addresses, and values."""
    if len(data) < MBAP_HEADER_SIZE + 1:
        return None
    pdu = data[MBAP_HEADER_SIZE:]
    function_code = pdu[0]
    is_exception = function_code > 0x80
    result = {
        "function_code": function_code & 0x7F if is_exception else function_code,
        "is_exception": is_exception,
        "exception_code": pdu[1] if is_exception and len(pdu) > 1 else None,
        "raw_pdu": pdu.hex(),
    }
    fc = result["function_code"]
    if not is_exception and len(pdu) >= 5:
        if fc in (1, 2, 3, 4):
            result["start_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]
        elif fc == 5:
            result["coil_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["coil_value"] = struct.unpack(">H", pdu[3:5])[0]
        elif fc == 6:
            result["register_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["register_value"] = struct.unpack(">H", pdu[3:5])[0]
        elif fc == 16 and len(pdu) >= 7:
            result["start_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]
            byte_count = pdu[5]
            values = []
            for i in range(result["quantity"]):
                offset = 6 + i * 2
                if offset + 2 <= len(pdu):
                    values.append(struct.unpack(">H", pdu[offset:offset + 2])[0])
            result["values"] = values
        elif fc == 15 and len(pdu) >= 6:
            result["start_address"] = struct.unpack(">H", pdu[1:3])[0]
            result["quantity"] = struct.unpack(">H", pdu[3:5])[0]
    return result


class ModbusBaseline:
    """Maintains baseline statistics for Modbus communication patterns."""

    def __init__(self):
        self.function_code_counts = defaultdict(lambda: defaultdict(int))
        self.register_ranges = defaultdict(set)
        self.timing_windows = defaultdict(list)
        self.register_values = defaultdict(list)
        self.total_packets = defaultdict(int)

    def record(self, src_ip, dst_ip, function_code, timestamp, registers=None, values=None):
        pair_key = (src_ip, dst_ip)
        self.function_code_counts[pair_key][function_code] += 1
        self.total_packets[pair_key] += 1
        self.timing_windows[pair_key].append(timestamp)
        if registers:
            for reg in registers:
                self.register_ranges[pair_key].add(reg)
        if values and registers:
            for reg, val in zip(registers, values):
                self.register_values[reg].append(val)

    def get_fc_distribution(self, src_ip, dst_ip):
        pair_key = (src_ip, dst_ip)
        total = self.total_packets[pair_key]
        if total == 0:
            return {}
        return {
            fc: count / total
            for fc, count in self.function_code_counts[pair_key].items()
        }

    def get_timing_stats(self, src_ip, dst_ip):
        pair_key = (src_ip, dst_ip)
        timestamps = self.timing_windows[pair_key]
        if len(timestamps) < 10:
            return None
        intervals = np.diff(sorted(timestamps))
        return {"mean": float(np.mean(intervals)), "std": float(np.std(intervals))}

    def get_register_stats(self, register_addr):
        values = self.register_values.get(register_addr, [])
        if len(values) < 5:
            return None
        return {
            "min": float(np.min(values)),
            "max": float(np.max(values)),
            "mean": float(np.mean(values)),
            "std": float(np.std(values)),
        }

    def save(self, filepath):
        data = {
            "fc_counts": {
                f"{k[0]}->{k[1]}": dict(v)
                for k, v in self.function_code_counts.items()
            },
            "register_ranges": {
                f"{k[0]}->{k[1]}": sorted(v)
                for k, v in self.register_ranges.items()
            },
            "total_packets": {
                f"{k[0]}->{k[1]}": v for k, v in self.total_packets.items()
            },
            "register_values": {
                str(k): {
                    "min": float(np.min(v)),
                    "max": float(np.max(v)),
                    "mean": float(np.mean(v)),
                    "std": float(np.std(v)),
                    "count": len(v),
                }
                for k, v in self.register_values.items()
                if len(v) >= 5
            },
        }
        Path(filepath).write_text(json.dumps(data, indent=2))
        logger.info("Baseline saved to %s", filepath)

    def load(self, filepath):
        data = json.loads(Path(filepath).read_text())
        for pair_str, fc_dict in data.get("fc_counts", {}).items():
            src, dst = pair_str.split("->")
            for fc_str, count in fc_dict.items():
                self.function_code_counts[(src, dst)][int(fc_str)] = count
        for pair_str, regs in data.get("register_ranges", {}).items():
            src, dst = pair_str.split("->")
            self.register_ranges[(src, dst)] = set(regs)
        for pair_str, total in data.get("total_packets", {}).items():
            src, dst = pair_str.split("->")
            self.total_packets[(src, dst)] = total
        logger.info("Baseline loaded from %s", filepath)


class ModbusAnomalyDetector:
    """Detects anomalies in Modbus TCP traffic based on baseline profiles."""

    def __init__(self, authorized_masters=None, authorized_writers=None,
                 register_limits=None, baseline=None):
        self.authorized_masters = set(authorized_masters or [])
        self.authorized_writers = set(authorized_writers or [])
        self.register_limits = register_limits or {}
        self.baseline = baseline or ModbusBaseline()
        self.alerts = []
        self.previous_register_values = {}
        self.exception_counts = defaultdict(lambda: defaultdict(int))
        self.device_scan_tracker = defaultdict(set)
        self.connection_counts = defaultdict(list)

    def analyze_packet(self, src_ip, dst_ip, dst_port, raw_payload, timestamp):
        """Analyze a single Modbus TCP packet for anomalies."""
        if dst_port != MODBUS_PORT:
            return []
        packet_alerts = []

        rogue = self._check_rogue_master(src_ip, dst_ip, timestamp)
        if rogue:
            packet_alerts.append(rogue)

        mbap = parse_mbap_header(raw_payload)
        if not mbap:
            packet_alerts.append({
                "alert": "MALFORMED_MBAP_HEADER",
                "severity": "MEDIUM",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "description": "Modbus frame with invalid MBAP header",
            })
            return packet_alerts

        pdu = parse_modbus_pdu(raw_payload)
        if not pdu:
            return packet_alerts

        fc = pdu["function_code"]

        if pdu["is_exception"]:
            exc_alerts = self._check_exception_burst(
                src_ip, dst_ip, fc, pdu.get("exception_code"), timestamp
            )
            if exc_alerts:
                packet_alerts.extend(exc_alerts)
            return packet_alerts

        unauth_write = self._check_unauthorized_write(src_ip, fc, dst_ip, timestamp)
        if unauth_write:
            packet_alerts.append(unauth_write)

        recon = self._check_reconnaissance(src_ip, dst_ip, fc, timestamp)
        if recon:
            packet_alerts.append(recon)

        fc_anomaly = self._check_fc_anomaly(src_ip, dst_ip, fc, timestamp)
        if fc_anomaly:
            packet_alerts.append(fc_anomaly)

        reg_alerts = self._check_register_values(src_ip, dst_ip, pdu, timestamp)
        if reg_alerts:
            packet_alerts.extend(reg_alerts)

        timing = self._check_timing_anomaly(src_ip, dst_ip, timestamp)
        if timing:
            packet_alerts.append(timing)

        registers = self._extract_registers(pdu)
        values = self._extract_values(pdu)
        self.baseline.record(src_ip, dst_ip, fc, timestamp, registers, values)

        self.alerts.extend(packet_alerts)
        return packet_alerts

    def _check_rogue_master(self, src_ip, dst_ip, timestamp):
        if self.authorized_masters and src_ip not in self.authorized_masters:
            return {
                "alert": "ROGUE_MODBUS_MASTER",
                "severity": "CRITICAL",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "target_slave": dst_ip,
                "description": f"Unauthorized device {src_ip} initiating Modbus connection "
                               f"to slave {dst_ip}",
            }
        return None

    def _check_unauthorized_write(self, src_ip, function_code, dst_ip, timestamp):
        if function_code in WRITE_FUNCTION_CODES and self.authorized_writers and \
                src_ip not in self.authorized_writers:
            return {
                "alert": "UNAUTHORIZED_MODBUS_WRITE",
                "severity": "CRITICAL",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "function_code": function_code,
                "function_name": FUNCTION_CODE_NAMES.get(function_code, "Unknown"),
                "description": f"Write FC {function_code} "
                               f"({FUNCTION_CODE_NAMES.get(function_code, 'Unknown')}) "
                               f"from unauthorized source {src_ip}",
            }
        return None

    def _check_reconnaissance(self, src_ip, dst_ip, function_code, timestamp):
        if function_code in DIAGNOSTIC_FUNCTION_CODES:
            self.device_scan_tracker[src_ip].add(dst_ip)
            targets = self.device_scan_tracker[src_ip]
            severity = "CRITICAL" if len(targets) >= 5 else "HIGH"
            return {
                "alert": "DEVICE_ENUMERATION",
                "severity": severity,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "function_code": function_code,
                "function_name": FUNCTION_CODE_NAMES.get(function_code, "Unknown"),
                "unique_targets": len(targets),
                "description": f"Diagnostic FC {function_code} from {src_ip} to {dst_ip}. "
                               f"Total unique targets scanned: {len(targets)}",
            }
        return None

    def _check_fc_anomaly(self, src_ip, dst_ip, function_code, timestamp):
        pair_key = (src_ip, dst_ip)
        baseline_dist = self.baseline.get_fc_distribution(src_ip, dst_ip)
        if not baseline_dist:
            return None
        if function_code not in self.baseline.function_code_counts.get(pair_key, {}):
            return {
                "alert": "NEW_FUNCTION_CODE",
                "severity": "HIGH",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "function_code": function_code,
                "function_name": FUNCTION_CODE_NAMES.get(function_code, "Unknown"),
                "description": f"FC {function_code} "
                               f"({FUNCTION_CODE_NAMES.get(function_code, 'Unknown')}) "
                               f"never seen before for {src_ip} -> {dst_ip}",
            }
        return None

    def _check_exception_burst(self, src_ip, dst_ip, function_code, exception_code, timestamp):
        pair_key = (src_ip, dst_ip)
        minute_key = int(timestamp // 60)
        self.exception_counts[pair_key][minute_key] += 1
        count = self.exception_counts[pair_key][minute_key]
        exception_names = {1: "Illegal Function", 2: "Illegal Data Address",
                           3: "Illegal Data Value", 4: "Slave Device Failure"}
        if count == 10:
            return [{
                "alert": "EXCEPTION_BURST",
                "severity": "HIGH",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "exception_code": exception_code,
                "exception_name": exception_names.get(exception_code, "Unknown"),
                "count_per_minute": count,
                "description": f"Burst of {count} Modbus exceptions from {dst_ip} in response "
                               f"to requests from {src_ip}. Possible scanning or fuzzing.",
            }]
        return None

    def _check_register_values(self, src_ip, dst_ip, pdu, timestamp):
        alerts = []
        fc = pdu["function_code"]
        if fc == 6:
            reg = pdu.get("register_address")
            val = pdu.get("register_value")
            if reg is not None and val is not None:
                alert = self._validate_register(reg, val, src_ip, dst_ip, timestamp)
                if alert:
                    alerts.extend(alert)
        elif fc == 16:
            start = pdu.get("start_address", 0)
            values = pdu.get("values", [])
            for i, val in enumerate(values):
                reg = start + i
                alert = self._validate_register(reg, val, src_ip, dst_ip, timestamp)
                if alert:
                    alerts.extend(alert)
        return alerts

    def _validate_register(self, register_addr, new_value, src_ip, dst_ip, timestamp):
        alerts = []
        if register_addr in self.register_limits:
            limits = self.register_limits[register_addr]
            if new_value < limits.get("min", float("-inf")) or \
                    new_value > limits.get("max", float("inf")):
                alerts.append({
                    "alert": "REGISTER_VALUE_OUT_OF_RANGE",
                    "severity": "CRITICAL",
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "register": register_addr,
                    "register_name": limits.get("name", f"Register {register_addr}"),
                    "value": new_value,
                    "safe_range": f"{limits.get('min', 'N/A')}-{limits.get('max', 'N/A')} "
                                  f"{limits.get('unit', '')}",
                    "description": f"Register {register_addr} "
                                   f"({limits.get('name', 'Unknown')}) set to {new_value}, "
                                   f"outside safe range "
                                   f"{limits.get('min')}-{limits.get('max')} "
                                   f"{limits.get('unit', '')}",
                })
        prev = self.previous_register_values.get(register_addr)
        if prev is not None and register_addr in self.register_limits:
            limits = self.register_limits[register_addr]
            max_rate = limits.get("max_rate")
            if max_rate and abs(new_value - prev) > max_rate:
                alerts.append({
                    "alert": "REGISTER_VALUE_EXCESSIVE_RATE",
                    "severity": "HIGH",
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "register": register_addr,
                    "register_name": limits.get("name", f"Register {register_addr}"),
                    "previous_value": prev,
                    "new_value": new_value,
                    "change": abs(new_value - prev),
                    "max_allowed_change": max_rate,
                    "description": f"Register {register_addr} changed by "
                                   f"{abs(new_value - prev)} (max allowed: {max_rate})",
                })
        self.previous_register_values[register_addr] = new_value
        return alerts if alerts else None

    def _check_timing_anomaly(self, src_ip, dst_ip, timestamp):
        stats = self.baseline.get_timing_stats(src_ip, dst_ip)
        if not stats or stats["std"] == 0:
            return None
        pair_key = (src_ip, dst_ip)
        timestamps = self.baseline.timing_windows[pair_key]
        if len(timestamps) < 2:
            return None
        interval = timestamp - timestamps[-1]
        deviation = abs(interval - stats["mean"]) / stats["std"]
        if deviation > 3.0:
            return {
                "alert": "TIMING_ANOMALY",
                "severity": "MEDIUM",
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "interval_seconds": round(interval, 4),
                "expected_mean": round(stats["mean"], 4),
                "expected_std": round(stats["std"], 4),
                "deviation_sigma": round(deviation, 2),
                "description": f"Inter-packet interval {interval:.4f}s deviates "
                               f"{deviation:.1f} sigma from mean {stats['mean']:.4f}s",
            }
        return None

    def _extract_registers(self, pdu):
        fc = pdu["function_code"]
        if fc in (1, 2, 3, 4):
            start = pdu.get("start_address", 0)
            qty = pdu.get("quantity", 0)
            return list(range(start, start + qty))
        elif fc == 5:
            addr = pdu.get("coil_address")
            return [addr] if addr is not None else []
        elif fc == 6:
            addr = pdu.get("register_address")
            return [addr] if addr is not None else []
        elif fc in (15, 16):
            start = pdu.get("start_address", 0)
            qty = pdu.get("quantity", 0)
            return list(range(start, start + qty))
        return []

    def _extract_values(self, pdu):
        fc = pdu["function_code"]
        if fc == 5:
            val = pdu.get("coil_value")
            return [val] if val is not None else []
        elif fc == 6:
            val = pdu.get("register_value")
            return [val] if val is not None else []
        elif fc == 16:
            return pdu.get("values", [])
        return []

    def generate_report(self):
        """Generate JSON anomaly report."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_alerts = sorted(
            self.alerts, key=lambda a: severity_order.get(a.get("severity", "LOW"), 99)
        )
        report = {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "total_anomalies": len(sorted_alerts),
            "severity_summary": {
                "CRITICAL": sum(1 for a in sorted_alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in sorted_alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in sorted_alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in sorted_alerts if a["severity"] == "LOW"),
            },
            "alerts": sorted_alerts,
        }
        return report


def analyze_pcap(pcap_file, detector):
    """Analyze a pcap file for Modbus TCP anomalies using Scapy."""
    try:
        from scapy.all import rdpcap, TCP, IP
    except ImportError:
        logger.error("Scapy is required for pcap analysis: pip install scapy")
        return

    logger.info("Loading pcap: %s", pcap_file)
    packets = rdpcap(pcap_file)
    modbus_count = 0

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            continue
        tcp = pkt[TCP]
        ip = pkt[IP]
        if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT:
            continue
        payload = bytes(tcp.payload)
        if len(payload) < MBAP_HEADER_SIZE + 1:
            continue

        dst_port = tcp.dport
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = float(pkt.time)

        alerts = detector.analyze_packet(src_ip, dst_ip, dst_port, payload, timestamp)
        modbus_count += 1
        for alert in alerts:
            logger.warning("[%s] %s: %s", alert["severity"], alert["alert"],
                           alert["description"])

    logger.info("Analyzed %d Modbus packets from %d total packets", modbus_count, len(packets))


def live_capture(interface, detector, duration=0):
    """Capture and analyze Modbus TCP traffic in real-time using Scapy."""
    try:
        from scapy.all import sniff, TCP, IP
    except ImportError:
        logger.error("Scapy is required for live capture: pip install scapy")
        return

    def process_packet(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        tcp = pkt[TCP]
        ip = pkt[IP]
        payload = bytes(tcp.payload)
        if len(payload) < MBAP_HEADER_SIZE + 1:
            return
        alerts = detector.analyze_packet(
            ip.src, ip.dst, tcp.dport, payload, float(pkt.time)
        )
        for alert in alerts:
            logger.warning("[%s] %s: %s", alert["severity"], alert["alert"],
                           alert["description"])

    logger.info("Starting live capture on %s (filter: port 502)", interface)
    kwargs = {"iface": interface, "filter": "tcp port 502", "prn": process_packet,
              "store": False}
    if duration > 0:
        kwargs["timeout"] = duration
    sniff(**kwargs)


def main():
    parser = argparse.ArgumentParser(
        description="Modbus TCP Traffic Anomaly Detector for SCADA/ICS Networks"
    )
    parser.add_argument("--pcap", help="Path to pcap file to analyze")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--duration", type=int, default=0,
                        help="Live capture duration in seconds (0=indefinite)")
    parser.add_argument("--authorized-masters", nargs="+",
                        help="List of authorized Modbus master IPs")
    parser.add_argument("--authorized-writers", nargs="+",
                        help="List of IPs authorized to send write commands")
    parser.add_argument("--register-limits-file",
                        help="JSON file defining safe register value ranges")
    parser.add_argument("--baseline-file",
                        help="Path to load/save baseline profile")
    parser.add_argument("--baseline-mode", action="store_true",
                        help="Run in baseline-building mode (no alerting)")
    parser.add_argument("--output", default="modbus_anomaly_report.json",
                        help="Output report file (default: modbus_anomaly_report.json)")
    args = parser.parse_args()

    register_limits = {}
    if args.register_limits_file:
        register_limits = json.loads(Path(args.register_limits_file).read_text())
        logger.info("Loaded register limits for %d registers", len(register_limits))

    baseline = ModbusBaseline()
    if args.baseline_file and Path(args.baseline_file).exists() and not args.baseline_mode:
        baseline.load(args.baseline_file)

    detector = ModbusAnomalyDetector(
        authorized_masters=args.authorized_masters,
        authorized_writers=args.authorized_writers,
        register_limits=register_limits,
        baseline=baseline,
    )

    if args.pcap:
        analyze_pcap(args.pcap, detector)
    elif args.interface:
        live_capture(args.interface, detector, args.duration)
    else:
        parser.error("Either --pcap or --interface is required")

    if args.baseline_mode and args.baseline_file:
        baseline.save(args.baseline_file)
        logger.info("Baseline mode complete. Profile saved to %s", args.baseline_file)
    else:
        report = detector.generate_report()
        Path(args.output).write_text(json.dumps(report, indent=2, default=str))
        logger.info("Report saved to %s (%d anomalies detected)",
                     args.output, report["total_anomalies"])


if __name__ == "__main__":
    main()
