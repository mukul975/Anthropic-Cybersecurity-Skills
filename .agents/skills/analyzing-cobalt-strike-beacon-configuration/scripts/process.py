#!/usr/bin/env python3
"""
Cobalt Strike Beacon Configuration Analyzer

Extracts and analyzes beacon configurations from PE files, shellcode,
and memory dumps using dissect.cobaltstrike and manual parsing.

Requirements:
    pip install dissect.cobaltstrike pefile yara-python

Usage:
    python process.py --file beacon.exe --output report.json
    python process.py --file memdump.bin --scan-memory
    python process.py --directory ./samples --batch
"""

import argparse
import json
import os
import struct
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from dissect.cobaltstrike.beacon import BeaconConfig
except ImportError:
    print("ERROR: dissect.cobaltstrike not installed.")
    print("Run: pip install dissect.cobaltstrike")
    sys.exit(1)


# TLV field type mapping
TLV_FIELDS = {
    0x0001: ("BeaconType", "short"),
    0x0002: ("Port", "short"),
    0x0003: ("SleepTime", "int"),
    0x0004: ("MaxGetSize", "int"),
    0x0005: ("Jitter", "short"),
    0x0006: ("MaxDNS", "short"),
    0x0008: ("C2Server", "str"),
    0x0009: ("UserAgent", "str"),
    0x000a: ("PostURI", "str"),
    0x000b: ("Malleable_C2_Instructions", "blob"),
    0x000d: ("SpawnTo_x86", "str"),
    0x000e: ("SpawnTo_x64", "str"),
    0x000f: ("CryptoScheme", "short"),
    0x001a: ("Watermark", "int"),
    0x001d: ("HostHeader", "str"),
    0x0024: ("PipeName", "str"),
    0x0025: ("Year", "short"),
    0x0026: ("Month", "short"),
    0x0027: ("Day", "short"),
    0x002c: ("ProxyHostname", "str"),
    0x002d: ("ProxyUsername", "str"),
    0x002e: ("ProxyPassword", "str"),
}

BEACON_TYPES = {
    0: "HTTP",
    1: "Hybrid HTTP/DNS",
    2: "SMB",
    4: "TCP",
    8: "HTTPS",
    10: "TCP Bind",
    14: "External C2",
}


class BeaconAnalyzer:
    """Analyze Cobalt Strike beacon configurations."""

    def __init__(self):
        self.results = []

    def analyze_file(self, filepath):
        """Extract beacon config from a file."""
        filepath = Path(filepath)
        if not filepath.exists():
            print(f"[-] File not found: {filepath}")
            return None

        print(f"[*] Analyzing: {filepath}")

        # Try dissect.cobaltstrike first
        result = self._extract_with_dissect(filepath)

        # Fall back to manual extraction
        if not result:
            result = self._extract_manual(filepath)

        if result:
            result["source_file"] = str(filepath)
            result["analysis_time"] = datetime.now().isoformat()
            self.results.append(result)

        return result

    def _extract_with_dissect(self, filepath):
        """Extract config using dissect.cobaltstrike library."""
        try:
            configs = list(BeaconConfig.from_path(filepath))
            if not configs:
                return None

            config = configs[0]
            settings = config.as_dict()

            result = {
                "method": "dissect.cobaltstrike",
                "config": {},
                "indicators": {},
            }

            for key, value in settings.items():
                if value is not None:
                    result["config"][key] = str(value)

            result["indicators"] = self._extract_indicators(settings)
            return result

        except Exception as e:
            print(f"  [!] dissect extraction failed: {e}")
            return None

    def _extract_manual(self, filepath):
        """Manual XOR-based config extraction."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"  [!] Read failed: {e}")
            return None

        for xor_key in [0x2e, 0x69]:
            # Search for XOR'd config start marker
            magic = bytes([0x00 ^ xor_key, 0x01 ^ xor_key,
                           0x00 ^ xor_key, 0x02 ^ xor_key])

            offset = data.find(magic)
            if offset == -1:
                continue

            print(f"  [+] Config found at 0x{offset:x} (XOR key: 0x{xor_key:02x})")

            config_blob = data[offset:offset + 4096]
            decrypted = bytes([b ^ xor_key for b in config_blob])

            entries = self._parse_tlv(decrypted)
            if entries:
                return {
                    "method": "manual_xor",
                    "xor_key": f"0x{xor_key:02x}",
                    "config_offset": f"0x{offset:x}",
                    "config": entries,
                    "indicators": self._extract_indicators(entries),
                }

        return None

    def _parse_tlv(self, data):
        """Parse TLV configuration entries."""
        entries = {}
        offset = 0

        while offset + 6 <= len(data):
            try:
                entry_type = struct.unpack(">H", data[offset:offset+2])[0]
                data_type = struct.unpack(">H", data[offset+2:offset+4])[0]
                entry_len = struct.unpack(">H", data[offset+4:offset+6])[0]
            except struct.error:
                break

            if entry_type == 0 or entry_len > 4096:
                break

            value_data = data[offset+6:offset+6+entry_len]
            field_info = TLV_FIELDS.get(entry_type)

            if field_info:
                field_name, expected_type = field_info
            else:
                field_name = f"Unknown_0x{entry_type:04x}"
                expected_type = "blob"

            if data_type == 1 and len(value_data) >= 2:
                value = struct.unpack(">H", value_data[:2])[0]
            elif data_type == 2 and len(value_data) >= 4:
                value = struct.unpack(">I", value_data[:4])[0]
            elif data_type == 3:
                value = value_data.rstrip(b'\x00').decode('utf-8', errors='replace')
            else:
                value = value_data.hex()

            # Resolve beacon type names
            if field_name == "BeaconType" and isinstance(value, int):
                value = BEACON_TYPES.get(value, f"Unknown ({value})")

            entries[field_name] = value
            offset += 6 + entry_len

        return entries

    def _extract_indicators(self, config):
        """Extract IOCs from parsed configuration."""
        indicators = {
            "c2_servers": [],
            "user_agent": "",
            "named_pipes": [],
            "spawn_processes": [],
            "watermark": "",
            "beacon_type": "",
            "sleep_time_ms": 0,
            "jitter_pct": 0,
        }

        # Handle both dissect dict keys and manual parse keys
        c2_keys = ["SETTING_DOMAINS", "C2Server"]
        for key in c2_keys:
            domains = config.get(key, "")
            if domains:
                for d in str(domains).split(","):
                    d = d.strip().rstrip("/")
                    if d:
                        indicators["c2_servers"].append(d)

        ua_keys = ["SETTING_USERAGENT", "UserAgent"]
        for key in ua_keys:
            ua = config.get(key, "")
            if ua:
                indicators["user_agent"] = str(ua)

        pipe_keys = ["SETTING_PIPENAME", "PipeName"]
        for key in pipe_keys:
            pipe = config.get(key, "")
            if pipe:
                indicators["named_pipes"].append(str(pipe))

        spawn_keys = [
            ("SETTING_SPAWNTO_X86", "SpawnTo_x86"),
            ("SETTING_SPAWNTO_X64", "SpawnTo_x64"),
        ]
        for dissect_key, manual_key in spawn_keys:
            for key in [dissect_key, manual_key]:
                proc = config.get(key, "")
                if proc:
                    indicators["spawn_processes"].append(str(proc))

        wm_keys = ["SETTING_WATERMARK", "Watermark"]
        for key in wm_keys:
            wm = config.get(key, "")
            if wm:
                indicators["watermark"] = str(wm)

        return indicators

    def batch_analyze(self, directory):
        """Analyze all files in a directory."""
        directory = Path(directory)
        extensions = {".exe", ".dll", ".bin", ".dmp", ".raw"}

        for filepath in directory.rglob("*"):
            if filepath.suffix.lower() in extensions:
                self.analyze_file(filepath)

        return self.results

    def cluster_by_watermark(self):
        """Cluster analyzed beacons by watermark."""
        clusters = defaultdict(list)

        for result in self.results:
            wm = result.get("indicators", {}).get("watermark", "unknown")
            clusters[wm].append(result.get("source_file", "unknown"))

        return dict(clusters)

    def generate_report(self, output_path=None):
        """Generate JSON analysis report."""
        report = {
            "analysis_date": datetime.now().isoformat(),
            "total_beacons": len(self.results),
            "watermark_clusters": self.cluster_by_watermark(),
            "all_c2_servers": list(set(
                server
                for r in self.results
                for server in r.get("indicators", {}).get("c2_servers", [])
            )),
            "results": self.results,
        }

        if output_path:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"[+] Report saved to {output_path}")

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Cobalt Strike Beacon Configuration Analyzer"
    )
    parser.add_argument("--file", help="Single file to analyze")
    parser.add_argument("--directory", help="Directory for batch analysis")
    parser.add_argument("--output", default="beacon_report.json",
                        help="Output report path")
    parser.add_argument("--scan-memory", action="store_true",
                        help="Treat input as raw memory dump")
    parser.add_argument("--batch", action="store_true",
                        help="Batch analyze directory")

    args = parser.parse_args()
    analyzer = BeaconAnalyzer()

    if args.file:
        result = analyzer.analyze_file(args.file)
        if result:
            print(json.dumps(result, indent=2, default=str))

    elif args.directory and args.batch:
        results = analyzer.batch_analyze(args.directory)
        print(f"\n[+] Analyzed {len(results)} beacons")

    else:
        parser.print_help()
        sys.exit(1)

    report = analyzer.generate_report(args.output)
    print(f"\n[+] Total C2 servers found: {len(report['all_c2_servers'])}")
    for server in report["all_c2_servers"]:
        print(f"    {server}")


if __name__ == "__main__":
    main()
