#!/usr/bin/env python3
"""Cobalt Strike beacon configuration extraction and analysis agent.

Extracts C2 configuration from beacon payloads including server addresses,
communication settings, malleable C2 profile details, and watermark values.
"""

import struct
import os
import sys
import json
import hashlib
import re
from collections import OrderedDict

# Cobalt Strike beacon configuration field IDs (Type-Length-Value format)
BEACON_CONFIG_FIELDS = {
    1: ("BeaconType", "short"),
    2: ("Port", "short"),
    3: ("SleepTime", "int"),
    4: ("MaxGetSize", "int"),
    5: ("Jitter", "short"),
    7: ("PublicKey", "bytes"),
    8: ("C2Server", "str"),
    9: ("UserAgent", "str"),
    10: ("PostURI", "str"),
    11: ("Malleable_C2_Instructions", "bytes"),
    12: ("HttpGet_Metadata", "bytes"),
    13: ("HttpPost_Metadata", "bytes"),
    14: ("SpawnToX86", "str"),
    15: ("SpawnToX64", "str"),
    19: ("CryptoScheme", "short"),
    26: ("GetVerb", "str"),
    27: ("PostVerb", "str"),
    28: ("HttpPostChunk", "int"),
    29: ("Spawnto_x86", "str"),
    30: ("Spawnto_x64", "str"),
    31: ("CryptoScheme2", "str"),
    37: ("Watermark", "int"),
    38: ("StageCleanup", "short"),
    39: ("CFGCaution", "short"),
    43: ("DNS_Idle", "int"),
    44: ("DNS_Sleep", "int"),
    50: ("HostHeader", "str"),
    54: ("PipeName", "str"),
}

BEACON_TYPES = {0: "HTTP", 1: "Hybrid HTTP/DNS", 2: "SMB", 4: "TCP", 8: "HTTPS", 16: "DNS over HTTPS"}

XOR_KEY_V3 = 0x69
XOR_KEY_V4 = 0x2E


def compute_hash(filepath):
    """Compute SHA-256 hash of file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def find_config_offset(data):
    """Find the beacon configuration blob in PE data or shellcode."""
    # Look for XOR-encoded config patterns
    for xor_key in [XOR_KEY_V3, XOR_KEY_V4]:
        # Config starts with 0x0001 (BeaconType field ID) XOR-encoded
        encoded_marker = bytes([0x00 ^ xor_key, 0x01 ^ xor_key, 0x00 ^ xor_key, 0x01 ^ xor_key])
        offset = data.find(encoded_marker)
        if offset != -1:
            return offset, xor_key
    # Try unencoded
    for offset in range(len(data) - 100):
        if data[offset:offset+4] == b"\x00\x01\x00\x01":
            return offset, None
    return -1, None


def xor_decode(data, key):
    """XOR decode data with single byte key."""
    if key is None:
        return data
    return bytes(b ^ key for b in data)


def parse_config_field(data, offset):
    """Parse a single TLV config field."""
    if offset + 6 > len(data):
        return None, None, None, offset
    field_id = struct.unpack_from(">H", data, offset)[0]
    field_type = struct.unpack_from(">H", data, offset + 2)[0]
    if field_type == 1:  # short
        value = struct.unpack_from(">H", data, offset + 4)[0]
        return field_id, "short", value, offset + 6
    elif field_type == 2:  # int
        value = struct.unpack_from(">I", data, offset + 4)[0]
        return field_id, "int", value, offset + 8
    elif field_type == 3:  # str/bytes
        length = struct.unpack_from(">H", data, offset + 4)[0]
        if offset + 6 + length > len(data):
            return None, None, None, offset
        value = data[offset + 6:offset + 6 + length]
        return field_id, "str", value, offset + 6 + length
    return None, None, None, offset + 2


def extract_beacon_config(filepath):
    """Extract and parse Cobalt Strike beacon configuration."""
    with open(filepath, "rb") as f:
        data = f.read()

    config_offset, xor_key = find_config_offset(data)
    if config_offset == -1:
        return {"error": "No beacon configuration found", "file": filepath}

    config_data = xor_decode(data[config_offset:config_offset + 4096], xor_key)
    config = OrderedDict()
    config["_meta"] = {
        "config_offset": f"0x{config_offset:08X}",
        "xor_key": f"0x{xor_key:02X}" if xor_key else "none",
        "version_guess": "4.x" if xor_key == XOR_KEY_V4 else "3.x" if xor_key == XOR_KEY_V3 else "unknown",
    }

    offset = 0
    max_fields = 100
    parsed = 0
    while offset < len(config_data) - 4 and parsed < max_fields:
        field_id, field_type, value, new_offset = parse_config_field(config_data, offset)
        if field_id is None or new_offset == offset:
            break
        offset = new_offset
        parsed += 1

        field_info = BEACON_CONFIG_FIELDS.get(field_id)
        if field_info:
            field_name, expected_type = field_info
            if isinstance(value, bytes):
                try:
                    str_value = value.rstrip(b"\x00").decode("utf-8", errors="replace")
                    config[field_name] = str_value
                except Exception:
                    config[field_name] = value.hex()[:100]
            elif field_id == 1:
                config[field_name] = BEACON_TYPES.get(value, f"Unknown({value})")
            else:
                config[field_name] = value

    return config


def extract_c2_indicators(config):
    """Extract C2 indicators from parsed config for threat intelligence."""
    indicators = {"c2_servers": [], "user_agents": [], "uris": [],
                  "pipes": [], "watermark": None, "dns": []}
    c2 = config.get("C2Server", "")
    if c2:
        for server in c2.split(","):
            server = server.strip().rstrip("/")
            if server:
                indicators["c2_servers"].append(server)
    ua = config.get("UserAgent", "")
    if ua:
        indicators["user_agents"].append(ua)
    for key in ["PostURI"]:
        uri = config.get(key, "")
        if uri:
            indicators["uris"].append(uri)
    pipe = config.get("PipeName", "")
    if pipe:
        indicators["pipes"].append(pipe)
    wm = config.get("Watermark")
    if wm:
        indicators["watermark"] = wm
    return indicators


def assess_operator_opsec(config):
    """Assess operator OPSEC based on beacon configuration."""
    findings = []
    sleep = config.get("SleepTime", 0)
    jitter = config.get("Jitter", 0)
    if sleep < 30000:
        findings.append({"level": "INFO", "detail": f"Low sleep time: {sleep}ms - high beacon frequency"})
    if jitter == 0:
        findings.append({"level": "WARN", "detail": "No jitter configured - predictable beacon interval"})
    ua = config.get("UserAgent", "")
    if "Mozilla" not in ua and ua:
        findings.append({"level": "WARN", "detail": f"Non-standard User-Agent: {ua[:60]}"})
    spawn86 = config.get("SpawnToX86", config.get("Spawnto_x86", ""))
    if "rundll32" in spawn86.lower():
        findings.append({"level": "INFO", "detail": "Default spawn-to process (rundll32) - easy to detect"})
    cleanup = config.get("StageCleanup", 0)
    if cleanup == 0:
        findings.append({"level": "INFO", "detail": "Stage cleanup disabled - beacon stub remains in memory"})
    return findings


if __name__ == "__main__":
    print("=" * 60)
    print("Cobalt Strike Beacon Configuration Extractor")
    print("C2 extraction, watermark analysis, OPSEC assessment")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None

    if not target or not os.path.exists(target):
        print("\n[DEMO] Usage: python agent.py <beacon_sample.exe>")
        print("  Extracts: C2 servers, sleep/jitter, watermark, malleable profile")
        sys.exit(0)

    print(f"\n[*] Analyzing: {target}")
    print(f"[*] SHA-256: {compute_hash(target)}")
    print(f"[*] Size: {os.path.getsize(target)} bytes")

    config = extract_beacon_config(target)

    if "error" in config:
        print(f"\n[!] {config['error']}")
        sys.exit(1)

    print("\n--- Beacon Configuration ---")
    for key, value in config.items():
        if key == "_meta":
            for mk, mv in value.items():
                print(f"  {mk}: {mv}")
        else:
            print(f"  {key}: {value}")

    indicators = extract_c2_indicators(config)
    print("\n--- C2 Indicators ---")
    for c2 in indicators["c2_servers"]:
        print(f"  [C2] {c2}")
    if indicators["watermark"]:
        print(f"  [Watermark] {indicators['watermark']}")
    for pipe in indicators["pipes"]:
        print(f"  [Pipe] {pipe}")

    opsec = assess_operator_opsec(config)
    print("\n--- Operator OPSEC Assessment ---")
    for f in opsec:
        print(f"  [{f['level']}] {f['detail']}")
