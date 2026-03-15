---
name: analyzing-cobalt-strike-beacon-configuration
description: Extract and analyze Cobalt Strike beacon configuration from PE files and memory dumps to identify C2 infrastructure, malleable profiles, and operator tradecraft.
domain: cybersecurity
subdomain: malware-analysis
tags: [cobalt-strike, beacon, c2, malware-analysis, config-extraction, threat-hunting, red-team-tools]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Analyzing Cobalt Strike Beacon Configuration

## Overview

Cobalt Strike is a commercial adversary simulation tool widely abused by threat actors for post-exploitation operations. Beacon payloads contain embedded configuration data that reveals C2 server addresses, communication protocols, sleep intervals, jitter values, malleable C2 profile settings, watermark identifiers, and encryption keys. Extracting this configuration from PE files, shellcode, or memory dumps is critical for incident responders to map attacker infrastructure and attribute campaigns. The beacon configuration is XOR-encoded using a single byte (0x69 for version 3, 0x2e for version 4) and stored in a Type-Length-Value (TLV) format within the .data section.

## Prerequisites

- Python 3.9+ with `dissect.cobaltstrike`, `pefile`, `yara-python`
- SentinelOne CobaltStrikeParser (`parse_beacon_config.py`)
- Hex editor (010 Editor, HxD) for manual inspection
- Understanding of PE file format and XOR encoding
- Memory dump acquisition tools (Volatility3, WinDbg)
- Network analysis tools (Wireshark) for C2 traffic correlation

## Key Concepts

### Beacon Configuration Structure

Cobalt Strike beacons store their configuration as a blob of TLV (Type-Length-Value) entries within the .data section of the PE. Stageless beacons XOR the entire beacon code with a 4-byte key. The configuration blob itself uses a single-byte XOR key. Each TLV entry contains a 2-byte type identifier (e.g., 0x0001 for BeaconType, 0x0008 for C2Server), a 2-byte length, and variable-length data.

### Malleable C2 Profiles

The beacon configuration encodes the malleable C2 profile that dictates HTTP request/response transformations, including URI paths, headers, metadata encoding (Base64, NetBIOS), and data transforms. Analyzing these settings reveals how the beacon disguises its traffic to blend with legitimate web traffic.

### Watermark and License Identification

Each Cobalt Strike license embeds a unique watermark (4-byte integer) into generated beacons. Extracting the watermark can link multiple beacons to the same operator or cracked license. Known watermark databases maintained by threat intelligence providers map watermarks to specific threat actors or leaked license keys.

## Practical Steps

### Step 1: Extract Configuration with CobaltStrikeParser

```python
#!/usr/bin/env python3
"""Extract Cobalt Strike beacon config from PE or memory dump."""
import sys
import json

# Using SentinelOne's CobaltStrikeParser
# pip install dissect.cobaltstrike
from dissect.cobaltstrike.beacon import BeaconConfig

def extract_beacon_config(filepath):
    """Parse beacon configuration from file."""
    configs = list(BeaconConfig.from_path(filepath))

    if not configs:
        print(f"[-] No beacon configuration found in {filepath}")
        return None

    for i, config in enumerate(configs):
        print(f"\n[+] Beacon Configuration #{i+1}")
        print(f"{'='*60}")

        settings = config.as_dict()

        # Critical fields for incident response
        critical_fields = [
            "SETTING_C2_REQUEST",
            "SETTING_C2_RECOVER",
            "SETTING_PUBKEY",
            "SETTING_DOMAINS",
            "SETTING_BEACONTYPE",
            "SETTING_PORT",
            "SETTING_SLEEPTIME",
            "SETTING_JITTER",
            "SETTING_MAXGET",
            "SETTING_SPAWNTO_X86",
            "SETTING_SPAWNTO_X64",
            "SETTING_PIPENAME",
            "SETTING_WATERMARK",
            "SETTING_C2_VERB_GET",
            "SETTING_C2_VERB_POST",
            "SETTING_USERAGENT",
            "SETTING_PROTOCOL",
        ]

        for field in critical_fields:
            value = settings.get(field, "N/A")
            print(f"  {field}: {value}")

        return settings

    return None


def extract_c2_indicators(config):
    """Extract actionable C2 indicators from beacon config."""
    indicators = {
        "c2_domains": [],
        "c2_ips": [],
        "c2_urls": [],
        "user_agent": "",
        "named_pipes": [],
        "spawn_processes": [],
        "watermark": "",
    }

    if not config:
        return indicators

    # Extract C2 domains
    domains = config.get("SETTING_DOMAINS", "")
    if domains:
        for domain in str(domains).split(","):
            domain = domain.strip().rstrip("/")
            if domain:
                indicators["c2_domains"].append(domain)

    # Extract user agent
    indicators["user_agent"] = str(config.get("SETTING_USERAGENT", ""))

    # Extract named pipes
    pipe = config.get("SETTING_PIPENAME", "")
    if pipe:
        indicators["named_pipes"].append(str(pipe))

    # Extract spawn-to processes
    for arch in ["SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64"]:
        proc = config.get(arch, "")
        if proc:
            indicators["spawn_processes"].append(str(proc))

    # Extract watermark
    indicators["watermark"] = str(config.get("SETTING_WATERMARK", ""))

    return indicators


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <beacon_file_or_dump>")
        sys.exit(1)

    config = extract_beacon_config(sys.argv[1])
    if config:
        indicators = extract_c2_indicators(config)
        print(f"\n[+] Extracted C2 Indicators:")
        print(json.dumps(indicators, indent=2))
```

### Step 2: Manual XOR Decryption of Beacon Config

```python
import struct

def find_and_decrypt_config(data):
    """Manually locate and decrypt beacon configuration."""
    # Cobalt Strike 4.x uses 0x2e as XOR key
    xor_keys = [0x2e, 0x69]  # v4, v3

    for xor_key in xor_keys:
        # Search for the config magic bytes after XOR
        # Config starts with 0x0001 (BeaconType) XOR'd with key
        magic = bytes([0x00 ^ xor_key, 0x01 ^ xor_key,
                       0x00 ^ xor_key, 0x02 ^ xor_key])

        offset = data.find(magic)
        if offset == -1:
            continue

        print(f"[+] Found config at offset 0x{offset:x} (XOR key: 0x{xor_key:02x})")

        # Decrypt the config blob (typically 4096 bytes)
        config_size = 4096
        encrypted = data[offset:offset + config_size]
        decrypted = bytes([b ^ xor_key for b in encrypted])

        # Parse TLV entries
        entries = parse_tlv(decrypted)
        return entries

    return None


def parse_tlv(data):
    """Parse Type-Length-Value configuration entries."""
    entries = {}
    offset = 0

    # TLV field type mapping
    field_names = {
        0x0001: "BeaconType",
        0x0002: "Port",
        0x0003: "SleepTime",
        0x0004: "MaxGetSize",
        0x0005: "Jitter",
        0x0006: "MaxDNS",
        0x0007: "Deprecated_PublicKey",
        0x0008: "C2Server",
        0x0009: "UserAgent",
        0x000a: "PostURI",
        0x000b: "Malleable_C2_Instructions",
        0x000c: "Deprecated_HttpGet_Metadata",
        0x000d: "SpawnTo_x86",
        0x000e: "SpawnTo_x64",
        0x000f: "CryptoScheme",
        0x001a: "Watermark",
        0x001d: "C2_HostHeader",
        0x0024: "PipeName",
        0x0025: "Year",
        0x0026: "Month",
        0x0027: "Day",
        0x0036: "ProxyHostname",
    }

    while offset + 6 <= len(data):
        entry_type = struct.unpack(">H", data[offset:offset+2])[0]
        entry_len_type = struct.unpack(">H", data[offset+2:offset+4])[0]
        entry_len = struct.unpack(">H", data[offset+4:offset+6])[0]

        if entry_type == 0:
            break

        value_start = offset + 6
        value_end = value_start + entry_len
        value_data = data[value_start:value_end]

        field_name = field_names.get(entry_type, f"Unknown_0x{entry_type:04x}")

        if entry_len_type == 1:  # Short
            value = struct.unpack(">H", value_data[:2])[0]
        elif entry_len_type == 2:  # Int
            value = struct.unpack(">I", value_data[:4])[0]
        elif entry_len_type == 3:  # String/Blob
            value = value_data.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            value = value_data.hex()

        entries[field_name] = value
        print(f"  {field_name}: {value}")

        offset = value_end

    return entries
```

### Step 3: YARA Rule for Beacon Detection

```python
import yara

cobalt_strike_rule = """
rule CobaltStrike_Beacon_Config {
    meta:
        description = "Detects Cobalt Strike beacon configuration"
        author = "Malware Analysis Team"
        date = "2025-01-01"

    strings:
        // XOR'd config marker for CS 4.x (key 0x2e)
        $config_v4 = { 2e 2f 2e 2c }

        // XOR'd config marker for CS 3.x (key 0x69)
        $config_v3 = { 69 68 69 6b }

        // Common beacon strings
        $str_pipe = "\\\\.\\pipe\\" ascii wide
        $str_beacon = "beacon" ascii nocase
        $str_sleeptime = "sleeptime" ascii nocase

        // Reflective loader pattern
        $reflective = { 4D 5A 41 52 55 48 89 E5 }

    condition:
        ($config_v4 or $config_v3) or
        (2 of ($str_*) and $reflective)
}
"""

def scan_for_beacons(filepath):
    """Scan file with YARA rules for Cobalt Strike beacons."""
    rules = yara.compile(source=cobalt_strike_rule)
    matches = rules.match(filepath)

    for match in matches:
        print(f"[+] YARA Match: {match.rule}")
        for string_match in match.strings:
            offset = string_match.instances[0].offset
            print(f"    String: {string_match.identifier} at offset 0x{offset:x}")

    return matches
```

### Step 4: Network Traffic Correlation

```python
from dissect.cobaltstrike.c2 import HttpC2Config

def analyze_c2_profile(beacon_config):
    """Analyze malleable C2 profile from beacon configuration."""
    print("\n[+] Malleable C2 Profile Analysis")
    print("=" * 60)

    # HTTP GET configuration
    get_verb = beacon_config.get("SETTING_C2_VERB_GET", "GET")
    get_uri = beacon_config.get("SETTING_C2_REQUEST", "")
    print(f"\n  HTTP GET Request:")
    print(f"    Verb: {get_verb}")
    print(f"    URI: {get_uri}")

    # HTTP POST configuration
    post_verb = beacon_config.get("SETTING_C2_VERB_POST", "POST")
    post_uri = beacon_config.get("SETTING_C2_POSTREQ", "")
    print(f"\n  HTTP POST Request:")
    print(f"    Verb: {post_verb}")
    print(f"    URI: {post_uri}")

    # User Agent
    ua = beacon_config.get("SETTING_USERAGENT", "")
    print(f"\n  User-Agent: {ua}")

    # Host header
    host = beacon_config.get("SETTING_C2_HOSTHEADER", "")
    print(f"  Host Header: {host}")

    # Sleep and jitter for traffic pattern
    sleep_ms = beacon_config.get("SETTING_SLEEPTIME", 60000)
    jitter = beacon_config.get("SETTING_JITTER", 0)
    print(f"\n  Sleep Time: {sleep_ms}ms")
    print(f"  Jitter: {jitter}%")

    # Generate Suricata/Snort signatures
    print(f"\n[+] Suggested Network Signatures:")
    if ua:
        print(f'  alert http any any -> any any (msg:"CS Beacon UA"; '
              f'content:"{ua}"; http_user_agent; sid:1000001; rev:1;)')
    if get_uri:
        print(f'  alert http any any -> any any (msg:"CS Beacon URI"; '
              f'content:"{get_uri}"; http_uri; sid:1000002; rev:1;)')
```

## Validation Criteria

- Beacon configuration successfully extracted from PE file or memory dump
- C2 server domains/IPs correctly identified with port and protocol
- Malleable C2 profile parameters decoded showing HTTP transforms
- Watermark value extracted for attribution correlation
- Sleep time and jitter values match observed network beacon intervals
- YARA rules detect beacon in both packed and unpacked samples
- Network signatures generated from extracted C2 profile

## References

- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [dissect.cobaltstrike Library](https://github.com/fox-it/dissect.cobaltstrike)
- [SentinelLabs Beacon Configuration Analysis](https://www.sentinelone.com/labs/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/)
- [Cobalt Strike Staging and Config Extraction](https://blog.securehat.co.uk/cobaltstrike/extracting-config-from-cobaltstrike-stager-shellcode)
- [MITRE ATT&CK - Cobalt Strike S0154](https://attack.mitre.org/software/S0154/)
