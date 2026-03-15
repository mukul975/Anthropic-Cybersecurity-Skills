#!/usr/bin/env python3
"""Agent for extracting configuration from Agent Tesla RAT samples (malware analysis)."""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone


AGENT_TESLA_INDICATORS = {
    "strings": [
        "smtp.gmail.com", "smtp.yandex.com", "SmtpPort",
        "KeyboardHook", "ClipboardLogger", "ScreenCapture",
        "GetClipboardData", "GetForegroundWindow",
        "Mozilla/5.0", "passwords.txt",
    ],
    "namespaces": [
        "AgentTesla", "WebMonitor", "HPDefender",
        "GodMode", "AKStealer", "Origin Logger",
    ],
}


def compute_file_hashes(file_path):
    """Compute MD5, SHA1, SHA256 of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def extract_strings(file_path, min_len=6):
    """Extract ASCII and wide strings from binary."""
    strings = []
    with open(file_path, "rb") as f:
        data = f.read()
    # ASCII strings
    for match in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data):
        strings.append(match.group().decode("ascii", errors="replace"))
    # Wide strings (UTF-16LE)
    for match in re.finditer(rb'(?:[\x20-\x7e]\x00){%d,}' % min_len, data):
        try:
            strings.append(match.group().decode("utf-16-le", errors="replace"))
        except UnicodeDecodeError:
            pass
    return strings


def find_smtp_config(strings_list):
    """Extract SMTP configuration from string artifacts."""
    config = {"smtp_server": None, "smtp_port": None, "email": None, "password": None}
    for s in strings_list:
        if re.match(r'smtp\.\w+\.\w+', s, re.I):
            config["smtp_server"] = s
        if re.match(r'^\d{2,5}$', s) and int(s) in (25, 465, 587, 2525):
            config["smtp_port"] = int(s)
        if re.match(r'[\w.+-]+@[\w-]+\.[\w.]+', s):
            config["email"] = s
    return config


def find_ftp_config(strings_list):
    """Extract FTP exfiltration configuration."""
    config = {"ftp_server": None, "ftp_user": None, "ftp_password": None}
    for s in strings_list:
        if re.match(r'ftp\.\w+\.\w+', s, re.I):
            config["ftp_server"] = s
        if "ftp://" in s.lower():
            config["ftp_url"] = s
    return config


def find_telegram_config(strings_list):
    """Extract Telegram bot exfiltration config."""
    config = {"bot_token": None, "chat_id": None}
    for s in strings_list:
        if re.match(r'\d{8,12}:[A-Za-z0-9_-]{35}', s):
            config["bot_token"] = s
        if re.match(r'^-?\d{9,13}$', s):
            config["chat_id"] = s
    return config


def decode_base64_strings(strings_list):
    """Try to decode base64-encoded configuration strings."""
    decoded = []
    for s in strings_list:
        if len(s) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', s):
            try:
                d = base64.b64decode(s).decode("utf-8", errors="replace")
                if any(c.isprintable() for c in d) and len(d) > 4:
                    decoded.append({"encoded": s[:40], "decoded": d[:100]})
            except Exception:
                pass
    return decoded


def analyze_sample(file_path):
    """Full analysis of suspected Agent Tesla sample."""
    hashes = compute_file_hashes(file_path)
    strings = extract_strings(file_path)

    indicators_found = []
    for indicator in AGENT_TESLA_INDICATORS["strings"]:
        if any(indicator.lower() in s.lower() for s in strings):
            indicators_found.append(indicator)

    smtp = find_smtp_config(strings)
    ftp = find_ftp_config(strings)
    telegram = find_telegram_config(strings)
    b64_decoded = decode_base64_strings(strings)

    return {
        "file": file_path,
        "file_size": os.path.getsize(file_path),
        "hashes": hashes,
        "agent_tesla_indicators": indicators_found,
        "is_agent_tesla": len(indicators_found) >= 3,
        "config": {
            "smtp": smtp,
            "ftp": ftp,
            "telegram": telegram,
        },
        "base64_decoded": b64_decoded[:10],
        "total_strings": len(strings),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract configuration from Agent Tesla RAT samples"
    )
    parser.add_argument("sample", help="Path to suspected Agent Tesla sample")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Agent Tesla Configuration Extraction Agent")
    result = analyze_sample(args.sample)

    print(f"[*] SHA256: {result['hashes']['sha256']}")
    print(f"[*] Agent Tesla indicators: {len(result['agent_tesla_indicators'])}")
    print(f"[*] Likely Agent Tesla: {result['is_agent_tesla']}")

    if result["config"]["smtp"]["smtp_server"]:
        print(f"[*] SMTP C2: {result['config']['smtp']['smtp_server']}")
    if result["config"]["telegram"]["bot_token"]:
        print(f"[*] Telegram bot found")

    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "analysis": result}

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
