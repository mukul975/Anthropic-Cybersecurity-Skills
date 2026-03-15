#!/usr/bin/env python3
"""PowerShell Script Block Logging Analyzer - Parses Event 4104 from EVTX for obfuscated commands."""

import json
import math
import re
import base64
import logging
import argparse
from collections import defaultdict
from datetime import datetime

from Evtx.Evtx import FileHeader
from lxml import etree

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

SUSPICIOUS_PATTERNS = [
    (r"(?i)\-[Ee]ncoded[Cc]ommand", "Encoded command parameter", "T1059.001", "high"),
    (r"(?i)FromBase64String", "Base64 decoding", "T1140", "high"),
    (r"(?i)(Invoke-Expression|iex)\s*\(", "Invoke-Expression execution", "T1059.001", "high"),
    (r"(?i)(DownloadString|DownloadFile|Invoke-WebRequest|wget|curl)", "Download cradle", "T1105", "critical"),
    (r"(?i)(Net\.WebClient|WebRequest\.Create)", "Network client instantiation", "T1071.001", "high"),
    (r"(?i)(AmsiUtils|amsiInitFailed|AmsiScanBuffer)", "AMSI bypass attempt", "T1562.001", "critical"),
    (r"(?i)(Invoke-Mimikatz|Invoke-Kerberoast|Invoke-TokenManipulation)", "Offensive PowerShell tool", "T1003", "critical"),
    (r"(?i)(Add-MpPreference\s*-ExclusionPath)", "Defender exclusion", "T1562.001", "high"),
    (r"(?i)(Set-MpPreference\s*-DisableRealtimeMonitoring)", "Defender disable", "T1562.001", "critical"),
    (r"(?i)(New-Object\s+System\.Net\.Sockets\.TCPClient)", "Reverse shell pattern", "T1059.001", "critical"),
    (r"(?i)(Get-Process\s+lsass|MiniDump)", "LSASS dump attempt", "T1003.001", "critical"),
    (r"(?i)(ConvertTo-SecureString|PSCredential)", "Credential handling", "T1078", "medium"),
]


def calculate_entropy(text):
    """Calculate Shannon entropy of a string to detect obfuscation."""
    if not text:
        return 0.0
    freq = defaultdict(int)
    for char in text:
        freq[char] += 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def parse_evtx_4104(evtx_path):
    """Parse Event ID 4104 entries from a PowerShell Operational EVTX file."""
    script_blocks = defaultdict(dict)
    with open(evtx_path, "rb") as f:
        fh = FileHeader(f)
        for record in fh.records():
            try:
                xml = record.xml()
                root = etree.fromstring(xml.encode("utf-8"))
                event_id_elem = root.find(".//evt:System/evt:EventID", NS)
                if event_id_elem is None or event_id_elem.text != "4104":
                    continue
                event_data = {}
                for data_elem in root.findall(".//evt:EventData/evt:Data", NS):
                    name = data_elem.get("Name", "")
                    event_data[name] = data_elem.text or ""
                script_block_id = event_data.get("ScriptBlockId", "")
                message_number = int(event_data.get("MessageNumber", "1"))
                message_total = int(event_data.get("MessageTotal", "1"))
                script_text = event_data.get("ScriptBlockText", "")
                time_elem = root.find(".//evt:System/evt:TimeCreated", NS)
                timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""
                if script_block_id not in script_blocks:
                    script_blocks[script_block_id] = {
                        "parts": {},
                        "total": message_total,
                        "timestamp": timestamp,
                        "path": event_data.get("Path", ""),
                    }
                script_blocks[script_block_id]["parts"][message_number] = script_text
            except Exception:
                continue
    logger.info("Parsed %d unique script blocks from %s", len(script_blocks), evtx_path)
    return script_blocks


def reconstruct_scripts(script_blocks):
    """Reconstruct full scripts from multi-part script block entries."""
    reconstructed = []
    for block_id, block_data in script_blocks.items():
        parts = block_data["parts"]
        total = block_data["total"]
        ordered = [parts.get(i, "") for i in range(1, total + 1)]
        full_script = "".join(ordered)
        reconstructed.append({
            "script_block_id": block_id,
            "timestamp": block_data["timestamp"],
            "path": block_data["path"],
            "part_count": total,
            "script_text": full_script,
            "length": len(full_script),
        })
    logger.info("Reconstructed %d complete scripts", len(reconstructed))
    return reconstructed


def decode_base64_commands(script_text):
    """Attempt to decode Base64-encoded command strings found in scripts."""
    decoded_commands = []
    b64_pattern = re.compile(r"[A-Za-z0-9+/=]{40,}")
    for match in b64_pattern.finditer(script_text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-16-le", errors="ignore")
            if any(c.isalpha() for c in decoded[:20]):
                decoded_commands.append({"encoded": match.group()[:60], "decoded": decoded[:500]})
        except Exception:
            continue
    return decoded_commands


def analyze_script(script_entry):
    """Analyze a single reconstructed script for suspicious patterns."""
    text = script_entry["script_text"]
    findings = []
    for pattern, description, mitre, severity in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            findings.append({
                "pattern": description,
                "mitre_technique": mitre,
                "severity": severity,
                "match_count": len(matches),
                "sample": matches[0][:100] if matches else "",
            })
    entropy = calculate_entropy(text)
    if entropy > 5.5 and len(text) > 200:
        findings.append({
            "pattern": "High entropy (possible obfuscation)",
            "mitre_technique": "T1027",
            "severity": "medium",
            "entropy": round(entropy, 2),
        })
    decoded = decode_base64_commands(text)
    if decoded:
        findings.append({
            "pattern": "Base64-encoded content decoded",
            "mitre_technique": "T1140",
            "severity": "high",
            "decoded_count": len(decoded),
            "samples": decoded[:3],
        })
    return findings


def generate_report(scripts, all_findings):
    """Generate PowerShell script block analysis report."""
    critical = sum(1 for f in all_findings if any(ff["severity"] == "critical" for ff in f["findings"]))
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_scripts": len(scripts),
        "suspicious_scripts": len([f for f in all_findings if f["findings"]]),
        "critical_scripts": critical,
        "findings": all_findings[:50],
    }
    print(f"PS SCRIPT BLOCK REPORT: {len(scripts)} scripts, {critical} critical")
    return report


def main():
    parser = argparse.ArgumentParser(description="PowerShell Script Block Logging Analyzer")
    parser.add_argument("--evtx-file", required=True, help="Path to PowerShell Operational EVTX")
    parser.add_argument("--output", default="ps_analysis.json")
    args = parser.parse_args()

    blocks = parse_evtx_4104(args.evtx_file)
    scripts = reconstruct_scripts(blocks)

    all_findings = []
    for script in scripts:
        findings = analyze_script(script)
        if findings:
            all_findings.append({
                "script_block_id": script["script_block_id"],
                "timestamp": script["timestamp"],
                "path": script["path"],
                "length": script["length"],
                "findings": findings,
                "script_preview": script["script_text"][:300],
            })

    report = generate_report(scripts, all_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
