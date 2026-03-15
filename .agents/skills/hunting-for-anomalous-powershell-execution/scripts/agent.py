#!/usr/bin/env python3
"""PowerShell Script Block Logging threat hunting agent."""

import json
import sys
import argparse
import base64
import re
from datetime import datetime
from collections import defaultdict

try:
    import Evtx.Evtx as evtx
    from lxml import etree
except ImportError:
    print("Install: pip install python-evtx lxml")
    sys.exit(1)

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

AMSI_INDICATORS = [
    "amsiutils", "amsiinitfailed", "amsicontext", "amsisession",
    "amsiinitialize", "amsi.dll", "amsiScanBuffer",
    "System.Management.Automation.AmsiUtils",
]

SUSPICIOUS_KEYWORDS = [
    "Invoke-Mimikatz", "Invoke-Kerberoast", "Invoke-ShellCode",
    "Invoke-ReflectivePEInjection", "Invoke-TokenManipulation",
    "Get-GPPPassword", "Get-Keystrokes", "Get-TimedScreenshot",
    "Out-Minidump", "Invoke-NinjaCopy", "Invoke-CredentialInjection",
    "Invoke-DllInjection", "Invoke-WMICommand", "PowerSploit",
    "Empire", "BloodHound", "Rubeus", "SharpHound",
    "Invoke-PSInject", "Invoke-RunAs", "PowerView",
]

DOWNLOAD_PATTERNS = [
    r"Net\.WebClient", r"Invoke-WebRequest", r"wget\s", r"curl\s",
    r"DownloadString", r"DownloadFile", r"DownloadData",
    r"Start-BitsTransfer", r"Invoke-RestMethod",
    r"New-Object\s+IO\.MemoryStream",
]

OBFUSCATION_PATTERNS = [
    r"-[Ee]nc(?:oded)?[Cc]ommand",
    r"\-e\s+[A-Za-z0-9+/=]{20,}",
    r"IEX\s*\(",
    r"Invoke-Expression",
    r"\[Convert\]::FromBase64String",
    r"\[System\.Text\.Encoding\]::",
    r"\.Replace\(['\"][^'\"]+['\"],\s*['\"][^'\"]+['\"]\)",
    r"-join\s*\[char\[\]\]",
    r"\$env:comspec",
]


def parse_evtx_4104(evtx_path, max_events=10000):
    """Parse Event 4104 script block logging entries from EVTX."""
    events = []
    count = 0
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            if count >= max_events:
                break
            xml = record.xml()
            root = etree.fromstring(xml.encode("utf-8"))
            event_id_el = root.find(".//e:System/e:EventID", NS)
            if event_id_el is None or event_id_el.text != "4104":
                continue
            count += 1
            time_el = root.find(".//e:System/e:TimeCreated", NS)
            timestamp = time_el.get("SystemTime", "") if time_el is not None else ""
            data = {}
            for el in root.findall(".//e:EventData/e:Data", NS):
                name = el.get("Name", "")
                data[name] = el.text or ""
            events.append({
                "timestamp": timestamp,
                "script_block_id": data.get("ScriptBlockId", ""),
                "script_block_text": data.get("ScriptBlockText", ""),
                "message_number": data.get("MessageNumber", "1"),
                "message_total": data.get("MessageTotal", "1"),
                "path": data.get("Path", ""),
            })
    return events


def reassemble_script_blocks(events):
    """Reassemble multi-part script blocks by ScriptBlockId."""
    blocks = defaultdict(list)
    for ev in events:
        sb_id = ev.get("script_block_id", "")
        if sb_id:
            blocks[sb_id].append(ev)
    assembled = []
    for sb_id, parts in blocks.items():
        parts.sort(key=lambda x: int(x.get("message_number", "1")))
        full_text = "".join(p.get("script_block_text", "") for p in parts)
        assembled.append({
            "script_block_id": sb_id,
            "timestamp": parts[0].get("timestamp", ""),
            "path": parts[0].get("path", ""),
            "parts": len(parts),
            "full_text": full_text,
        })
    return assembled


def detect_amsi_bypass(script_text):
    """Check script text for AMSI bypass indicators."""
    findings = []
    lower = script_text.lower()
    for indicator in AMSI_INDICATORS:
        if indicator.lower() in lower:
            findings.append({"type": "amsi_bypass", "indicator": indicator})
    return findings


def detect_suspicious_keywords(script_text):
    """Check for known offensive tool keywords."""
    findings = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in script_text.lower():
            findings.append({"type": "credential_or_offensive_tool", "keyword": kw})
    return findings


def detect_download_cradles(script_text):
    """Detect download cradle patterns in script text."""
    findings = []
    for pattern in DOWNLOAD_PATTERNS:
        if re.search(pattern, script_text, re.IGNORECASE):
            findings.append({"type": "download_cradle", "pattern": pattern})
    return findings


def detect_obfuscation(script_text):
    """Detect obfuscation and encoded command patterns."""
    findings = []
    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, script_text, re.IGNORECASE):
            findings.append({"type": "obfuscation", "pattern": pattern})
    b64_match = re.search(r"[A-Za-z0-9+/=]{40,}", script_text)
    if b64_match:
        try:
            decoded = base64.b64decode(b64_match.group()).decode("utf-16-le", errors="ignore")
            if any(c.isalpha() for c in decoded[:20]):
                findings.append({
                    "type": "encoded_payload",
                    "decoded_preview": decoded[:200],
                })
        except Exception:
            pass
    return findings


def hunt_scripts(assembled_blocks):
    """Run all detection checks on assembled script blocks."""
    results = []
    for block in assembled_blocks:
        text = block.get("full_text", "")
        if not text.strip():
            continue
        findings = []
        findings.extend(detect_amsi_bypass(text))
        findings.extend(detect_suspicious_keywords(text))
        findings.extend(detect_download_cradles(text))
        findings.extend(detect_obfuscation(text))
        if findings:
            results.append({
                "script_block_id": block["script_block_id"],
                "timestamp": block["timestamp"],
                "path": block["path"],
                "text_preview": text[:300],
                "findings": findings,
                "severity": "high" if any(
                    f["type"] in ("amsi_bypass", "credential_or_offensive_tool")
                    for f in findings
                ) else "medium",
            })
    return results


def run_audit(args):
    """Execute PowerShell script block hunting."""
    print(f"\n{'='*60}")
    print(f"  POWERSHELL SCRIPT BLOCK HUNTING")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}
    events = parse_evtx_4104(args.evtx, args.max_events)
    report["total_4104_events"] = len(events)
    print(f"Parsed {len(events)} Event 4104 records\n")

    blocks = reassemble_script_blocks(events)
    report["unique_script_blocks"] = len(blocks)
    print(f"Reassembled {len(blocks)} unique script blocks\n")

    results = hunt_scripts(blocks)
    report["suspicious_blocks"] = len(results)
    report["findings"] = results

    amsi = sum(1 for r in results if any(f["type"] == "amsi_bypass" for f in r["findings"]))
    cred = sum(1 for r in results if any(f["type"] == "credential_or_offensive_tool" for f in r["findings"]))
    dl = sum(1 for r in results if any(f["type"] == "download_cradle" for f in r["findings"]))
    obf = sum(1 for r in results if any(f["type"] == "obfuscation" for f in r["findings"]))
    report["summary"] = {
        "amsi_bypass_attempts": amsi,
        "credential_access": cred,
        "download_cradles": dl,
        "obfuscation_detected": obf,
    }

    print(f"--- HUNT RESULTS ---")
    print(f"  AMSI bypass attempts: {amsi}")
    print(f"  Credential/offensive tools: {cred}")
    print(f"  Download cradles: {dl}")
    print(f"  Obfuscation detected: {obf}")
    print(f"\n--- HIGH SEVERITY ---")
    for r in results[:15]:
        if r["severity"] == "high":
            print(f"  [{r['timestamp']}] {r['script_block_id']}")
            for f in r["findings"]:
                print(f"    {f['type']}: {f.get('keyword', f.get('indicator', ''))}")

    return report


def main():
    parser = argparse.ArgumentParser(description="PowerShell Script Block Hunting Agent")
    parser.add_argument("--evtx", required=True,
                        help="Path to PowerShell Operational .evtx file")
    parser.add_argument("--max-events", type=int, default=10000,
                        help="Max events to parse (default: 10000)")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
