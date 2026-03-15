#!/usr/bin/env python3
"""Threat hunting agent using YARA rules.

Scans files and directories with yara-python, supports rule compilation,
multi-rule scanning, and structured JSON match output.
"""

import argparse
import json
import os
import sys
import hashlib
import datetime

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


BUILTIN_RULES = {
    "suspicious_powershell": """
rule Suspicious_PowerShell {
    meta:
        description = "Detects obfuscated PowerShell patterns"
        severity = "high"
    strings:
        $enc = "-EncodedCommand" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $iex = "IEX" ascii nocase
        $webclient = "Net.WebClient" ascii nocase
        $downloadstring = "DownloadString" ascii nocase
    condition:
        2 of them
}""",
    "mimikatz_strings": """
rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential harvesting tool"
        severity = "critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "sekurlsa::wdigest" ascii nocase
        $s3 = "lsadump::sam" ascii nocase
        $s4 = "privilege::debug" ascii nocase
        $s5 = "gentilkiwi" ascii wide
    condition:
        2 of them
}""",
    "webshell_generic": """
rule Webshell_Generic {
    meta:
        description = "Detects common webshell patterns"
        severity = "high"
    strings:
        $php1 = "eval($_POST" ascii nocase
        $php2 = "eval($_GET" ascii nocase
        $php3 = "eval($_REQUEST" ascii nocase
        $php4 = "base64_decode($_" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii
    condition:
        any of them
}""",
}


def compile_rules(rule_sources=None, rule_dir=None):
    """Compile YARA rules from strings or directory."""
    if not HAS_YARA:
        return None
    if rule_dir and os.path.isdir(rule_dir):
        filepaths = {}
        for f in os.listdir(rule_dir):
            if f.endswith((".yar", ".yara")):
                filepaths[f] = os.path.join(rule_dir, f)
        if filepaths:
            return yara.compile(filepaths=filepaths)
    if rule_sources:
        combined = "\n".join(rule_sources.values())
        return yara.compile(source=combined)
    return yara.compile(source="\n".join(BUILTIN_RULES.values()))


def scan_file(rules, filepath):
    """Scan a single file with compiled YARA rules."""
    try:
        matches = rules.match(filepath)
        return [
            {
                "rule": m.rule,
                "meta": m.meta,
                "strings": [
                    {"offset": s[0], "identifier": s[1], "data": s[2].decode("utf-8", errors="replace")[:64]}
                    for s in m.strings
                ],
                "tags": list(m.tags),
            }
            for m in matches
        ]
    except yara.Error as e:
        return [{"error": str(e)}]


def scan_directory(rules, directory, max_size_mb=50):
    """Recursively scan directory with YARA rules."""
    results = []
    max_bytes = max_size_mb * 1024 * 1024
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > max_bytes:
                    continue
                matches = scan_file(rules, fpath)
                if matches and not any("error" in m for m in matches):
                    sha256 = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                    results.append({"file": fpath, "sha256": sha256, "matches": matches})
            except (PermissionError, OSError):
                continue
    return results


def main():
    parser = argparse.ArgumentParser(description="YARA-based threat hunting scanner")
    parser.add_argument("target", nargs="?", help="File or directory to scan")
    parser.add_argument("--rules-dir", help="Directory containing .yar/.yara rule files")
    parser.add_argument("--max-size", type=int, default=50, help="Max file size in MB (default: 50)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] YARA Threat Hunting Agent")
    print(f"    yara-python available: {HAS_YARA}")

    if not HAS_YARA:
        print("[!] Install yara-python: pip install yara-python")
        sys.exit(1)

    rules = compile_rules(rule_dir=args.rules_dir)
    if not rules:
        print("[!] No rules compiled")
        sys.exit(1)

    report = {"timestamp": datetime.datetime.utcnow().isoformat() + "Z", "findings": []}

    if args.target and os.path.isfile(args.target):
        matches = scan_file(rules, args.target)
        if matches:
            report["findings"].append({"file": args.target, "matches": matches})
    elif args.target and os.path.isdir(args.target):
        report["findings"] = scan_directory(rules, args.target, args.max_size)
    else:
        print("[DEMO] Built-in rules available:")
        for name, rule in BUILTIN_RULES.items():
            desc = [l for l in rule.splitlines() if "description" in l]
            print(f"  {name}: {desc[0].strip() if desc else ''}")
        print("\nUsage: python agent.py /path/to/scan --rules-dir /path/to/rules")

    total = len(report["findings"])
    print(f"\n[*] Total files with matches: {total}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps({"files_matched": total, "rules_loaded": len(BUILTIN_RULES)}, indent=2))


if __name__ == "__main__":
    main()
