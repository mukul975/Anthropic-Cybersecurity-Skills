#!/usr/bin/env python3
"""
Go Malware Binary Analyzer

Extracts metadata, function names, dependencies, and suspicious
indicators from Go-compiled malware binaries.

Usage:
    python process.py --file malware.exe --output report.json
"""

import argparse
import json
import re
import struct
import sys
from pathlib import Path


PCLNTAB_MAGICS = {
    b'\xf0\xff\xff\xff': "Go 1.20+",
    b'\xf1\xff\xff\xff': "Go 1.18-1.19",
    b'\xfa\xff\xff\xff': "Go 1.16-1.17",
    b'\xfb\xff\xff\xff': "Go 1.2-1.15",
}


def find_pclntab(data):
    for magic, version in PCLNTAB_MAGICS.items():
        offset = data.find(magic)
        if offset != -1:
            return offset, version
    return None, None


def extract_go_version(data):
    match = re.search(rb'go(\d+\.\d+(?:\.\d+)?)', data)
    return match.group(1).decode() if match else "unknown"


def extract_functions(data):
    func_pattern = re.compile(
        rb'((?:main|runtime|fmt|net|os|crypto|encoding|io|sync|'
        rb'syscall|reflect|strings|bytes|path|time|math|sort|'
        rb'github\.com|golang\.org|gopkg\.in)[/\.][\w/.]+)'
    )
    functions = set()
    for match in func_pattern.finditer(data):
        name = match.group(1).decode('utf-8', errors='replace')
        if 4 < len(name) < 200:
            functions.add(name)
    return sorted(functions)


def extract_dependencies(data):
    dep_pattern = re.compile(
        rb'((?:github\.com|gitlab\.com|golang\.org|gopkg\.in|'
        rb'go\.etcd\.io|google\.golang\.org)/[\w./-]{5,80})'
    )
    deps = set()
    for match in dep_pattern.finditer(data):
        dep = match.group(1).decode('utf-8', errors='replace')
        # Clean up trailing artifacts
        dep = dep.rstrip('/.')
        deps.add(dep)
    return sorted(deps)


def extract_suspicious_strings(data):
    interesting_patterns = [
        rb'https?://[\w./:?&=-]+',
        rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?',
        rb'(?:cmd|powershell|bash|sh)(?:\.exe)?',
        rb'(?:HKLM|HKCU)\\[^\x00]+',
        rb'/etc/(?:passwd|shadow|crontab)',
    ]

    results = {}
    for pattern in interesting_patterns:
        matches = re.findall(pattern, data)
        if matches:
            decoded = [m.decode('utf-8', errors='replace') for m in matches]
            results[pattern.decode('utf-8', errors='replace')] = list(set(decoded))

    return results


def categorize_functions(functions):
    categories = {
        "main_logic": [],
        "networking": [],
        "cryptography": [],
        "os_execution": [],
        "file_operations": [],
        "third_party": [],
        "runtime": [],
    }

    for func in functions:
        fl = func.lower()
        if func.startswith('main.'):
            categories["main_logic"].append(func)
        elif any(x in fl for x in ['net/', 'http', 'tcp', 'udp', 'dns']):
            categories["networking"].append(func)
        elif 'crypto' in fl:
            categories["cryptography"].append(func)
        elif any(x in fl for x in ['os/exec', 'syscall']):
            categories["os_execution"].append(func)
        elif any(x in fl for x in ['os.', 'io/', 'ioutil']):
            categories["file_operations"].append(func)
        elif any(x in fl for x in ['github.com', 'golang.org', 'gopkg.in']):
            categories["third_party"].append(func)
        elif func.startswith('runtime.'):
            categories["runtime"].append(func)

    return {k: v for k, v in categories.items() if v}


def analyze(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    report = {
        "file": str(filepath),
        "size": len(data),
        "go_version": extract_go_version(data),
    }

    pclntab_offset, pclntab_version = find_pclntab(data)
    report["pclntab"] = {
        "offset": f"0x{pclntab_offset:x}" if pclntab_offset else None,
        "version": pclntab_version,
    }

    functions = extract_functions(data)
    report["total_functions"] = len(functions)
    report["function_categories"] = categorize_functions(functions)

    report["dependencies"] = extract_dependencies(data)
    report["suspicious_strings"] = extract_suspicious_strings(data)

    return report


def main():
    parser = argparse.ArgumentParser(description="Go Malware Analyzer")
    parser.add_argument("--file", required=True, help="Go binary to analyze")
    parser.add_argument("--output", help="Output JSON report")

    args = parser.parse_args()
    report = analyze(args.file)

    print(json.dumps(report, indent=2))

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
