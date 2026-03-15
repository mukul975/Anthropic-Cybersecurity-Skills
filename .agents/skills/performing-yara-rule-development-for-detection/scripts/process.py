#!/usr/bin/env python3
"""
YARA Rule Development and Testing Framework

Assists in creating, testing, and optimizing YARA rules
for malware detection.

Requirements:
    pip install yara-python pefile

Usage:
    python process.py --analyze sample.exe
    python process.py --test rule.yar --samples ./malware --clean ./goodware
    python process.py --generate --name MalwareX --strings strings.txt
"""

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

try:
    import yara
except ImportError:
    print("ERROR: yara-python not installed. Run: pip install yara-python")
    sys.exit(1)

try:
    import pefile
except ImportError:
    pefile = None


class YaraRuleBuilder:
    """Build and test YARA rules."""

    def __init__(self):
        self.candidate_strings = []
        self.candidate_hex = []
        self.imports = []

    def analyze_sample(self, filepath):
        """Extract candidate patterns from a malware sample."""
        with open(filepath, 'rb') as f:
            data = f.read()

        # Extract ASCII strings (min 8 chars)
        ascii_strings = [
            s.decode('ascii')
            for s in re.findall(rb'[\x20-\x7e]{8,}', data)
        ]

        # Extract wide strings
        wide_strings = [
            s.decode('utf-16-le')
            for s in re.findall(rb'(?:[\x20-\x7e]\x00){8,}', data)
        ]

        # Score strings by uniqueness/suspiciousness
        suspicious = [
            'http', 'https', 'ftp', 'cmd.exe', 'powershell',
            'mutex', 'pipe', 'password', 'encrypt', 'decrypt',
            'inject', 'hook', 'shell', 'backdoor', 'keylog',
            'screenshot', 'clipboard', 'download', 'upload',
            'sandbox', 'vmware', 'virtualbox', 'debug',
        ]

        scored = []
        for s in ascii_strings + wide_strings:
            score = 0
            s_lower = s.lower()
            for kw in suspicious:
                if kw in s_lower:
                    score += 10
            if len(s) > 20:
                score += 5
            if re.search(r'[A-Z][a-z]+[A-Z]', s):  # CamelCase
                score += 3
            scored.append((s, score))

        scored.sort(key=lambda x: -x[1])
        self.candidate_strings = scored[:30]

        # PE imports if available
        if pefile:
            try:
                pe = pefile.PE(filepath)
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                self.imports.append(
                                    imp.name.decode('utf-8', errors='replace')
                                )
            except Exception:
                pass

        return {
            "total_ascii": len(ascii_strings),
            "total_wide": len(wide_strings),
            "top_candidates": [(s, sc) for s, sc in scored[:10]],
            "suspicious_imports": [
                i for i in self.imports
                if i in ['VirtualAlloc', 'VirtualAllocEx',
                         'WriteProcessMemory', 'CreateRemoteThread',
                         'NtUnmapViewOfSection', 'OpenProcess',
                         'CryptEncrypt', 'InternetOpenA']
            ],
        }

    def generate_rule(self, name, author="analyst", description=""):
        """Generate YARA rule from analyzed patterns."""
        strings_section = []
        conditions = []

        # Add top candidate strings
        for i, (s, score) in enumerate(self.candidate_strings[:8]):
            if score > 0:
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                strings_section.append(
                    f'$str{i} = "{escaped}" ascii wide'
                )

        # Add import-based strings
        sus_imports = [
            i for i in self.imports
            if i in ['VirtualAlloc', 'VirtualAllocEx',
                     'WriteProcessMemory', 'CreateRemoteThread']
        ]
        for i, imp in enumerate(sus_imports[:4]):
            strings_section.append(f'$api{i} = "{imp}" ascii')

        # Build condition
        str_count = len([s for s in strings_section if s.startswith('$str')])
        api_count = len([s for s in strings_section if s.startswith('$api')])

        condition_parts = ['uint16(0) == 0x5A4D', 'filesize < 5MB']
        if str_count > 0:
            threshold = max(2, str_count // 2)
            condition_parts.append(f'{threshold} of ($str*)')
        if api_count > 0:
            condition_parts.append(f'{max(1, api_count - 1)} of ($api*)')

        rule = f"""rule {name} {{
    meta:
        description = "{description or f'Detects {name}'}"
        author = "{author}"
        date = "{time.strftime('%Y-%m-%d')}"
        tlp = "WHITE"

    strings:
        {chr(10) + "        ".join(strings_section)}

    condition:
        {" and ".join(condition_parts)}
}}"""
        return rule

    def test_rule(self, rule_path_or_text, sample_dir, clean_dir=None):
        """Test YARA rule for detection and false positive rates."""
        if os.path.isfile(rule_path_or_text):
            rules = yara.compile(filepath=rule_path_or_text)
        else:
            rules = yara.compile(source=rule_path_or_text)

        results = {
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "scan_time": 0,
            "details": [],
        }

        # Scan malware samples
        start = time.perf_counter()
        for f in Path(sample_dir).rglob('*'):
            if f.is_file():
                try:
                    matches = rules.match(str(f))
                    if matches:
                        results["true_positives"] += 1
                    else:
                        results["false_negatives"] += 1
                        results["details"].append(
                            {"file": str(f), "result": "FALSE_NEGATIVE"}
                        )
                except Exception:
                    pass

        # Scan clean files
        if clean_dir:
            for f in Path(clean_dir).rglob('*'):
                if f.is_file():
                    try:
                        matches = rules.match(str(f))
                        if matches:
                            results["false_positives"] += 1
                            results["details"].append(
                                {"file": str(f), "result": "FALSE_POSITIVE"}
                            )
                        else:
                            results["true_negatives"] += 1
                    except Exception:
                        pass

        results["scan_time"] = time.perf_counter() - start

        total_samples = results["true_positives"] + results["false_negatives"]
        if total_samples > 0:
            results["detection_rate"] = round(
                results["true_positives"] / total_samples * 100, 2
            )

        total_clean = results["false_positives"] + results["true_negatives"]
        if total_clean > 0:
            results["fp_rate"] = round(
                results["false_positives"] / total_clean * 100, 4
            )

        return results


def main():
    parser = argparse.ArgumentParser(
        description="YARA Rule Development Framework"
    )
    parser.add_argument("--analyze", help="Analyze sample for YARA patterns")
    parser.add_argument("--generate", action="store_true",
                        help="Generate rule from analysis")
    parser.add_argument("--name", default="MalwareDetection",
                        help="Rule name")
    parser.add_argument("--test", help="Test YARA rule file")
    parser.add_argument("--samples", help="Malware samples directory")
    parser.add_argument("--clean", help="Clean files directory")
    parser.add_argument("--output", help="Output rule file")

    args = parser.parse_args()
    builder = YaraRuleBuilder()

    if args.analyze:
        analysis = builder.analyze_sample(args.analyze)
        print(json.dumps(analysis, indent=2, default=str))

        if args.generate:
            rule = builder.generate_rule(args.name)
            print(f"\n{rule}")
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(rule)
                print(f"[+] Rule saved to {args.output}")

    elif args.test and args.samples:
        results = builder.test_rule(args.test, args.samples, args.clean)
        print(json.dumps(results, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
