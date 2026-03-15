#!/usr/bin/env python3
"""Agent for YARA rule development and testing.

Creates YARA rules from malware samples by extracting unique strings
and byte patterns, validates rules for performance, tests against
sample sets, and generates detection coverage reports.
"""

import json
import sys
import os
import hashlib
import re
from datetime import datetime
from pathlib import Path

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


class YaraRuleDeveloper:
    """Develops, validates, and tests YARA rules."""

    def __init__(self, output_dir="./yara_rules"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rules = []

    def extract_strings(self, sample_path, min_length=8, max_strings=30):
        """Extract unique strings from a binary sample for rule creation."""
        with open(sample_path, "rb") as f:
            data = f.read()

        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
        wide_strings = re.findall(
            rb'(?:[\x20-\x7E]\x00){%d,}' % min_length, data)

        unique_ascii = list(set(s.decode("ascii", errors="ignore")
                                for s in ascii_strings))
        unique_wide = list(set(s.decode("utf-16-le", errors="ignore")
                               for s in wide_strings))

        scored = []
        generic_terms = {"http", "https", "www", "com", "dll", "exe",
                         "the", "this", "that", "error", "warning"}
        for s in unique_ascii:
            score = len(s)
            if any(g in s.lower() for g in generic_terms):
                score -= 5
            if re.search(r'[A-Z][a-z]+[A-Z]', s):
                score += 3
            if "/" in s or "\\" in s:
                score += 2
            scored.append({"string": s, "type": "ascii", "score": score})

        for s in unique_wide:
            scored.append({"string": s, "type": "wide", "score": len(s) - 2})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:max_strings]

    def generate_rule(self, rule_name, sample_path, description="",
                      tags=None, author="auto"):
        """Generate a YARA rule from a malware sample."""
        strings = self.extract_strings(sample_path)
        sha256 = hashlib.sha256(Path(sample_path).read_bytes()).hexdigest()

        rule_strings = []
        for i, s in enumerate(strings[:15]):
            if s["type"] == "ascii":
                rule_strings.append(f'        $s{i} = "{s["string"]}"')
            else:
                rule_strings.append(f'        $s{i} = "{s["string"]}" wide')

        tags_str = " : " + " ".join(tags) if tags else ""
        rule_text = f"""rule {rule_name}{tags_str}
{{
    meta:
        description = "{description}"
        author = "{author}"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        hash = "{sha256}"

    strings:
{chr(10).join(rule_strings)}

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 5 of ($s*)
}}
"""
        rule_path = self.output_dir / f"{rule_name}.yar"
        rule_path.write_text(rule_text)
        self.rules.append({"name": rule_name, "path": str(rule_path),
                           "strings_count": len(rule_strings)})
        return {"rule_name": rule_name, "path": str(rule_path),
                "strings": len(rule_strings), "hash": sha256}

    def validate_rule(self, rule_path):
        """Compile and validate a YARA rule for syntax and performance."""
        if not HAS_YARA:
            return {"error": "yara-python not installed"}
        try:
            yara.compile(filepath=rule_path)
            return {"valid": True, "path": rule_path}
        except yara.SyntaxError as exc:
            return {"valid": False, "error": str(exc)}

    def test_rule(self, rule_path, sample_dir):
        """Test a YARA rule against a directory of samples."""
        if not HAS_YARA:
            return {"error": "yara-python not installed"}
        try:
            compiled = yara.compile(filepath=rule_path)
        except yara.SyntaxError as exc:
            return {"error": str(exc)}

        results = {"matches": [], "no_match": [], "errors": []}
        for root, dirs, files in os.walk(sample_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    matches = compiled.match(fpath, timeout=30)
                    if matches:
                        results["matches"].append({
                            "file": fpath, "rules": [m.rule for m in matches]})
                    else:
                        results["no_match"].append(fpath)
                except yara.Error as exc:
                    results["errors"].append({"file": fpath, "error": str(exc)})
        return results

    def generate_report(self):
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "rules_created": len(self.rules),
            "rules": self.rules,
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <rule_name> <sample_path> [test_dir]")
        sys.exit(1)
    agent = YaraRuleDeveloper()
    rule_name = sys.argv[1]
    sample = sys.argv[2]
    result = agent.generate_rule(rule_name, sample)
    validation = agent.validate_rule(result["path"])
    print(json.dumps({"rule": result, "validation": validation}, indent=2))
    if len(sys.argv) > 3:
        test_results = agent.test_rule(result["path"], sys.argv[3])
        print(json.dumps(test_results, indent=2))


if __name__ == "__main__":
    main()
