#!/usr/bin/env python3
"""Agent for implementing API threat protection policies with Google Apigee."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path


APIGEE_POLICIES = {
    "JSONThreatProtection": {
        "max_depth": 5, "max_string_length": 500,
        "max_entries": 25, "max_array_elements": 100,
    },
    "XMLThreatProtection": {
        "max_depth": 5, "max_attributes": 10,
        "max_element_name_length": 128, "max_text_length": 500,
    },
    "RegularExpressionProtection": {
        "patterns": [
            r"[\s]*((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update)|(or))",
            r"<\s*script\b[^>]*>[^<]+<\s*/\s*script\s*>",
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        ]
    },
    "SpikeArrest": {
        "rate": "30ps", "identifier": "request.header.x-api-key",
    },
}


def generate_json_threat_policy(config=None):
    """Generate Apigee JSONThreatProtection policy XML."""
    cfg = config or APIGEE_POLICIES["JSONThreatProtection"]
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<JSONThreatProtection name="JSON-Threat-Protection">
    <DisplayName>JSON Threat Protection</DisplayName>
    <ObjectEntryCount>{cfg['max_entries']}</ObjectEntryCount>
    <ArrayElementCount>{cfg['max_array_elements']}</ArrayElementCount>
    <ContainerDepth>{cfg['max_depth']}</ContainerDepth>
    <StringValueLength>{cfg['max_string_length']}</StringValueLength>
    <Source>request</Source>
</JSONThreatProtection>"""


def generate_spike_arrest_policy(rate="30ps"):
    """Generate Apigee SpikeArrest policy XML."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SpikeArrest name="Spike-Arrest">
    <DisplayName>Spike Arrest</DisplayName>
    <Rate>{rate}</Rate>
    <Identifier ref="request.header.x-api-key"/>
    <UseEffectiveCount>true</UseEffectiveCount>
</SpikeArrest>"""


def generate_regex_protection_policy():
    """Generate RegularExpressionProtection policy for SQL/XSS."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<RegularExpressionProtection name="Regex-Protection">
    <DisplayName>SQL Injection and XSS Protection</DisplayName>
    <Source>request</Source>
    <QueryParam name="*">
        <Pattern>[\s]*((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update))</Pattern>
        <Pattern>&lt;\\s*script\\b[^&gt;]*&gt;</Pattern>
    </QueryParam>
    <JSONPayload>
        <JSONPath>$.*</JSONPath>
        <Pattern>[\s]*((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update))</Pattern>
    </JSONPayload>
</RegularExpressionProtection>"""


def analyze_apigee_proxy_bundle(bundle_path):
    """Analyze an Apigee proxy bundle for security policy gaps."""
    findings = []
    bundle = Path(bundle_path)
    policies_dir = bundle / "apiproxy" / "policies"
    if not policies_dir.exists():
        return [{"issue": "no_policies_directory", "severity": "CRITICAL"}]
    policy_files = list(policies_dir.glob("*.xml"))
    policy_names = [p.stem for p in policy_files]
    required_policies = [
        ("JSONThreatProtection", "json_threat_protection", "HIGH"),
        ("SpikeArrest", "spike_arrest", "HIGH"),
        ("OAuthV2", "oauth_authentication", "CRITICAL"),
        ("CORS", "cors_policy", "MEDIUM"),
    ]
    for policy_type, issue_name, severity in required_policies:
        has_policy = any(policy_type.lower() in p.lower() for p in policy_names)
        if not has_policy:
            for pf in policy_files:
                content = pf.read_text(errors="ignore")
                if policy_type in content:
                    has_policy = True
                    break
        if not has_policy:
            findings.append({
                "issue": f"missing_{issue_name}",
                "policy_type": policy_type,
                "severity": severity,
            })
    return findings


def audit_threat_protection_config(policy_path):
    """Audit a threat protection policy for weak configurations."""
    findings = []
    content = Path(policy_path).read_text(errors="ignore")
    depth_match = re.search(r"<ContainerDepth>(\d+)</ContainerDepth>", content)
    if depth_match and int(depth_match.group(1)) > 10:
        findings.append({
            "issue": "excessive_container_depth",
            "value": int(depth_match.group(1)),
            "recommended": 5, "severity": "MEDIUM",
        })
    string_match = re.search(r"<StringValueLength>(\d+)</StringValueLength>", content)
    if string_match and int(string_match.group(1)) > 10000:
        findings.append({
            "issue": "excessive_string_length",
            "value": int(string_match.group(1)),
            "recommended": 500, "severity": "MEDIUM",
        })
    rate_match = re.search(r"<Rate>(\d+)(ps|pm)</Rate>", content)
    if rate_match:
        rate_val = int(rate_match.group(1))
        unit = rate_match.group(2)
        if unit == "ps" and rate_val > 100:
            findings.append({
                "issue": "spike_arrest_too_permissive",
                "rate": f"{rate_val}{unit}", "severity": "HIGH",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Apigee API Threat Protection Agent")
    parser.add_argument("--action", choices=[
        "generate", "audit_bundle", "audit_policy", "full"
    ], default="generate")
    parser.add_argument("--bundle", help="Apigee proxy bundle path")
    parser.add_argument("--policy", help="Policy XML file to audit")
    parser.add_argument("--output", default="apigee_threat_protection_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action == "generate":
        report["policies"] = {
            "json_threat_protection": generate_json_threat_policy(),
            "spike_arrest": generate_spike_arrest_policy(),
            "regex_protection": generate_regex_protection_policy(),
        }
        print("[+] Generated 3 Apigee security policies")

    if args.action in ("audit_bundle", "full") and args.bundle:
        f = analyze_apigee_proxy_bundle(args.bundle)
        report["findings"]["bundle_audit"] = f
        print(f"[+] Bundle audit findings: {len(f)}")

    if args.action in ("audit_policy", "full") and args.policy:
        f = audit_threat_protection_config(args.policy)
        report["findings"]["policy_audit"] = f
        print(f"[+] Policy audit findings: {len(f)}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
