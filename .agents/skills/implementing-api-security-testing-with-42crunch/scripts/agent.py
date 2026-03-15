#!/usr/bin/env python3
"""Agent for API security testing using 42Crunch audit methodology."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


OWASP_API_CHECKS = {
    "API1:2023": {"name": "Broken Object Level Authorization", "check": "bola"},
    "API2:2023": {"name": "Broken Authentication", "check": "auth"},
    "API3:2023": {"name": "Broken Object Property Level Authorization", "check": "bopla"},
    "API4:2023": {"name": "Unrestricted Resource Consumption", "check": "resource"},
    "API5:2023": {"name": "Broken Function Level Authorization", "check": "bfla"},
    "API6:2023": {"name": "Unrestricted Access to Sensitive Business Flows", "check": "flow"},
    "API7:2023": {"name": "Server-Side Request Forgery", "check": "ssrf"},
    "API8:2023": {"name": "Security Misconfiguration", "check": "config"},
    "API9:2023": {"name": "Improper Inventory Management", "check": "inventory"},
    "API10:2023": {"name": "Unsafe Consumption of APIs", "check": "consumption"},
}


def load_spec(spec_path):
    """Load OpenAPI spec."""
    with open(spec_path) as f:
        if spec_path.endswith((".yaml", ".yml")):
            return yaml.safe_load(f)
        return json.load(f)


def audit_spec_security(spec):
    """Perform static security audit of OpenAPI specification."""
    findings = []
    security_schemes = spec.get("components", {}).get("securitySchemes", {})
    global_security = spec.get("security", [])
    if not security_schemes:
        findings.append({
            "owasp": "API2:2023", "issue": "no_security_schemes",
            "severity": "CRITICAL", "score_deduction": 30,
        })
    if not global_security:
        findings.append({
            "owasp": "API8:2023", "issue": "no_global_security",
            "severity": "HIGH", "score_deduction": 20,
        })
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            if details.get("security") == []:
                findings.append({
                    "path": path, "method": method.upper(),
                    "owasp": "API2:2023", "issue": "security_disabled",
                    "severity": "CRITICAL", "score_deduction": 25,
                })
            if method in ("post", "put", "patch"):
                body = details.get("requestBody", {})
                content = body.get("content", {})
                for media, media_def in content.items():
                    schema = media_def.get("schema", {})
                    if not schema:
                        findings.append({
                            "path": path, "method": method.upper(),
                            "owasp": "API3:2023", "issue": "no_input_schema",
                            "severity": "HIGH", "score_deduction": 15,
                        })
                    if schema.get("additionalProperties") is not False:
                        findings.append({
                            "path": path, "method": method.upper(),
                            "owasp": "API3:2023", "issue": "mass_assignment_risk",
                            "severity": "MEDIUM", "score_deduction": 10,
                        })
            for param in details.get("parameters", []):
                p_schema = param.get("schema", {})
                if p_schema.get("type") == "string" and not p_schema.get("maxLength"):
                    findings.append({
                        "path": path, "method": method.upper(),
                        "parameter": param.get("name"),
                        "owasp": "API4:2023", "issue": "unbounded_string",
                        "severity": "MEDIUM", "score_deduction": 5,
                    })
            responses = details.get("responses", {})
            if "429" not in responses:
                findings.append({
                    "path": path, "method": method.upper(),
                    "owasp": "API4:2023", "issue": "no_429_response",
                    "severity": "MEDIUM", "score_deduction": 5,
                })
    servers = spec.get("servers", [])
    for server in servers:
        url = server.get("url", "")
        if url.startswith("http://"):
            findings.append({
                "server": url, "owasp": "API8:2023",
                "issue": "http_not_https", "severity": "HIGH", "score_deduction": 15,
            })
    return findings


def calculate_security_score(findings):
    """Calculate security score (0-100) based on findings."""
    total_deduction = sum(f.get("score_deduction", 0) for f in findings)
    score = max(0, 100 - total_deduction)
    if score >= 80:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    else:
        grade = "F"
    return {"score": score, "grade": grade, "total_findings": len(findings)}


def main():
    parser = argparse.ArgumentParser(description="42Crunch-Style API Security Testing Agent")
    parser.add_argument("--spec", required=True, help="OpenAPI spec file")
    parser.add_argument("--output", default="api_security_test_report.json")
    args = parser.parse_args()

    spec = load_spec(args.spec)
    report = {"generated_at": datetime.utcnow().isoformat()}

    findings = audit_spec_security(spec)
    score = calculate_security_score(findings)
    report["security_score"] = score
    report["findings"] = findings
    report["owasp_coverage"] = {k: v["name"] for k, v in OWASP_API_CHECKS.items()}

    print(f"[+] Security Score: {score['score']}/100 (Grade: {score['grade']})")
    print(f"[+] Findings: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
