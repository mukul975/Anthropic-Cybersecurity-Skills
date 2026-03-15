#!/usr/bin/env python3
"""Agent for auditing API schema validation security using OpenAPI specs."""

import json
import argparse
import re
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

try:
    import jsonschema
except ImportError:
    jsonschema = None


def load_openapi_spec(spec_path):
    """Load an OpenAPI specification file."""
    with open(spec_path) as f:
        if spec_path.endswith((".yaml", ".yml")):
            return yaml.safe_load(f)
        return json.load(f)


def audit_schema_validation(spec):
    """Audit OpenAPI spec for missing schema validation."""
    findings = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ("get", "post", "put", "patch", "delete"):
                request_body = details.get("requestBody", {})
                if method in ("post", "put", "patch") and not request_body:
                    findings.append({
                        "path": path, "method": method.upper(),
                        "issue": "no_request_body_schema", "severity": "HIGH",
                    })
                elif request_body:
                    content = request_body.get("content", {})
                    for media, media_def in content.items():
                        schema = media_def.get("schema", {})
                        if not schema:
                            findings.append({
                                "path": path, "method": method.upper(),
                                "issue": "empty_request_schema", "severity": "HIGH",
                            })
                        elif schema.get("additionalProperties") is not False:
                            findings.append({
                                "path": path, "method": method.upper(),
                                "issue": "additional_properties_allowed",
                                "severity": "MEDIUM",
                                "risk": "mass_assignment",
                            })
                params = details.get("parameters", [])
                for param in params:
                    if not param.get("schema"):
                        findings.append({
                            "path": path, "method": method.upper(),
                            "parameter": param.get("name"),
                            "issue": "parameter_no_schema", "severity": "MEDIUM",
                        })
                    elif param.get("schema", {}).get("type") == "string":
                        schema = param["schema"]
                        if not schema.get("maxLength") and not schema.get("pattern"):
                            findings.append({
                                "path": path, "method": method.upper(),
                                "parameter": param.get("name"),
                                "issue": "string_no_max_length", "severity": "MEDIUM",
                                "risk": "injection",
                            })
                responses = details.get("responses", {})
                for code, resp in responses.items():
                    content = resp.get("content", {})
                    for media, media_def in content.items():
                        schema = media_def.get("schema", {})
                        if not schema:
                            findings.append({
                                "path": path, "method": method.upper(),
                                "response_code": code,
                                "issue": "no_response_schema", "severity": "MEDIUM",
                                "risk": "data_exposure",
                            })
    return findings


def check_security_definitions(spec):
    """Check security scheme definitions in OpenAPI spec."""
    findings = []
    version = spec.get("openapi", spec.get("swagger", ""))
    if version.startswith("3"):
        security_schemes = spec.get("components", {}).get("securitySchemes", {})
    else:
        security_schemes = spec.get("securityDefinitions", {})
    if not security_schemes:
        findings.append({"issue": "no_security_schemes_defined", "severity": "CRITICAL"})
    global_security = spec.get("security", [])
    if not global_security:
        findings.append({"issue": "no_global_security", "severity": "HIGH"})
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ("get", "post", "put", "patch", "delete"):
                op_security = details.get("security")
                if op_security == []:
                    findings.append({
                        "path": path, "method": method.upper(),
                        "issue": "security_explicitly_disabled", "severity": "CRITICAL",
                    })
    return findings


def validate_request_payload(schema_path, payload_path):
    """Validate a request payload against a JSON schema."""
    if jsonschema is None:
        return {"error": "jsonschema not installed"}
    with open(schema_path) as f:
        schema = json.load(f)
    with open(payload_path) as f:
        payload = json.load(f)
    errors = []
    v = jsonschema.Draft7Validator(schema)
    for error in v.iter_errors(payload):
        errors.append({
            "path": list(error.path),
            "message": error.message,
            "schema_path": list(error.schema_path),
        })
    return {"valid": len(errors) == 0, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description="API Schema Validation Security Agent")
    parser.add_argument("--spec", help="OpenAPI spec file (JSON/YAML)")
    parser.add_argument("--schema", help="JSON Schema for validation")
    parser.add_argument("--payload", help="Request payload to validate")
    parser.add_argument("--output", default="schema_validation_report.json")
    parser.add_argument("--action", choices=["audit", "security", "validate", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.spec:
        spec = load_openapi_spec(args.spec)
        if args.action in ("audit", "full"):
            f = audit_schema_validation(spec)
            report["findings"]["schema_audit"] = f
            print(f"[+] Schema validation issues: {len(f)}")
        if args.action in ("security", "full"):
            f = check_security_definitions(spec)
            report["findings"]["security_schemes"] = f
            print(f"[+] Security definition issues: {len(f)}")

    if args.action == "validate" and args.schema and args.payload:
        result = validate_request_payload(args.schema, args.payload)
        report["findings"]["validation"] = result
        print(f"[+] Validation: {'PASS' if result.get('valid') else 'FAIL'}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
