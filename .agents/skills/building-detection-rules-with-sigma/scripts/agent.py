#!/usr/bin/env python3
"""Agent for building and converting Sigma detection rules."""

import os
import json
import argparse
from datetime import datetime
from pathlib import Path

from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.collection import SigmaCollection


def load_sigma_rule(rule_path):
    """Load a Sigma rule from a YAML file."""
    with open(rule_path) as f:
        return SigmaRule.from_yaml(f.read())


def load_sigma_directory(directory):
    """Load all Sigma rules from a directory."""
    rules = []
    for path in Path(directory).rglob("*.yml"):
        try:
            rule = load_sigma_rule(str(path))
            rules.append({"path": str(path), "rule": rule})
        except Exception as e:
            print(f"  Warning: Failed to parse {path}: {e}")
    return rules


def convert_to_splunk(rule):
    """Convert a Sigma rule to Splunk SPL query."""
    pipeline = splunk_windows_pipeline()
    backend = SplunkBackend(pipeline)
    queries = backend.convert_rule(rule)
    return queries


def convert_to_splunk_savedsearch(rule):
    """Convert a Sigma rule to Splunk saved search format."""
    pipeline = splunk_windows_pipeline()
    backend = SplunkBackend(pipeline)
    return backend.convert_rule(rule, output_format="savedsearches")


def validate_sigma_rule(rule_path):
    """Validate a Sigma rule for syntax and best practices."""
    issues = []
    try:
        rule = load_sigma_rule(rule_path)
        if not rule.title:
            issues.append("Missing title")
        if not rule.id:
            issues.append("Missing rule ID")
        if not rule.level:
            issues.append("Missing severity level")
        if not rule.tags:
            issues.append("Missing ATT&CK tags")
        if not rule.description:
            issues.append("Missing description")
        if not rule.logsource:
            issues.append("Missing logsource definition")
        return {"valid": len(issues) == 0, "issues": issues, "title": str(rule.title)}
    except Exception as e:
        return {"valid": False, "issues": [str(e)]}


def extract_attack_techniques(rules):
    """Extract MITRE ATT&CK technique IDs from Sigma rules."""
    techniques = {}
    for entry in rules:
        rule = entry["rule"]
        for tag in rule.tags:
            tag_str = str(tag)
            if tag_str.startswith("attack.t"):
                technique_id = tag_str.replace("attack.", "").upper()
                if technique_id not in techniques:
                    techniques[technique_id] = []
                techniques[technique_id].append(str(rule.title))
    return techniques


def generate_attack_navigator_layer(techniques, layer_name="Sigma Detection Coverage"):
    """Generate a MITRE ATT&CK Navigator layer JSON from extracted techniques."""
    layer = {
        "name": layer_name,
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [],
    }
    for tid, rule_names in techniques.items():
        layer["techniques"].append({
            "techniqueID": tid,
            "color": "#31a354",
            "score": len(rule_names),
            "comment": "; ".join(rule_names[:3]),
        })
    return layer


def batch_convert(directory, backend_name="splunk"):
    """Batch convert all Sigma rules in a directory to target backend."""
    rules = load_sigma_directory(directory)
    converted = []
    for entry in rules:
        try:
            if backend_name == "splunk":
                queries = convert_to_splunk(entry["rule"])
                converted.append({
                    "file": entry["path"],
                    "title": str(entry["rule"].title),
                    "level": str(entry["rule"].level),
                    "queries": [str(q) for q in queries],
                })
        except Exception as e:
            converted.append({"file": entry["path"], "error": str(e)})
    return converted


def main():
    parser = argparse.ArgumentParser(description="Sigma Detection Rule Builder Agent")
    parser.add_argument("--rule", help="Path to a single Sigma rule YAML file")
    parser.add_argument("--directory", help="Directory of Sigma rules")
    parser.add_argument("--backend", choices=["splunk"], default="splunk")
    parser.add_argument("--output", default="sigma_output.json")
    parser.add_argument("--action", choices=[
        "validate", "convert", "batch_convert", "coverage", "full_pipeline"
    ], default="full_pipeline")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat()}

    if args.action == "validate" and args.rule:
        result = validate_sigma_rule(args.rule)
        print(f"[+] Validation: {'PASS' if result['valid'] else 'FAIL'}")
        if result["issues"]:
            for issue in result["issues"]:
                print(f"    - {issue}")
        report["validation"] = result

    if args.action == "convert" and args.rule:
        rule = load_sigma_rule(args.rule)
        queries = convert_to_splunk(rule)
        print(f"[+] Converted '{rule.title}' to Splunk SPL:")
        for q in queries:
            print(f"    {q}")
        report["conversion"] = {"title": str(rule.title), "queries": [str(q) for q in queries]}

    if args.action in ("batch_convert", "full_pipeline") and args.directory:
        converted = batch_convert(args.directory, args.backend)
        success = sum(1 for c in converted if "queries" in c)
        print(f"[+] Batch converted {success}/{len(converted)} rules to {args.backend}")
        report["batch_conversion"] = converted

    if args.action in ("coverage", "full_pipeline") and args.directory:
        rules = load_sigma_directory(args.directory)
        techniques = extract_attack_techniques(rules)
        layer = generate_attack_navigator_layer(techniques)
        layer_path = args.output.replace(".json", "_layer.json")
        with open(layer_path, "w") as f:
            json.dump(layer, f, indent=2)
        print(f"[+] ATT&CK coverage: {len(techniques)} techniques from {len(rules)} rules")
        print(f"[+] Navigator layer saved to {layer_path}")
        report["coverage"] = {"techniques": len(techniques), "rules": len(rules)}

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Output saved to {args.output}")


if __name__ == "__main__":
    main()
