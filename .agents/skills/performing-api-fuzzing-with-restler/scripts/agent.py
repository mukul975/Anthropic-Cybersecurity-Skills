#!/usr/bin/env python3
# For authorized testing only
"""RESTler API fuzzing orchestration and result analysis agent."""

import json
import sys
import argparse
import subprocess
import os
from datetime import datetime


def compile_spec(restler_path, api_spec):
    """Compile OpenAPI spec into RESTler fuzzing grammar."""
    cmd = [
        os.path.join(restler_path, "Restler"), "compile",
        "--api_spec", api_spec,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    compile_dir = os.path.join(os.path.dirname(api_spec), "Compile")
    if os.path.isdir(compile_dir):
        grammar = os.path.join(compile_dir, "grammar.py")
        dictionary = os.path.join(compile_dir, "dict.json")
        return {
            "status": "success" if os.path.exists(grammar) else "failed",
            "grammar": grammar if os.path.exists(grammar) else None,
            "dictionary": dictionary if os.path.exists(dictionary) else None,
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
        }
    return {"status": "failed", "stderr": result.stderr[:500]}


def run_fuzz_mode(restler_path, grammar, dictionary, settings, target_ip,
                  target_port, mode="fuzz-lean", time_budget=1):
    """Run RESTler in test, fuzz-lean, or fuzz mode."""
    cmd = [
        os.path.join(restler_path, "Restler"), mode,
        "--grammar_file", grammar,
        "--dictionary_file", dictionary,
        "--settings", settings,
        "--target_ip", target_ip,
        "--target_port", str(target_port),
        "--time_budget", str(time_budget),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=time_budget * 3600 + 300)
    return {
        "mode": mode,
        "exit_code": result.returncode,
        "stdout_tail": result.stdout[-1000:] if result.stdout else "",
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
    }


def parse_run_summary(results_dir):
    """Parse RESTler run summary JSON from results directory."""
    summary_path = os.path.join(results_dir, "ResponseBuckets", "runSummary.json")
    if not os.path.exists(summary_path):
        return {"error": f"Summary not found at {summary_path}"}
    with open(summary_path, "r") as f:
        summary = json.load(f)
    return {
        "total_requests": summary.get("total_requests_sent", {}).get("num_requests", 0),
        "valid_2xx": summary.get("num_fully_valid", 0),
        "client_errors_4xx": summary.get("num_invalid", 0),
        "server_errors_5xx": summary.get("num_server_error", 0),
        "bugs_found": summary.get("num_bugs", 0),
        "covered_endpoints": len(summary.get("covered_endpoints", [])),
        "total_endpoints": len(summary.get("total_endpoints", [])),
    }


def parse_bug_buckets(results_dir):
    """Parse RESTler bug bucket files for discovered vulnerabilities."""
    bugs_dir = os.path.join(results_dir, "bug_buckets")
    if not os.path.isdir(bugs_dir):
        return []
    bugs = []
    for filename in sorted(os.listdir(bugs_dir)):
        if not filename.endswith(".txt"):
            continue
        filepath = os.path.join(bugs_dir, filename)
        with open(filepath, "r") as f:
            content = f.read()
        bug_type = "unknown"
        if "UseAfterFree" in filename:
            bug_type = "use_after_free"
        elif "NamespaceRule" in filename:
            bug_type = "namespace_violation"
        elif "ResourceHierarchy" in filename:
            bug_type = "resource_hierarchy"
        elif "LeakageRule" in filename:
            bug_type = "information_leakage"
        elif "500" in content[:200]:
            bug_type = "server_error_500"
        bugs.append({
            "file": filename,
            "type": bug_type,
            "severity": "CRITICAL" if bug_type in ("use_after_free", "namespace_violation") else "HIGH",
            "excerpt": content[:300],
        })
    return bugs


def generate_custom_dictionary(output_path):
    """Generate a security-focused fuzzing dictionary for RESTler."""
    dictionary = {
        "restler_fuzzable_string": [
            "fuzzstring", "' OR '1'='1", "\" OR \"1\"=\"1",
            "<script>alert(1)</script>", "../../../etc/passwd",
            "${7*7}", "{{7*7}}", "a]UNION SELECT 1,2,3--",
            "\"; cat /etc/passwd; echo \"",
            "A" * 65536,
        ],
        "restler_fuzzable_int": ["0", "-1", "999999999", "2147483647", "-2147483648"],
        "restler_fuzzable_bool": ["true", "false", "null", "1", "0"],
        "restler_fuzzable_datetime": [
            "2024-01-01T00:00:00Z", "0000-00-00T00:00:00Z",
            "9999-12-31T23:59:59Z", "invalid-date",
        ],
        "restler_fuzzable_uuid4": [
            "00000000-0000-0000-0000-000000000000",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ],
    }
    with open(output_path, "w") as f:
        json.dump(dictionary, f, indent=2)
    return {"dictionary_path": output_path, "fuzz_categories": len(dictionary)}


def run_audit(args):
    """Execute RESTler fuzzing audit workflow."""
    print(f"\n{'='*60}")
    print(f"  RESTLER API FUZZING AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.results_dir:
        summary = parse_run_summary(args.results_dir)
        report["summary"] = summary
        print(f"--- FUZZING SUMMARY ---")
        print(f"  Total requests: {summary.get('total_requests', 0)}")
        print(f"  2xx responses: {summary.get('valid_2xx', 0)}")
        print(f"  5xx errors: {summary.get('server_errors_5xx', 0)}")
        print(f"  Bugs found: {summary.get('bugs_found', 0)}")
        coverage = summary.get("covered_endpoints", 0)
        total = summary.get("total_endpoints", 0)
        pct = (coverage / total * 100) if total else 0
        print(f"  Coverage: {coverage}/{total} ({pct:.1f}%)")

        bugs = parse_bug_buckets(args.results_dir)
        report["bugs"] = bugs
        print(f"\n--- BUG BUCKETS ({len(bugs)} bugs) ---")
        for b in bugs:
            print(f"  [{b['severity']}] {b['type']}: {b['file']}")

    if args.gen_dict:
        dict_result = generate_custom_dictionary(args.gen_dict)
        report["dictionary"] = dict_result
        print(f"\n--- GENERATED DICTIONARY ---")
        print(f"  Path: {dict_result['dictionary_path']}")

    if args.compile_spec and args.restler_path:
        comp = compile_spec(args.restler_path, args.compile_spec)
        report["compilation"] = comp
        print(f"\n--- COMPILATION ---")
        print(f"  Status: {comp['status']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="RESTler API Fuzzing Agent")
    parser.add_argument("--restler-path", help="Path to RESTler binary directory")
    parser.add_argument("--compile-spec", help="OpenAPI spec to compile")
    parser.add_argument("--results-dir", help="RESTler results directory to analyze")
    parser.add_argument("--gen-dict", help="Generate fuzzing dictionary to path")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
