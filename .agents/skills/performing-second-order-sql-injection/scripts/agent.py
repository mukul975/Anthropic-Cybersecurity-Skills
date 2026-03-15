#!/usr/bin/env python3
"""Second-Order SQL Injection agent — detects stored SQL injection payloads
by analyzing database content and tracing data flow from input to secondary
query execution points."""

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


SQL_INJECTION_PATTERNS = [
    r"(?i)(\bunion\b\s+\bselect\b)",
    r"(?i)(\bor\b\s+1\s*=\s*1)",
    r"(?i)(\band\b\s+1\s*=\s*1)",
    r"(?i)(;\s*drop\s+table\b)",
    r"(?i)(;\s*delete\s+from\b)",
    r"(?i)(;\s*update\b.*\bset\b)",
    r"(?i)(;\s*insert\s+into\b)",
    r"(?i)(--\s*$)",
    r"(?i)(\bexec\b\s*\()",
    r"(?i)(\bwaitfor\b\s+\bdelay\b)",
    r"(?i)(\bsleep\b\s*\(\d+\))",
    r"(?i)(\bconvert\b\s*\()",
    r"(?i)(\bcast\b\s*\(.*\bas\b)",
    r"(?i)(\bchar\b\s*\(\d+\))",
    r"(?i)(\b0x[0-9a-f]+\b)",
    r"(\x27|\x22)\s*(or|and|union)",
]


def scan_database_values(db_dump_path: str) -> list[dict]:
    """Scan a database dump (JSON format) for stored SQL injection payloads."""
    data = json.loads(Path(db_dump_path).read_text(encoding="utf-8"))
    findings = []
    for table_name, rows in data.items():
        for row_idx, row in enumerate(rows):
            for col_name, value in row.items():
                if not isinstance(value, str):
                    continue
                for pattern in SQL_INJECTION_PATTERNS:
                    match = re.search(pattern, value)
                    if match:
                        findings.append({
                            "type": "stored_sqli_payload",
                            "severity": "critical",
                            "table": table_name,
                            "column": col_name,
                            "row_index": row_idx,
                            "matched_pattern": pattern,
                            "matched_text": match.group(0),
                            "value_preview": value[:200],
                            "detail": f"SQL injection payload in {table_name}.{col_name} row {row_idx}",
                        })
                        break
    return findings


def scan_source_code(source_dir: str) -> list[dict]:
    """Scan source code for second-order SQL injection sinks (string concatenation with DB data)."""
    dangerous_patterns = [
        (r"(?i)cursor\.execute\s*\(\s*[\"'].*%s", "python_format_string"),
        (r"(?i)cursor\.execute\s*\(\s*f[\"']", "python_fstring"),
        (r'(?i)query\s*=\s*["\'].*\+\s*\w+', "string_concatenation"),
        (r"(?i)\.format\s*\(.*\)\s*\)", "python_format"),
        (r'(?i)\$\{.*\}\s*(?:FROM|WHERE|INSERT|UPDATE|DELETE)', "template_literal"),
        (r'(?i)sprintf\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)', "sprintf_query"),
    ]
    findings = []
    src = Path(source_dir)
    for ext in ("*.py", "*.php", "*.java", "*.js", "*.rb", "*.cs"):
        for fpath in src.rglob(ext):
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for line_no, line in enumerate(content.splitlines(), 1):
                    for pattern, pattern_name in dangerous_patterns:
                        if re.search(pattern, line):
                            findings.append({
                                "type": "second_order_sqli_sink",
                                "severity": "high",
                                "file": str(fpath),
                                "line": line_no,
                                "pattern": pattern_name,
                                "code_snippet": line.strip()[:200],
                                "detail": f"Potential second-order SQLi sink at {fpath.name}:{line_no}",
                            })
                            break
            except OSError:
                continue
    return findings


def trace_data_flow(db_findings: list[dict], code_findings: list[dict]) -> list[dict]:
    """Correlate stored payloads with code sinks to identify complete attack paths."""
    attack_paths = []
    for db_f in db_findings:
        table = db_f["table"]
        column = db_f["column"]
        for code_f in code_findings:
            snippet = code_f.get("code_snippet", "").lower()
            if table.lower() in snippet or column.lower() in snippet:
                attack_paths.append({
                    "type": "confirmed_attack_path",
                    "severity": "critical",
                    "source": f"{table}.{column}",
                    "sink": f"{code_f['file']}:{code_f['line']}",
                    "detail": f"Stored payload in {table}.{column} flows to query at {code_f['file']}:{code_f['line']}",
                })
    return attack_paths


def generate_report(db_dump_path: str = None, source_dir: str = None) -> dict:
    """Run analysis and build consolidated report."""
    findings = []
    db_findings = []
    code_findings = []

    if db_dump_path:
        db_findings = scan_database_values(db_dump_path)
        findings.extend(db_findings)
    if source_dir:
        code_findings = scan_source_code(source_dir)
        findings.extend(code_findings)
    if db_findings and code_findings:
        attack_paths = trace_data_flow(db_findings, code_findings)
        findings.extend(attack_paths)

    severity_counts = Counter(f.get("severity", "info") for f in findings)
    return {
        "report": "second_order_sql_injection",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "stored_payloads": len(db_findings),
        "code_sinks": len(code_findings),
        "confirmed_attack_paths": len([f for f in findings if f["type"] == "confirmed_attack_path"]),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Second-Order SQL Injection Agent")
    parser.add_argument("--db-dump", help="JSON database dump file to scan for stored payloads")
    parser.add_argument("--source", help="Source code directory to scan for injection sinks")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    if not args.db_dump and not args.source:
        parser.error("At least one of --db-dump or --source is required")

    report = generate_report(args.db_dump, args.source)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
