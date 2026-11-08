#!/usr/bin/env python3
"""
GDPR Article 30 Record of Processing Activities (RoPA) validator and reporter.

Subcommands:
    validate  -- check each row against Article 30(1) (controller) or 30(2)
                 (processor); non-zero exit if any mandatory field is missing.
    report    -- generate a dated, labelled Markdown RoPA for a supervisory
                 authority, with a third-country transfers summary table.

Input: CSV (standard library) or YAML (requires pyyaml). One row per processing
activity. See assets/ropa-template.csv and assets/ropa-processor-template.csv.

Reference: GDPR Article 30 -- https://gdpr-info.eu/art-30-gdpr/
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path

# Mandatory columns per role. Keys are internal; values are the human label used
# in validation messages and the report. "Where possible" fields (retention,
# security) are warned, not failed -- matching the Regulation's wording.
CONTROLLER_REQUIRED = {
    "controller": "Controller name & contact [Art. 30(1)(a)]",
    "purposes": "Purposes of processing [Art. 30(1)(b)]",
    "data_subjects": "Categories of data subjects [Art. 30(1)(c)]",
    "data_categories": "Categories of personal data [Art. 30(1)(c)]",
    "recipients": "Categories of recipients [Art. 30(1)(d)]",
}
CONTROLLER_WHERE_POSSIBLE = {
    "retention": "Retention time limits [Art. 30(1)(f)]",
    "security_measures": "General security description [Art. 30(1)(g)]",
}
PROCESSOR_REQUIRED = {
    "processor": "Processor name & contact [Art. 30(2)(a)]",
    "controller": "Controller name & contact [Art. 30(2)(a)]",
    "processing_categories": "Categories of processing [Art. 30(2)(b)]",
}
PROCESSOR_WHERE_POSSIBLE = {
    "security_measures": "General security description [Art. 30(2)(d)]",
}

# Transfer columns, common to both roles.
TRANSFER_COUNTRY = "third_country"
TRANSFER_SAFEGUARD = "transfer_safeguard"


def load_rows(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8")
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:
            raise SystemExit("YAML input needs pyyaml: pip install pyyaml")
        data = yaml.safe_load(text)
        rows = data.get("activities", data) if isinstance(data, dict) else data
        return [dict(r) for r in rows]
    return list(csv.DictReader(text.splitlines()))


def field_set(role: str):
    if role == "controller":
        return CONTROLLER_REQUIRED, CONTROLLER_WHERE_POSSIBLE
    if role == "processor":
        return PROCESSOR_REQUIRED, PROCESSOR_WHERE_POSSIBLE
    raise SystemExit(f"Unknown role: {role!r} (use controller|processor)")


def blank(row: dict, key: str) -> bool:
    return not str(row.get(key, "")).strip()


def validate(rows, role):
    required, where_possible = field_set(role)
    errors, warnings = [], []
    for i, row in enumerate(rows, start=1):
        label = row.get("activity") or row.get("purposes") or f"row {i}"
        for key, name in required.items():
            if blank(row, key):
                errors.append((i, label, f"missing mandatory field: {name}"))
        for key, name in where_possible.items():
            if blank(row, key):
                warnings.append((i, label, f"empty where-possible field: {name}"))
        # transfer check: a named third country must carry a safeguard.
        if not blank(row, TRANSFER_COUNTRY) and blank(row, TRANSFER_SAFEGUARD):
            errors.append((i, label,
                           f"third-country recipient '{row[TRANSFER_COUNTRY]}' has no "
                           f"transfer safeguard recorded [Chapter V]"))
    return errors, warnings


def cmd_validate(args):
    rows = load_rows(args.infile)
    errors, warnings = validate(rows, args.role)
    for i, label, msg in warnings:
        print(f"WARN  [{i}] {label}: {msg}", file=sys.stderr)
    for i, label, msg in errors:
        print(f"FAIL  [{i}] {label}: {msg}", file=sys.stderr)
    summary = {"rows": len(rows), "errors": len(errors), "warnings": len(warnings)}
    print(json.dumps(summary, indent=2))
    if errors:
        sys.exit(1)
    print("OK: all rows satisfy the mandatory Article 30 fields.")


def cmd_report(args):
    rows = load_rows(args.infile)
    required, where_possible = field_set(args.role)
    all_fields = {**required, **where_possible}
    today = dt.date.today().isoformat()

    lines = [
        f"# Record of Processing Activities ({args.role.title()})",
        "",
        f"**Organisation:** {args.org or '(set --org)'}  ",
        f"**Data Protection Officer:** {args.dpo or '(set --dpo)'}  ",
        f"**Generated:** {today}  ",
        f"**Legal basis for this record:** GDPR Article 30"
        f"{'(1)' if args.role == 'controller' else '(2)'}",
        "",
        f"This record covers {len(rows)} processing "
        f"{'activity' if len(rows) == 1 else 'activities'}.",
        "",
    ]

    transfers = []
    for i, row in enumerate(rows, start=1):
        label = row.get("activity") or row.get("purposes") or f"Activity {i}"
        lines.append(f"## {i}. {label}")
        lines.append("")
        for key, name in all_fields.items():
            val = str(row.get(key, "")).strip() or "_(not recorded)_"
            lines.append(f"- **{name}:** {val}")
        if not blank(row, TRANSFER_COUNTRY):
            country = row[TRANSFER_COUNTRY]
            safeguard = str(row.get(TRANSFER_SAFEGUARD, "")).strip() or "**(none recorded)**"
            lines.append(f"- **Third-country transfer:** {country} — safeguard: {safeguard}")
            transfers.append((label, country, safeguard))
        lines.append("")

    lines.append("## Third-country transfers summary")
    lines.append("")
    if transfers:
        lines.append("| Activity | Destination | Safeguard (Chapter V) |")
        lines.append("|---|---|---|")
        for label, country, safeguard in transfers:
            lines.append(f"| {label} | {country} | {safeguard} |")
    else:
        lines.append("No third-country transfers recorded.")
    lines.append("")

    Path(args.outfile).write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {args.outfile} ({len(rows)} activities, {len(transfers)} transfer(s)).")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--in", dest="infile", required=True, help="RoPA CSV or YAML")
    common.add_argument("--role", choices=["controller", "processor"], default="controller")

    v = sub.add_parser("validate", parents=[common], help="check Article 30 fields")
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("report", parents=[common], help="generate Markdown RoPA")
    r.add_argument("--out", dest="outfile", required=True)
    r.add_argument("--org", help="organisation / controller name for the header")
    r.add_argument("--dpo", help="DPO contact for the header")
    r.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
