#!/usr/bin/env python3
"""
GDPR Article 30 RoPA Validator.

Validates a Records of Processing Activities (RoPA) JSON file against Article 30
mandatory fields and flags incomplete or missing entries.

Checks:
- All mandatory Article 30 fields present
- Retention periods specified (or criteria documented)
- International transfers have documented safeguards
- Special category data properly flagged
- Security measures documented

Usage:
  python article30_validator.py --ropa ropa.json
  python article30_validator.py --ropa ropa.json --check-retention --check-transfers --strict
"""

import argparse
import json
import sys
from datetime import datetime, timezone

MANDATORY_FIELDS = [
    "purposes",
    "data_subjects",
    "personal_data_categories",
    "recipients"
]

SPECIAL_CATEGORY_KEYWORDS = [
    "health", "medical", "biometric", "genetic", "racial", "ethnic",
    "political", "religious", "trade union", "sex life", "sexual orientation"
]

def validate_entry(entry, index, args):
    """Validate a single processing activity entry."""
    issues = []
    entry_id = entry.get("source_file", f"Entry {index}")
    
    # Check mandatory fields
    for field in MANDATORY_FIELDS:
        if field not in entry or not entry[field]:
            issues.append({
                "severity": "ERROR",
                "field": field,
                "message": f"Missing mandatory field: {field}"
            })
        elif isinstance(entry[field], list) and len(entry[field]) == 0:
            issues.append({
                "severity": "ERROR",
                "field": field,
                "message": f"Empty list for mandatory field: {field}"
            })
    
    # Check retention period
    if args.check_retention:
        if "retention_period" not in entry or not entry["retention_period"]:
            issues.append({
                "severity": "WARNING",
                "field": "retention_period",
                "message": "Retention period not specified (Article 30(1)(f))"
            })
        elif "[TO BE COMPLETED]" in str(entry.get("retention_period", "")):
            issues.append({
                "severity": "WARNING",
                "field": "retention_period",
                "message": "Retention period placeholder not completed"
            })
    
    # Check international transfers
    if args.check_transfers:
        transfers = entry.get("international_transfers", [])
        if len(transfers) > 0:
            # Check if safeguards are documented
            safeguards_mentioned = False
            for transfer in transfers:
                transfer_lower = str(transfer).lower()
                if any(word in transfer_lower for word in ["scc", "standard contractual clause", "adequacy", "bcr", "binding corporate rule"]):
                    safeguards_mentioned = True
                    break
            
            if not safeguards_mentioned:
                issues.append({
                    "severity": "ERROR",
                    "field": "international_transfers",
                    "message": "International transfers identified but no safeguards documented (Chapter V)"
                })
    
    # Check for special category data without additional legal basis
    personal_data_str = " ".join(entry.get("personal_data_categories", [])).lower()
    if any(keyword in personal_data_str for keyword in SPECIAL_CATEGORY_KEYWORDS):
        if "special_category_legal_basis" not in entry:
            issues.append({
                "severity": "WARNING",
                "field": "special_category_legal_basis",
                "message": "Possible special category data (Article 9) but no additional legal basis documented"
            })
    
    # Check security measures
    if not entry.get("security_measures"):
        issues.append({
            "severity": "WARNING",
            "field": "security_measures",
            "message": "No security measures documented (Article 32)"
        })
    
    return entry_id, issues

def generate_report(results, args):
    """Generate validation report."""
    total_errors = sum(1 for _, issues in results for issue in issues if issue["severity"] == "ERROR")
    total_warnings = sum(1 for _, issues in results for issue in issues if issue["severity"] == "WARNING")
    
    print(f"\n{'='*70}")
    print(f"GDPR Article 30 RoPA Validation Report")
    print(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*70}\n")
    
    print(f"Total Entries: {len(results)}")
    print(f"Total Errors: {total_errors}")
    print(f"Total Warnings: {total_warnings}")
    print()
    
    if total_errors == 0 and total_warnings == 0:
        print("✓ All entries passed validation")
        return 0
    
    for entry_id, issues in results:
        if not issues:
            continue
        
        print(f"\n{entry_id}")
        print(f"{'-'*70}")
        for issue in issues:
            icon = "✗" if issue["severity"] == "ERROR" else "⚠"
            print(f"  {icon} [{issue['severity']}] {issue['field']}: {issue['message']}")
    
    print(f"\n{'='*70}")
    if total_errors > 0:
        print(f"VALIDATION FAILED: {total_errors} error(s) found")
        print("Fix errors before using this RoPA for compliance purposes.")
        return 1
    else:
        print(f"VALIDATION PASSED with {total_warnings} warning(s)")
        print("Review warnings and complete missing optional fields.")
        return 0

def main():
    parser = argparse.ArgumentParser(description="Validate GDPR Article 30 RoPA")
    parser.add_argument("--ropa", required=True, help="Path to RoPA JSON file")
    parser.add_argument("--check-retention", action="store_true",
                        help="Validate retention periods are specified")
    parser.add_argument("--check-transfers", action="store_true",
                        help="Validate international transfer safeguards")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as errors")
    args = parser.parse_args()
    
    try:
        with open(args.ropa, 'r') as f:
            ropa = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: Could not read RoPA file: {e}", file=sys.stderr)
        return 2
    
    processing_activities = ropa.get("processing_activities", [])
    if not processing_activities:
        print("ERROR: No processing activities found in RoPA", file=sys.stderr)
        return 2
    
    results = []
    for i, entry in enumerate(processing_activities):
        entry_id, issues = validate_entry(entry, i, args)
        if args.strict:
            # Promote warnings to errors in strict mode
            for issue in issues:
                if issue["severity"] == "WARNING":
                    issue["severity"] = "ERROR"
        results.append((entry_id, issues))
    
    return generate_report(results, args)

if __name__ == "__main__":
    sys.exit(main())
