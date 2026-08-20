#!/usr/bin/env python3
"""
GDPR Article 30 Records of Processing Activities (RoPA) Parser.

Parses Data Processing Agreements (DPAs), privacy policies, and contracts to
extract Article 30 mandatory fields and generate a structured RoPA (Register
of Processing Activities) in JSON format.

Article 30 requires controllers to maintain written records containing:
- Name and contact details of controller (and DPO if designated)
- Purposes of processing
- Categories of data subjects and personal data
- Categories of recipients
- International transfers (destination countries + safeguards)
- Retention periods (or criteria)
- Security measures description

Usage:
  python article30_parser.py --input contracts/processors/ --output ropa.json
  python article30_parser.py --input privacy_policy.md --output ropa.json --mode single

This is a helper tool; manual review and completion is required. The parser
uses keyword extraction and NLP patterns to identify Article 30 fields but
cannot guarantee 100% accuracy.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

# Keywords for field extraction (naive pattern matching; production would use NLP)
KEYWORDS = {
    "purposes": ["purpose", "why we process", "reason for processing", "use of data"],
    "data_subjects": ["customer", "employee", "user", "visitor", "subscriber", "data subject"],
    "personal_data": ["name", "email", "address", "phone", "ip address", "device id", "location", "biometric"],
    "recipients": ["processor", "vendor", "third party", "recipient", "share with", "disclose to"],
    "retention": ["retention period", "keep for", "store for", "delete after", "retain until"],
    "transfers": ["transfer to", "country", "outside EU", "outside EEA", "international transfer"],
    "security": ["encryption", "access control", "security measure", "pseudonymization", "tls", "mfa"]
}

def extract_text(file_path):
    """Extract text from markdown, txt, or JSON files."""
    ext = Path(file_path).suffix.lower()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            if ext == '.json':
                data = json.load(f)
                # Flatten JSON to text
                return json.dumps(data, indent=2)
            else:
                return f.read()
    except Exception as e:
        print(f"[!] Could not read {file_path}: {e}", file=sys.stderr)
        return ""

def extract_fields(text, file_name):
    """Extract Article 30 fields using keyword patterns."""
    text_lower = text.lower()
    extracted = {
        "source_file": file_name,
        "purposes": [],
        "data_subjects": [],
        "personal_data_categories": [],
        "recipients": [],
        "retention_period": None,
        "international_transfers": [],
        "security_measures": []
    }
    
    # Extract sentences containing keywords
    sentences = re.split(r'[.!?\n]', text)
    
    for sent in sentences:
        sent_lower = sent.lower().strip()
        if not sent_lower:
            continue
            
        # Purposes
        if any(kw in sent_lower for kw in KEYWORDS["purposes"]):
            if len(sent) < 200:  # Avoid very long sentences
                extracted["purposes"].append(sent.strip())
        
        # Data subjects
        for subj in KEYWORDS["data_subjects"]:
            if subj in sent_lower:
                extracted["data_subjects"].append(subj)
        
        # Personal data categories
        for cat in KEYWORDS["personal_data"]:
            if cat in sent_lower:
                extracted["personal_data_categories"].append(cat)
        
        # Recipients
        if any(kw in sent_lower for kw in KEYWORDS["recipients"]):
            if len(sent) < 200:
                extracted["recipients"].append(sent.strip())
        
        # Retention
        if any(kw in sent_lower for kw in KEYWORDS["retention"]):
            if not extracted["retention_period"]:
                extracted["retention_period"] = sent.strip()
        
        # International transfers
        if any(kw in sent_lower for kw in KEYWORDS["transfers"]):
            extracted["international_transfers"].append(sent.strip())
        
        # Security measures
        if any(kw in sent_lower for kw in KEYWORDS["security"]):
            if len(sent) < 200:
                extracted["security_measures"].append(sent.strip())
    
    # Deduplicate lists
    extracted["data_subjects"] = list(set(extracted["data_subjects"]))
    extracted["personal_data_categories"] = list(set(extracted["personal_data_categories"]))
    extracted["purposes"] = list(set(extracted["purposes"]))[:5]  # Limit to top 5
    extracted["recipients"] = list(set(extracted["recipients"]))[:5]
    extracted["security_measures"] = list(set(extracted["security_measures"]))[:5]
    
    return extracted

def parse_directory(input_dir):
    """Parse all documents in a directory."""
    ropa_entries = []
    
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.startswith('.'):
                continue
            file_path = os.path.join(root, file)
            print(f"[*] Parsing: {file_path}", file=sys.stderr)
            text = extract_text(file_path)
            if text:
                entry = extract_fields(text, file)
                ropa_entries.append(entry)
    
    return ropa_entries

def main():
    parser = argparse.ArgumentParser(description="Parse documents for GDPR Article 30 fields")
    parser.add_argument("--input", "-i", required=True, help="Input file or directory")
    parser.add_argument("--output", "-o", default="ropa.json", help="Output JSON file")
    parser.add_argument("--mode", choices=["single", "directory"], default="directory",
                        help="Parse single file or directory")
    args = parser.parse_args()
    
    print(f"[*] Article 30 RoPA Parser - {datetime.now(timezone.utc).isoformat()}", file=sys.stderr)
    print(f"[*] Input: {args.input}", file=sys.stderr)
    print(f"[*] Mode: {args.mode}", file=sys.stderr)
    
    if args.mode == "single":
        if not os.path.isfile(args.input):
            print(f"[!] File not found: {args.input}", file=sys.stderr)
            return 2
        text = extract_text(args.input)
        ropa_entries = [extract_fields(text, os.path.basename(args.input))]
    else:
        if not os.path.isdir(args.input):
            print(f"[!] Directory not found: {args.input}", file=sys.stderr)
            return 2
        ropa_entries = parse_directory(args.input)
    
    # Build output structure
    output = {
        "organization": {
            "name": "[TO BE COMPLETED]",
            "controller_contact": "[TO BE COMPLETED]",
            "dpo_contact": "[IF REQUIRED]",
            "generated_date": datetime.now(timezone.utc).isoformat()
        },
        "processing_activities": ropa_entries,
        "completion_notes": [
            "This is a DRAFT generated by automated parsing.",
            "Manual review required for accuracy and completeness.",
            "Fill in [TO BE COMPLETED] placeholders.",
            "Verify all extracted fields against source documents.",
            "Add missing Article 30 mandatory fields.",
            "Consult legal counsel for final RoPA approval."
        ]
    }
    
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n[✓] Parsed {len(ropa_entries)} document(s)", file=sys.stderr)
    print(f"[✓] RoPA draft written to: {args.output}", file=sys.stderr)
    print(f"[!] Manual review required - this is a DRAFT only", file=sys.stderr)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
