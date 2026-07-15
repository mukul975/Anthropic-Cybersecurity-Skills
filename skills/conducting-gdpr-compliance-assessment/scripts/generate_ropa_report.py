#!/usr/bin/env python3
"""
GDPR Article 30 RoPA Report Generator.

Generates a formatted Article 30 Records of Processing Activities report
in Markdown format suitable for supervisory authority submission.

Usage:
  python generate_ropa_report.py --input ropa.json --output Article30_Register.md
  python generate_ropa_report.py --input ropa.json --output report.pdf --format pdf
"""

import argparse
import json
import sys
from datetime import datetime, timezone

def format_list(items):
    """Format a list of items as bullet points."""
    if not items:
        return "*[None specified]*"
    if isinstance(items, str):
        return items
    return "\n".join(f"- {item}" for item in items)

def generate_markdown(ropa):
    """Generate Markdown report from RoPA JSON."""
    org = ropa.get("organization", {})
    activities = ropa.get("processing_activities", [])
    
    lines = []
    lines.append("# Article 30 Records of Processing Activities")
    lines.append("")
    lines.append(f"**Organization**: {org.get('name', '[Organization Name]')}")
    lines.append(f"**Controller Contact**: {org.get('controller_contact', '[Contact Details]')}")
    if org.get('dpo_contact'):
        lines.append(f"**Data Protection Officer**: {org.get('dpo_contact')}")
    lines.append(f"**Generated**: {org.get('generated_date', datetime.now(timezone.utc).isoformat())}")
    lines.append(f"**Total Processing Activities**: {len(activities)}")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    for idx, activity in enumerate(activities, 1):
        lines.append(f"## Processing Activity {idx}: {activity.get('source_file', 'Unnamed Activity')}")
        lines.append("")
        
        # Purposes
        lines.append("### Purposes of Processing")
        lines.append(format_list(activity.get('purposes', [])))
        lines.append("")
        
        # Data Subjects
        lines.append("### Categories of Data Subjects")
        lines.append(format_list(activity.get('data_subjects', [])))
        lines.append("")
        
        # Personal Data
        lines.append("### Categories of Personal Data")
        lines.append(format_list(activity.get('personal_data_categories', [])))
        lines.append("")
        
        # Recipients
        lines.append("### Categories of Recipients")
        lines.append(format_list(activity.get('recipients', [])))
        lines.append("")
        
        # Retention
        lines.append("### Retention Period")
        retention = activity.get('retention_period', '*[Not specified]*')
        lines.append(f"{retention}")
        lines.append("")
        
        # International Transfers
        lines.append("### International Transfers")
        transfers = activity.get('international_transfers', [])
        if transfers:
            lines.append(format_list(transfers))
        else:
            lines.append("*No international transfers*")
        lines.append("")
        
        # Security Measures
        lines.append("### Technical and Organizational Security Measures")
        lines.append(format_list(activity.get('security_measures', [])))
        lines.append("")
        
        lines.append("---")
        lines.append("")
    
    # Completion Notes
    if ropa.get('completion_notes'):
        lines.append("## Completion Notes")
        lines.append("")
        for note in ropa['completion_notes']:
            lines.append(f"- {note}")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("*This document fulfills the requirements of GDPR Article 30 (Records of Processing Activities).*")
    lines.append("*Controllers must maintain this register and make it available to supervisory authorities upon request.*")
    
    return "\n".join(lines)

def generate_html(markdown_content):
    """Convert Markdown to basic HTML."""
    html_header = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Article 30 RoPA</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #1a5490; border-bottom: 3px solid #1a5490; }
        h2 { color: #2563eb; margin-top: 30px; }
        h3 { color: #4b5563; margin-top: 20px; }
        hr { margin: 30px 0; border: none; border-top: 1px solid #ddd; }
        ul { line-height: 1.6; }
        em { color: #6b7280; }
    </style>
</head>
<body>
"""
    html_footer = """
</body>
</html>
"""
    
    # Simple Markdown to HTML conversion
    html_body = markdown_content
    html_body = html_body.replace("# ", "<h1>").replace("\n\n", "</h1>\n\n")
    html_body = html_body.replace("## ", "<h2>").replace("\n\n", "</h2>\n\n")
    html_body = html_body.replace("### ", "<h3>").replace("\n\n", "</h3>\n\n")
    html_body = html_body.replace("**", "<strong>").replace("**", "</strong>")
    html_body = html_body.replace("*[", "<em>[").replace("]*", "]</em>")
    html_body = html_body.replace("---\n", "<hr>\n")
    html_body = html_body.replace("- ", "<li>").replace("\n", "</li>\n")
    
    return html_header + html_body + html_footer

def main():
    parser = argparse.ArgumentParser(description="Generate Article 30 RoPA Report")
    parser.add_argument("--input", "-i", required=True, help="Input RoPA JSON file")
    parser.add_argument("--output", "-o", required=True, help="Output file path")
    parser.add_argument("--format", choices=["markdown", "html", "pdf"], default="markdown",
                        help="Output format (default: markdown)")
    args = parser.parse_args()
    
    try:
        with open(args.input, 'r') as f:
            ropa = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: Could not read RoPA file: {e}", file=sys.stderr)
        return 2
    
    markdown_content = generate_markdown(ropa)
    
    if args.format == "markdown":
        with open(args.output, 'w') as f:
            f.write(markdown_content)
        print(f"[✓] Markdown report written to: {args.output}", file=sys.stderr)
    
    elif args.format == "html":
        html_content = generate_html(markdown_content)
        with open(args.output, 'w') as f:
            f.write(html_content)
        print(f"[✓] HTML report written to: {args.output}", file=sys.stderr)
    
    elif args.format == "pdf":
        try:
            # Try to use markdown2pdf if available
            import subprocess
            md_temp = args.output.replace('.pdf', '.md')
            with open(md_temp, 'w') as f:
                f.write(markdown_content)
            
            # Try pandoc first, fall back to instructions
            result = subprocess.run(['pandoc', md_temp, '-o', args.output], 
                                    capture_output=True)
            if result.returncode == 0:
                print(f"[✓] PDF report written to: {args.output}", file=sys.stderr)
                import os
                os.remove(md_temp)
            else:
                print(f"[!] pandoc not found. Markdown saved to: {md_temp}", file=sys.stderr)
                print(f"[!] Install pandoc to generate PDF: apt install pandoc", file=sys.stderr)
        except Exception as e:
            print(f"[!] PDF generation requires pandoc: {e}", file=sys.stderr)
            print(f"[!] Generating Markdown instead: {args.output.replace('.pdf', '.md')}", file=sys.stderr)
            with open(args.output.replace('.pdf', '.md'), 'w') as f:
                f.write(markdown_content)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
