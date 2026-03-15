#!/usr/bin/env python3
"""
Spearphishing Simulation Campaign Manager

Automates phishing campaign preparation including:
- Email template generation with personalization
- Domain reputation checking
- Email authentication validation (SPF/DKIM/DMARC)
- Campaign metrics analysis
- Phishing report generation

Usage:
    python process.py --mode setup --domain phishing-domain.com
    python process.py --mode template --pretext password-expiry --targets targets.csv
    python process.py --mode validate --domain phishing-domain.com
    python process.py --mode report --campaign-data results.json

Requirements:
    pip install requests dnspython rich jinja2
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import dns.resolver
    import requests
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("[!] Missing dependencies. Install with: pip install requests dnspython rich")
    sys.exit(1)

console = Console()

# Spearphishing pretext templates
PRETEXT_TEMPLATES = {
    "password-expiry": {
        "subject": "[ACTION REQUIRED] Password Expiry Notice - {first_name}",
        "body": """Dear {first_name} {last_name},

Your corporate password will expire in 24 hours. To maintain uninterrupted
access to company resources, please update your password immediately
using our secure self-service portal.

Update Password: {phishing_url}

If you have already updated your password, please disregard this message.

This is an automated message from the IT Security Team.
Do not reply to this email.

Best regards,
IT Security Team
{company_name}

{tracking_pixel}""",
        "urgency": "high",
        "authority": "IT Security",
    },
    "shared-document": {
        "subject": "{sender_name} shared a document with you: Q4 Financial Review",
        "body": """{first_name},

{sender_name} has shared a document with you via our secure file sharing platform.

Document: Q4 Financial Review - {company_name}
Shared by: {sender_name} ({sender_title})
Access expires: 48 hours

View Document: {phishing_url}

You are receiving this because {sender_name} included you in the
document sharing list. If you believe this was sent in error,
please contact {sender_name} directly.

Powered by SecureShare
{company_name} Document Management

{tracking_pixel}""",
        "urgency": "medium",
        "authority": "Colleague",
    },
    "hr-benefits": {
        "subject": "Important: Open Enrollment Benefits Update - Action Required",
        "body": """Dear {first_name},

As part of our annual benefits enrollment period, we are pleased to announce
updated benefits packages for all employees. Please review and confirm your
selections before the enrollment deadline.

Key updates include:
- Enhanced health coverage options
- New wellness program benefits
- Updated 401(k) matching contributions

Review Your Benefits: {phishing_url}

Deadline: {deadline_date}

If you have questions about your benefits options, please contact
the HR Benefits team.

Warm regards,
Human Resources Department
{company_name}

{tracking_pixel}""",
        "urgency": "medium",
        "authority": "HR Department",
    },
    "mfa-enrollment": {
        "subject": "Security Update: Multi-Factor Authentication Enrollment Required",
        "body": """Hello {first_name},

As part of our ongoing security improvements, all employees are required
to enroll in our new Multi-Factor Authentication (MFA) system by {deadline_date}.

This upgrade is mandatory and will help protect your account and
company data from unauthorized access.

Enroll Now: {phishing_url}

What you will need:
- Your current corporate credentials
- Your mobile phone for authenticator setup

Employees who do not complete enrollment by the deadline may experience
temporary access disruptions.

Thank you for your cooperation in keeping {company_name} secure.

IT Security Operations
{company_name}

{tracking_pixel}""",
        "urgency": "high",
        "authority": "IT Security",
    },
    "invoice-payment": {
        "subject": "Invoice #{invoice_number} - Payment Confirmation Required",
        "body": """Dear {first_name},

Please find attached the invoice for services rendered. We kindly request
your review and payment confirmation at your earliest convenience.

Invoice Number: #{invoice_number}
Amount Due: ${amount}
Due Date: {deadline_date}

View Invoice: {phishing_url}

If you have any questions regarding this invoice, please do not hesitate
to contact our accounts department.

Best regards,
{sender_name}
Accounts Receivable
{vendor_name}

{tracking_pixel}""",
        "urgency": "high",
        "authority": "Vendor",
    },
    "voicemail": {
        "subject": "You have a new voicemail from {sender_name} ({phone_number})",
        "body": """You received a voicemail

From: {sender_name}
Number: {phone_number}
Duration: 0:47
Date: {current_date}

Play Voicemail: {phishing_url}

This message was sent from your corporate voice messaging system.

{tracking_pixel}""",
        "urgency": "low",
        "authority": "System",
    },
}


def validate_email_authentication(domain: str) -> dict:
    """Validate SPF, DKIM, and DMARC configuration for a domain."""
    results = {
        "spf": {"configured": False, "record": None, "issues": []},
        "dkim": {"configured": False, "record": None, "issues": []},
        "dmarc": {"configured": False, "record": None, "issues": []},
    }

    # Check SPF
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                results["spf"]["configured"] = True
                results["spf"]["record"] = txt

                if "~all" in txt:
                    results["spf"]["issues"].append("Soft fail (~all) - consider using -all")
                elif "+all" in txt:
                    results["spf"]["issues"].append("WARNING: +all allows any sender")
                elif "-all" in txt:
                    results["spf"]["issues"].append("Hard fail (-all) - strict configuration")

                if txt.count("include:") > 10:
                    results["spf"]["issues"].append("Too many includes - may exceed DNS lookup limit")
    except Exception as e:
        results["spf"]["issues"].append(f"DNS query failed: {e}")

    # Check DKIM (common selectors)
    dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
    for selector in dkim_selectors:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DKIM1" in txt or "k=rsa" in txt:
                    results["dkim"]["configured"] = True
                    results["dkim"]["record"] = f"Selector: {selector} - {txt[:100]}..."
                    break
        except Exception:
            pass
        if results["dkim"]["configured"]:
            break

    if not results["dkim"]["configured"]:
        results["dkim"]["issues"].append("No DKIM record found for common selectors")

    # Check DMARC
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                results["dmarc"]["configured"] = True
                results["dmarc"]["record"] = txt

                if "p=none" in txt:
                    results["dmarc"]["issues"].append("Policy is 'none' - no enforcement")
                elif "p=quarantine" in txt:
                    results["dmarc"]["issues"].append("Policy is 'quarantine' - moderate enforcement")
                elif "p=reject" in txt:
                    results["dmarc"]["issues"].append("Policy is 'reject' - strict enforcement")
    except Exception as e:
        results["dmarc"]["issues"].append(f"No DMARC record found: {e}")

    return results


def generate_email_template(
    pretext: str,
    targets_file: str,
    company_name: str = "Target Corp",
    phishing_url: str = "https://login.example.com",
    output_dir: str = "./templates",
) -> list[dict]:
    """Generate personalized email templates for each target."""

    if pretext not in PRETEXT_TEMPLATES:
        console.print(f"[red][-] Unknown pretext: {pretext}[/red]")
        console.print(f"[yellow]Available: {', '.join(PRETEXT_TEMPLATES.keys())}[/yellow]")
        return []

    template = PRETEXT_TEMPLATES[pretext]
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    emails = []
    try:
        with open(targets_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                from datetime import timedelta

                personalized = {
                    "to": row.get("email", row.get("Email", "")),
                    "subject": template["subject"].format(
                        first_name=row.get("first_name", row.get("First Name", "User")),
                        sender_name="Michael Thompson",
                        invoice_number="INV-2024-4821",
                    ),
                    "body": template["body"].format(
                        first_name=row.get("first_name", row.get("First Name", "User")),
                        last_name=row.get("last_name", row.get("Last Name", "")),
                        company_name=company_name,
                        phishing_url=phishing_url,
                        sender_name="Michael Thompson",
                        sender_title="VP of Finance",
                        deadline_date=(datetime.now() + timedelta(days=3)).strftime("%B %d, %Y"),
                        current_date=datetime.now().strftime("%B %d, %Y %I:%M %p"),
                        invoice_number="INV-2024-4821",
                        amount="4,750.00",
                        vendor_name="Apex Business Solutions",
                        phone_number="+1 (555) 867-5309",
                        tracking_pixel='<img src="{tracking_url}" width="1" height="1" />',
                    ),
                    "urgency": template["urgency"],
                    "authority": template["authority"],
                }
                emails.append(personalized)
    except FileNotFoundError:
        console.print(f"[red][-] Targets file not found: {targets_file}[/red]")
        return []
    except Exception as e:
        console.print(f"[red][-] Error processing targets: {e}[/red]")
        return []

    # Save generated emails
    emails_path = out_path / f"campaign_emails_{pretext}.json"
    with open(emails_path, "w") as f:
        json.dump(emails, f, indent=2)

    console.print(f"[green][+] Generated {len(emails)} personalized emails[/green]")
    console.print(f"[green][+] Saved to: {emails_path}[/green]")

    return emails


def check_domain_reputation(domain: str) -> dict:
    """Check domain reputation and categorization status."""
    results = {
        "domain": domain,
        "checks": {},
    }

    # Check if domain resolves
    try:
        import socket
        ip = socket.gethostbyname(domain)
        results["resolves_to"] = ip
    except Exception:
        results["resolves_to"] = "DOES NOT RESOLVE"

    # Check Google Safe Browsing (requires API key)
    results["checks"]["google_safe_browsing"] = "Manual check required: https://transparencyreport.google.com/safe-browsing/search"

    # Check VirusTotal
    results["checks"]["virustotal"] = f"Manual check required: https://www.virustotal.com/gui/domain/{domain}"

    # Check domain age via WHOIS
    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_days = (datetime.now() - creation).days
            results["domain_age_days"] = age_days
            if age_days < 14:
                results["domain_age_warning"] = "Domain is less than 14 days old - high risk of being blocked"
            elif age_days < 30:
                results["domain_age_warning"] = "Domain is less than 30 days old - moderate risk"
            else:
                results["domain_age_warning"] = "Domain age is acceptable"
    except Exception:
        results["domain_age_days"] = "Unable to determine"

    # Check categorization services
    results["checks"]["bluecoat"] = "Manual check: https://sitereview.bluecoat.com/"
    results["checks"]["fortiguard"] = "Manual check: https://www.fortiguard.com/webfilter"
    results["checks"]["paloalto"] = "Manual check: https://urlfiltering.paloaltonetworks.com/"
    results["checks"]["mcafee"] = "Manual check: https://trustedsource.org/"

    return results


def analyze_campaign_results(results_file: str, output_dir: str = "./reports") -> dict:
    """Analyze campaign results and generate metrics report."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    try:
        with open(results_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red][-] Error loading results: {e}[/red]")
        return {}

    # Calculate metrics
    total_sent = len(data.get("results", []))
    delivered = sum(1 for r in data.get("results", []) if r.get("status") == "delivered")
    opened = sum(1 for r in data.get("results", []) if r.get("opened", False))
    clicked = sum(1 for r in data.get("results", []) if r.get("clicked", False))
    submitted = sum(1 for r in data.get("results", []) if r.get("submitted_data", False))
    reported = sum(1 for r in data.get("results", []) if r.get("reported", False))

    metrics = {
        "total_sent": total_sent,
        "delivered": delivered,
        "opened": opened,
        "clicked": clicked,
        "submitted_credentials": submitted,
        "reported_phishing": reported,
        "delivery_rate": (delivered / total_sent * 100) if total_sent > 0 else 0,
        "open_rate": (opened / delivered * 100) if delivered > 0 else 0,
        "click_rate": (clicked / delivered * 100) if delivered > 0 else 0,
        "credential_capture_rate": (submitted / delivered * 100) if delivered > 0 else 0,
        "report_rate": (reported / delivered * 100) if delivered > 0 else 0,
    }

    # Generate report
    report = f"""# Spearphishing Campaign Results Report

## Campaign Overview
- **Campaign ID:** {data.get('campaign_id', 'N/A')}
- **Date:** {data.get('date', datetime.now().strftime('%Y-%m-%d'))}
- **Pretext:** {data.get('pretext', 'N/A')}
- **Target Count:** {total_sent}

## Metrics Summary

| Metric | Count | Rate |
|--------|-------|------|
| Emails Sent | {total_sent} | 100% |
| Delivered | {delivered} | {metrics['delivery_rate']:.1f}% |
| Opened | {opened} | {metrics['open_rate']:.1f}% |
| Clicked Link | {clicked} | {metrics['click_rate']:.1f}% |
| Submitted Credentials | {submitted} | {metrics['credential_capture_rate']:.1f}% |
| Reported to SOC | {reported} | {metrics['report_rate']:.1f}% |

## Risk Assessment

### Credential Compromise Risk
{"CRITICAL" if metrics['credential_capture_rate'] > 20 else "HIGH" if metrics['credential_capture_rate'] > 10 else "MEDIUM" if metrics['credential_capture_rate'] > 5 else "LOW"}
- {submitted} out of {delivered} users submitted credentials
- These credentials could be used for initial access in a real attack

### Security Awareness Gap
{"CRITICAL" if metrics['report_rate'] < 5 else "HIGH" if metrics['report_rate'] < 15 else "MEDIUM" if metrics['report_rate'] < 30 else "LOW"}
- Only {reported} out of {delivered} users reported the phishing email
- Industry benchmark for phishing report rate is 20-30%

## Recommendations

1. {"Mandatory security awareness training for all users who clicked" if clicked > 0 else "Continue current awareness program"}
2. {"Implement MFA to mitigate credential compromise risk" if submitted > 0 else "Current credential protections appear effective"}
3. {"Improve phishing report mechanisms - too few users reported" if metrics['report_rate'] < 15 else "Phishing reporting culture is adequate"}
4. Review email security gateway rules based on successful deliveries
5. Consider additional technical controls for identified bypass methods

## MITRE ATT&CK Mapping

| Technique | ID | Result |
|-----------|----|--------|
| Spearphishing Link | T1566.002 | {"Successful" if clicked > 0 else "Blocked"} |
| User Execution | T1204.001 | {"Successful" if clicked > 0 else "No interaction"} |
| Valid Accounts | T1078 | {"Credentials captured" if submitted > 0 else "No credentials captured"} |
"""

    report_path = out_path / "phishing_campaign_report.md"
    with open(report_path, "w") as f:
        f.write(report)

    console.print(f"[green][+] Campaign report saved to: {report_path}[/green]")

    # Display summary table
    table = Table(title="Campaign Metrics Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="yellow")
    table.add_column("Rate", style="green")

    table.add_row("Emails Sent", str(total_sent), "100%")
    table.add_row("Delivered", str(delivered), f"{metrics['delivery_rate']:.1f}%")
    table.add_row("Opened", str(opened), f"{metrics['open_rate']:.1f}%")
    table.add_row("Clicked", str(clicked), f"{metrics['click_rate']:.1f}%")
    table.add_row("Credentials Captured", str(submitted), f"{metrics['credential_capture_rate']:.1f}%")
    table.add_row("Reported", str(reported), f"{metrics['report_rate']:.1f}%")

    console.print(table)

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="Spearphishing Simulation Campaign Manager"
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["setup", "template", "validate", "report", "list-pretexts", "check-domain"],
        help="Operation mode",
    )
    parser.add_argument("--domain", help="Phishing domain to validate")
    parser.add_argument("--pretext", help="Pretext template name")
    parser.add_argument("--targets", help="Path to targets CSV file")
    parser.add_argument("--company", default="Target Corp", help="Target company name")
    parser.add_argument("--phishing-url", default="https://login.example.com", help="Phishing URL")
    parser.add_argument("--campaign-data", help="Path to campaign results JSON")
    parser.add_argument("--output", default="./output", help="Output directory")

    args = parser.parse_args()

    if args.mode == "list-pretexts":
        table = Table(title="Available Pretext Templates")
        table.add_column("Name", style="red bold")
        table.add_column("Authority", style="yellow")
        table.add_column("Urgency", style="cyan")
        table.add_column("Subject Preview", style="green")

        for name, template in PRETEXT_TEMPLATES.items():
            table.add_row(
                name,
                template["authority"],
                template["urgency"],
                template["subject"][:50] + "...",
            )
        console.print(table)

    elif args.mode == "validate":
        if not args.domain:
            console.print("[red][-] --domain required for validation mode[/red]")
            return

        console.print(f"[yellow][*] Validating email authentication for {args.domain}...[/yellow]")
        auth_results = validate_email_authentication(args.domain)

        table = Table(title=f"Email Authentication: {args.domain}")
        table.add_column("Protocol", style="cyan")
        table.add_column("Configured", style="green")
        table.add_column("Record", style="yellow")
        table.add_column("Issues", style="red")

        for protocol, data in auth_results.items():
            table.add_row(
                protocol.upper(),
                "Yes" if data["configured"] else "No",
                (data["record"] or "N/A")[:60],
                "; ".join(data["issues"]) if data["issues"] else "None",
            )

        console.print(table)

    elif args.mode == "template":
        if not args.pretext or not args.targets:
            console.print("[red][-] --pretext and --targets required for template mode[/red]")
            return

        generate_email_template(
            args.pretext, args.targets, args.company, args.phishing_url, args.output
        )

    elif args.mode == "check-domain":
        if not args.domain:
            console.print("[red][-] --domain required[/red]")
            return

        console.print(f"[yellow][*] Checking domain reputation for {args.domain}...[/yellow]")
        rep_results = check_domain_reputation(args.domain)

        console.print(Panel(json.dumps(rep_results, indent=2), title="Domain Reputation"))

    elif args.mode == "report":
        if not args.campaign_data:
            console.print("[red][-] --campaign-data required for report mode[/red]")
            return

        analyze_campaign_results(args.campaign_data, args.output)

    elif args.mode == "setup":
        console.print(
            Panel(
                "[bold]Spearphishing Campaign Setup Checklist[/bold]\n\n"
                "1. Register look-alike domain (age 2+ weeks)\n"
                "2. Configure SPF/DKIM/DMARC records\n"
                "3. Set up GoPhish or mail infrastructure\n"
                "4. Install SSL certificates\n"
                "5. Create landing pages\n"
                "6. Prepare email templates\n"
                "7. Import target list\n"
                "8. Test delivery to operator account\n"
                "9. Launch campaign in waves\n"
                "10. Monitor and collect evidence",
                title="Setup Guide",
            )
        )


if __name__ == "__main__":
    main()
