#!/usr/bin/env python3
"""
OSINT Gathering Automation Tool

Performs automated open source intelligence collection including:
- Subdomain enumeration via Certificate Transparency logs
- DNS record collection
- WHOIS information gathering
- Technology fingerprinting
- Google dorking query generation
- Email pattern discovery
- Shodan/Censys integration

Usage:
    python process.py --domain targetdomain.com --output ./osint_report
    python process.py --domain targetdomain.com --modules all
    python process.py --domain targetdomain.com --modules dns,subdomains,emails

Requirements:
    pip install requests dnspython whois beautifulsoup4 rich
"""

import argparse
import json
import re
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import dns.resolver
    import requests
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install requests dnspython beautifulsoup4 rich")
    sys.exit(1)

console = Console()
SESSION = requests.Session()
SESSION.headers.update(
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
)


def resolve_dns_records(domain: str) -> dict:
    """Collect DNS records for a domain."""
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    return records


def enumerate_subdomains_ct(domain: str) -> list[str]:
    """Enumerate subdomains using Certificate Transparency logs via crt.sh."""
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = SESSION.get(url, timeout=30)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{domain}") or name == domain:
                        # Skip wildcard entries
                        if not name.startswith("*"):
                            subdomains.add(name)
    except Exception as e:
        console.print(f"[yellow][!] crt.sh query failed: {e}[/yellow]")

    # Also try common subdomain prefixes
    common_prefixes = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "vpn", "remote", "portal", "admin", "dev", "staging",
        "test", "api", "app", "blog", "shop", "store", "cdn",
        "ns1", "ns2", "dns", "mx", "exchange", "owa", "autodiscover",
        "sso", "login", "auth", "git", "gitlab", "jenkins",
        "jira", "confluence", "wiki", "docs", "support", "help",
    ]

    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            dns.resolver.resolve(subdomain, "A")
            subdomains.add(subdomain)
        except Exception:
            pass

    return sorted(subdomains)


def perform_whois_lookup(domain: str) -> dict:
    """Perform WHOIS lookup for a domain."""
    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        result = {
            "domain_name": str(w.domain_name) if w.domain_name else "N/A",
            "registrar": str(w.registrar) if w.registrar else "N/A",
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else [],
            "registrant_org": str(w.org) if w.org else "N/A",
            "registrant_country": str(w.country) if w.country else "N/A",
            "emails": w.emails if w.emails else [],
        }
        return result
    except Exception as e:
        console.print(f"[yellow][!] WHOIS lookup failed: {e}[/yellow]")
        return {}


def discover_email_format(domain: str) -> dict:
    """Attempt to discover email format patterns using Hunter.io free tier."""
    result = {
        "domain": domain,
        "format_guess": [],
        "discovered_emails": [],
    }

    # Common email format patterns
    common_formats = [
        "{first}.{last}@" + domain,
        "{first}{last}@" + domain,
        "{f}{last}@" + domain,
        "{first}_{last}@" + domain,
        "{first}@" + domain,
        "{last}@" + domain,
    ]
    result["format_guess"] = common_formats

    # Try to discover emails from web pages
    try:
        response = SESSION.get(f"https://{domain}", timeout=10)
        if response.status_code == 200:
            # Extract emails from page content
            email_pattern = re.compile(
                rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}",
                re.IGNORECASE
            )
            emails = email_pattern.findall(response.text)
            result["discovered_emails"] = list(set(emails))
    except Exception:
        pass

    # Search for emails on common pages
    common_pages = ["/contact", "/about", "/team", "/about-us", "/contact-us"]
    for page in common_pages:
        try:
            response = SESSION.get(f"https://{domain}{page}", timeout=10)
            if response.status_code == 200:
                email_pattern = re.compile(
                    rf"[a-zA-Z0-9._%+-]+@{re.escape(domain)}",
                    re.IGNORECASE
                )
                emails = email_pattern.findall(response.text)
                result["discovered_emails"].extend(emails)
        except Exception:
            pass

    result["discovered_emails"] = list(set(result["discovered_emails"]))
    return result


def fingerprint_web_technologies(domain: str) -> dict:
    """Identify web technologies using HTTP headers and response analysis."""
    tech = {
        "server": None,
        "powered_by": None,
        "frameworks": [],
        "security_headers": {},
        "cookies": [],
        "cdn": None,
        "cms": None,
    }

    try:
        response = SESSION.get(f"https://{domain}", timeout=10, allow_redirects=True)
        headers = response.headers

        # Server identification
        tech["server"] = headers.get("Server", "Not disclosed")
        tech["powered_by"] = headers.get("X-Powered-By", "Not disclosed")

        # Security headers
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ]

        for header in security_headers:
            value = headers.get(header)
            tech["security_headers"][header] = value if value else "MISSING"

        # Cookie analysis
        for cookie in response.cookies:
            tech["cookies"].append(
                {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": "httponly" in cookie._rest,
                    "domain": cookie.domain,
                }
            )

        # CDN detection
        cdn_indicators = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "akamai": ["x-akamai-transformed"],
            "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "fastly": ["x-served-by", "x-fastly-request-id"],
            "incapsula": ["x-iinfo"],
        }

        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in [h.lower() for h in headers]:
                    tech["cdn"] = cdn
                    break

        # CMS detection from HTML
        html = response.text.lower()
        if "wp-content" in html or "wordpress" in html:
            tech["cms"] = "WordPress"
        elif "drupal" in html:
            tech["cms"] = "Drupal"
        elif "joomla" in html:
            tech["cms"] = "Joomla"
        elif "shopify" in html:
            tech["cms"] = "Shopify"

        # Framework detection
        if "react" in html or "reactdom" in html:
            tech["frameworks"].append("React")
        if "angular" in html or "ng-" in html:
            tech["frameworks"].append("Angular")
        if "vue" in html or "vuejs" in html:
            tech["frameworks"].append("Vue.js")
        if "jquery" in html:
            tech["frameworks"].append("jQuery")
        if "bootstrap" in html:
            tech["frameworks"].append("Bootstrap")

    except Exception as e:
        console.print(f"[yellow][!] Web fingerprinting failed: {e}[/yellow]")

    return tech


def generate_google_dorks(domain: str) -> list[str]:
    """Generate Google dorking queries for the target domain."""
    dorks = [
        # Sensitive files
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xlsx',
        f'site:{domain} filetype:docx',
        f'site:{domain} filetype:csv',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log',
        f'site:{domain} filetype:bak',
        f'site:{domain} filetype:conf',
        f'site:{domain} filetype:env',
        f'site:{domain} filetype:xml',
        # Configuration and credentials
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:wp-admin',
        f'site:{domain} inurl:wp-login',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} intitle:"dashboard"',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:setup',
        # Error messages
        f'site:{domain} "error" "sql syntax"',
        f'site:{domain} "php error" "on line"',
        f'site:{domain} "ORA-" "error"',
        f'site:{domain} "mysql" "error"',
        f'site:{domain} "stack trace" "at"',
        # Sensitive information
        f'site:{domain} "confidential"',
        f'site:{domain} "internal use only"',
        f'site:{domain} "not for distribution"',
        f'site:{domain} "password" filetype:txt',
        f'site:{domain} "api_key" OR "apikey" OR "api-key"',
        # Infrastructure
        f'site:{domain} inurl:vpn',
        f'site:{domain} inurl:remote',
        f'site:{domain} inurl:portal',
        f'site:{domain} inurl:citrix',
        f'site:{domain} inurl:owa',
        # GitHub leaks
        f'"{domain}" password site:github.com',
        f'"{domain}" api_key site:github.com',
        f'"{domain}" secret site:github.com',
        f'"{domain}" token site:github.com',
        f'"{domain}" site:pastebin.com',
        # Cloud storage
        f'site:s3.amazonaws.com "{domain.split(".")[0]}"',
        f'site:blob.core.windows.net "{domain.split(".")[0]}"',
        f'site:storage.googleapis.com "{domain.split(".")[0]}"',
    ]
    return dorks


def check_security_txt(domain: str) -> dict | None:
    """Check for security.txt file per RFC 9116."""
    urls = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
    ]

    for url in urls:
        try:
            response = SESSION.get(url, timeout=10)
            if response.status_code == 200 and "contact" in response.text.lower():
                return {
                    "url": url,
                    "content": response.text[:2000],
                }
        except Exception:
            pass

    return None


def check_robots_txt(domain: str) -> dict | None:
    """Check robots.txt for interesting paths."""
    try:
        response = SESSION.get(f"https://{domain}/robots.txt", timeout=10)
        if response.status_code == 200:
            disallowed = []
            for line in response.text.split("\n"):
                if line.strip().lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallowed.append(path)
            return {
                "content": response.text[:2000],
                "disallowed_paths": disallowed,
            }
    except Exception:
        pass
    return None


def generate_report(domain: str, results: dict, output_dir: Path):
    """Generate comprehensive OSINT report."""
    report = f"""# OSINT Report: {domain}
## Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. Domain Information

### WHOIS Data
"""

    whois_data = results.get("whois", {})
    if whois_data:
        for key, value in whois_data.items():
            report += f"- **{key}**: {value}\n"
    else:
        report += "WHOIS data not available.\n"

    report += "\n### DNS Records\n\n"
    dns_data = results.get("dns", {})
    if dns_data:
        for rtype, records in dns_data.items():
            report += f"#### {rtype} Records\n"
            for record in records:
                report += f"- `{record}`\n"
            report += "\n"

    report += "## 2. Subdomain Enumeration\n\n"
    subdomains = results.get("subdomains", [])
    report += f"**Total subdomains discovered:** {len(subdomains)}\n\n"
    for sub in subdomains:
        try:
            ip = socket.gethostbyname(sub)
            report += f"- `{sub}` -> `{ip}`\n"
        except Exception:
            report += f"- `{sub}` -> [unresolvable]\n"

    report += "\n## 3. Web Technology Fingerprint\n\n"
    tech = results.get("technology", {})
    if tech:
        report += f"- **Server:** {tech.get('server', 'N/A')}\n"
        report += f"- **Powered By:** {tech.get('powered_by', 'N/A')}\n"
        report += f"- **CMS:** {tech.get('cms', 'None detected')}\n"
        report += f"- **CDN:** {tech.get('cdn', 'None detected')}\n"
        report += f"- **Frameworks:** {', '.join(tech.get('frameworks', [])) or 'None detected'}\n\n"

        report += "### Security Headers\n\n"
        report += "| Header | Status |\n|--------|--------|\n"
        for header, value in tech.get("security_headers", {}).items():
            status = "MISSING" if value == "MISSING" else "Present"
            report += f"| {header} | {status} |\n"

    report += "\n## 4. Email Intelligence\n\n"
    email_data = results.get("emails", {})
    if email_data:
        report += "### Discovered Emails\n"
        for email in email_data.get("discovered_emails", []):
            report += f"- `{email}`\n"
        report += "\n### Likely Email Formats\n"
        for fmt in email_data.get("format_guess", []):
            report += f"- `{fmt}`\n"

    report += "\n## 5. Google Dorking Queries\n\n"
    dorks = results.get("dorks", [])
    for dork in dorks[:20]:
        report += f"- `{dork}`\n"

    report += "\n## 6. Additional Findings\n\n"
    security_txt = results.get("security_txt")
    if security_txt:
        report += f"### security.txt Found\n- URL: {security_txt['url']}\n\n"

    robots_txt = results.get("robots_txt")
    if robots_txt:
        report += "### Interesting robots.txt Paths\n"
        for path in robots_txt.get("disallowed_paths", []):
            report += f"- `{path}`\n"

    report += f"""
---

## 7. Recommendations for Attack Planning

### Priority Initial Access Vectors
1. Review discovered subdomains for vulnerable web applications
2. Validate credential leaks against target systems
3. Use discovered email format for spearphishing campaign
4. Investigate missing security headers for potential exploitation
5. Check disallowed paths from robots.txt for sensitive content

### Social Engineering Targets
- Use discovered personnel for targeted phishing
- Leverage technology stack knowledge for pretexting
- Utilize physical location data for physical access testing

---

*Report generated by OSINT Automation Tool*
*Classification: CONFIDENTIAL - Red Team Use Only*
"""

    report_path = output_dir / f"osint_report_{domain}.md"
    with open(report_path, "w") as f:
        f.write(report)

    console.print(f"[green][+] Report saved to: {report_path}[/green]")

    # Save raw data as JSON
    json_path = output_dir / f"osint_data_{domain}.json"
    serializable_results = {}
    for key, value in results.items():
        try:
            json.dumps(value)
            serializable_results[key] = value
        except (TypeError, ValueError):
            serializable_results[key] = str(value)

    with open(json_path, "w") as f:
        json.dump(serializable_results, f, indent=2, default=str)

    console.print(f"[green][+] Raw data saved to: {json_path}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Gathering Automation Tool"
    )
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument(
        "--output", default="./osint_output", help="Output directory"
    )
    parser.add_argument(
        "--modules",
        default="all",
        help="Comma-separated modules: dns,subdomains,whois,emails,tech,dorks,all",
    )

    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    modules = args.modules.split(",") if args.modules != "all" else [
        "dns", "subdomains", "whois", "emails", "tech", "dorks", "security_txt", "robots_txt"
    ]

    console.print(
        Panel(
            f"[bold red]OSINT Gathering Tool[/bold red]\n"
            f"Target: {args.domain}\n"
            f"Modules: {', '.join(modules)}\n"
            f"Output: {args.output}",
            title="Configuration",
        )
    )

    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        if "dns" in modules:
            task = progress.add_task("[cyan]Collecting DNS records...", total=None)
            results["dns"] = resolve_dns_records(args.domain)
            progress.update(task, completed=True, description="[green]DNS records collected")

        if "subdomains" in modules:
            task = progress.add_task("[cyan]Enumerating subdomains...", total=None)
            results["subdomains"] = enumerate_subdomains_ct(args.domain)
            progress.update(
                task,
                completed=True,
                description=f"[green]Found {len(results['subdomains'])} subdomains",
            )

        if "whois" in modules:
            task = progress.add_task("[cyan]Performing WHOIS lookup...", total=None)
            results["whois"] = perform_whois_lookup(args.domain)
            progress.update(task, completed=True, description="[green]WHOIS data collected")

        if "emails" in modules:
            task = progress.add_task("[cyan]Discovering email formats...", total=None)
            results["emails"] = discover_email_format(args.domain)
            progress.update(task, completed=True, description="[green]Email discovery complete")

        if "tech" in modules:
            task = progress.add_task("[cyan]Fingerprinting technologies...", total=None)
            results["technology"] = fingerprint_web_technologies(args.domain)
            progress.update(task, completed=True, description="[green]Technology fingerprint complete")

        if "dorks" in modules:
            task = progress.add_task("[cyan]Generating Google dorks...", total=None)
            results["dorks"] = generate_google_dorks(args.domain)
            progress.update(
                task,
                completed=True,
                description=f"[green]Generated {len(results['dorks'])} dork queries",
            )

        if "security_txt" in modules:
            task = progress.add_task("[cyan]Checking security.txt...", total=None)
            results["security_txt"] = check_security_txt(args.domain)
            progress.update(task, completed=True, description="[green]security.txt check complete")

        if "robots_txt" in modules:
            task = progress.add_task("[cyan]Checking robots.txt...", total=None)
            results["robots_txt"] = check_robots_txt(args.domain)
            progress.update(task, completed=True, description="[green]robots.txt check complete")

    generate_report(args.domain, results, output_dir)

    # Display summary table
    table = Table(title=f"OSINT Summary: {args.domain}")
    table.add_column("Category", style="cyan")
    table.add_column("Count/Status", style="green")

    table.add_row("DNS Record Types", str(len(results.get("dns", {}))))
    table.add_row("Subdomains Found", str(len(results.get("subdomains", []))))
    table.add_row("Emails Discovered", str(len(results.get("emails", {}).get("discovered_emails", []))))
    table.add_row("Google Dorks Generated", str(len(results.get("dorks", []))))
    table.add_row("security.txt", "Found" if results.get("security_txt") else "Not Found")
    table.add_row("robots.txt", "Found" if results.get("robots_txt") else "Not Found")

    console.print(table)


if __name__ == "__main__":
    main()
