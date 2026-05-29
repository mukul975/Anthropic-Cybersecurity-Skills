#!/usr/bin/env python3
"""Content Security Policy (CSP) analysis and bypass testing agent.

Fetches and analyzes CSP headers from web applications to identify
misconfigurations, overly permissive directives, and potential bypass
vectors. Tests for unsafe-inline, unsafe-eval, wildcard sources,
missing directives, and known CSP bypass patterns.

AUTHORIZED TESTING ONLY: Only use against targets you have explicit
written permission to test.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' library required: pip install requests", file=sys.stderr)
    sys.exit(1)


CSP_DIRECTIVES = [
    "default-src", "script-src", "style-src", "img-src", "font-src",
    "connect-src", "media-src", "object-src", "frame-src", "child-src",
    "worker-src", "frame-ancestors", "form-action", "base-uri",
    "manifest-src", "prefetch-src", "navigate-to",
]


def fetch_csp(url, headers=None, cookies=None):
    """Fetch CSP header(s) from a URL."""
    print(f"[*] Fetching CSP from {url}")
    h = headers or {}
    c = cookies or {}
    resp = requests.get(url, headers=h, cookies=c, timeout=15, allow_redirects=True)
    csp_header = resp.headers.get("Content-Security-Policy", "")
    csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
    print(f"[+] Status: {resp.status_code}")
    if csp_header:
        print(f"[+] CSP header found ({len(csp_header)} chars)")
    else:
        print("[!] No CSP header found")
    if csp_ro:
        print(f"[+] CSP-Report-Only header found ({len(csp_ro)} chars)")
    return csp_header, csp_ro, resp.status_code


def parse_csp(csp_string):
    """Parse a CSP string into a structured dict."""
    directives = {}
    if not csp_string:
        return directives
    for part in csp_string.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive_name = tokens[0].lower()
            values = tokens[1:] if len(tokens) > 1 else []
            directives[directive_name] = values
    return directives


def analyze_csp(directives, csp_string):
    """Analyze CSP directives for security weaknesses."""
    findings = []

    # Missing CSP entirely
    if not directives:
        findings.append({
            "check": "CSP Header Present",
            "severity": "HIGH",
            "status": "MISSING",
            "description": "No Content-Security-Policy header",
            "recommendation": "Implement a CSP header",
        })
        return findings

    # Check for missing critical directives
    if "default-src" not in directives:
        findings.append({
            "check": "default-src directive",
            "severity": "HIGH",
            "status": "MISSING",
            "description": "No default-src fallback directive",
            "recommendation": "Add default-src 'none' or default-src 'self'",
        })

    if "script-src" not in directives and "default-src" not in directives:
        findings.append({
            "check": "script-src directive",
            "severity": "CRITICAL",
            "status": "MISSING",
            "description": "No script-src or default-src; scripts unrestricted",
        })

    if "object-src" not in directives:
        findings.append({
            "check": "object-src directive",
            "severity": "MEDIUM",
            "status": "MISSING",
            "description": "Missing object-src; plugin-based XSS possible",
            "recommendation": "Add object-src 'none'",
        })

    if "base-uri" not in directives:
        findings.append({
            "check": "base-uri directive",
            "severity": "MEDIUM",
            "status": "MISSING",
            "description": "Missing base-uri; base tag injection possible",
            "recommendation": "Add base-uri 'self' or base-uri 'none'",
        })

    if "frame-ancestors" not in directives:
        findings.append({
            "check": "frame-ancestors directive",
            "severity": "MEDIUM",
            "status": "MISSING",
            "description": "Missing frame-ancestors; clickjacking possible",
            "recommendation": "Add frame-ancestors 'self'",
        })

    # Analyze each directive
    for directive, values in directives.items():
        values_str = " ".join(values)

        # unsafe-inline
        if "'unsafe-inline'" in values:
            sev = "CRITICAL" if directive in ("script-src", "default-src") else "MEDIUM"
            findings.append({
                "check": f"unsafe-inline in {directive}",
                "severity": sev,
                "status": "FAIL",
                "description": f"'unsafe-inline' allows inline scripts/styles in {directive}",
                "bypass": "Inject inline <script> or event handlers",
            })

        # unsafe-eval
        if "'unsafe-eval'" in values:
            findings.append({
                "check": f"unsafe-eval in {directive}",
                "severity": "CRITICAL" if directive in ("script-src", "default-src") else "HIGH",
                "status": "FAIL",
                "description": f"'unsafe-eval' allows eval() and similar in {directive}",
                "bypass": "Use eval(), Function(), setTimeout('string') for XSS",
            })

        # Wildcard sources
        if "*" in values:
            findings.append({
                "check": f"Wildcard (*) in {directive}",
                "severity": "HIGH",
                "status": "FAIL",
                "description": f"Wildcard source in {directive} allows loading from any origin",
                "bypass": "Host payload on any domain",
            })

        # data: URI
        if "data:" in values and directive in ("script-src", "default-src", "object-src"):
            findings.append({
                "check": f"data: URI in {directive}",
                "severity": "HIGH",
                "status": "FAIL",
                "description": f"data: URI in {directive} allows inline data execution",
                "bypass": "Use data:text/html payload or data:application/javascript",
            })

        # blob: URI
        if "blob:" in values and directive in ("script-src", "default-src", "worker-src"):
            findings.append({
                "check": f"blob: URI in {directive}",
                "severity": "MEDIUM",
                "status": "FAIL",
                "description": f"blob: URI in {directive} may allow bypass via Blob URLs",
            })

        # Known bypass CDNs
        bypass_cdns = ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
                       "ajax.googleapis.com", "raw.githubusercontent.com"]
        for cdn in bypass_cdns:
            if cdn in values_str:
                findings.append({
                    "check": f"Bypassable CDN in {directive}",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "description": f"{cdn} in {directive} can host arbitrary scripts",
                    "bypass": f"Upload/find malicious script on {cdn}",
                })

        # http: in HTTPS context
        if any(v.startswith("http:") for v in values):
            findings.append({
                "check": f"HTTP source in {directive}",
                "severity": "MEDIUM",
                "status": "FAIL",
                "description": f"HTTP source allows MitM injection in {directive}",
            })

    return findings


def format_summary(url, directives, findings, csp_string):
    """Print analysis summary."""
    print(f"\n{'='*60}")
    print("  CSP Analysis Report")
    print(f"{'='*60}")
    print(f"  URL           : {url}")
    print(f"  Directives    : {len(directives)}")
    print(f"  Findings      : {len(findings)}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    if directives:
        print("\n  Parsed Directives:")
        for d, v in directives.items():
            print(f"    {d:20s}: {' '.join(v)[:60]}")

    if findings:
        print("\n  Security Issues:")
        for f in findings:
            if f["severity"] in ("CRITICAL", "HIGH"):
                bypass = f" | Bypass: {f['bypass']}" if f.get("bypass") else ""
                print(f"    [{f['severity']:8s}] {f['check']}{bypass}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="CSP analysis and bypass testing agent (authorized testing only)"
    )
    parser.add_argument("--url", required=True, help="Target URL to fetch CSP from")
    parser.add_argument("--csp-string", help="Analyze a CSP string directly instead of fetching")
    parser.add_argument("--header", nargs="+", help="Custom headers (key:value)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.csp_string:
        csp_string = args.csp_string
        csp_ro = ""
        status_code = 0
    else:
        headers = {}
        if args.header:
            for h in args.header:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        cookies = {}
        if args.cookie:
            for pair in args.cookie.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    cookies[k] = v
        csp_string, csp_ro, status_code = fetch_csp(args.url, headers or None, cookies or None)

    directives = parse_csp(csp_string)
    findings = analyze_csp(directives, csp_string)

    if csp_ro:
        ro_directives = parse_csp(csp_ro)
        findings.append({
            "check": "CSP-Report-Only mode",
            "severity": "MEDIUM",
            "status": "WARN",
            "description": "CSP in report-only mode does not enforce restrictions",
        })

    severity_counts = format_summary(args.url, directives, findings, csp_string)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "CSP Analyzer",
        "url": args.url,
        "csp_header": csp_string,
        "csp_report_only": csp_ro,
        "directives": {k: v for k, v in directives.items()},
        "findings": findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
