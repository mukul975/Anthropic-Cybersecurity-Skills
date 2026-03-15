#!/usr/bin/env python3
"""Agent for performing security headers audit.

Analyzes HTTP response headers for HSTS, CSP, X-Frame-Options,
cookie security attributes, and information disclosure to identify
missing or misconfigured browser-level protections.
"""

import requests
import json
import sys
import re
from urllib.parse import urlparse


class SecurityHeadersAgent:
    """Audits HTTP security headers on web applications."""

    def __init__(self, target_url):
        self.target_url = target_url
        if not target_url.startswith("http"):
            self.target_url = f"https://{target_url}"
        self.session = requests.Session()
        self.session.verify = True

    def fetch_headers(self, path="/"):
        """Fetch response headers from a target path."""
        url = f"{self.target_url.rstrip('/')}{path}"
        try:
            resp = self.session.get(url, timeout=10, allow_redirects=True)
            return {
                "url": url,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "cookies": [
                    {"name": c.name, "value": c.value[:20], "attributes": {
                        "secure": c.secure, "httponly": "httponly" in c._rest,
                        "samesite": c._rest.get("SameSite", c._rest.get("samesite", "Not set")),
                        "path": c.path, "domain": c.domain,
                    }} for c in resp.cookies
                ],
            }
        except requests.RequestException as e:
            return {"url": url, "error": str(e)}

    def check_hsts(self, headers):
        """Check HTTP Strict Transport Security configuration."""
        hsts = headers.get("Strict-Transport-Security", headers.get("strict-transport-security", ""))
        finding = {
            "header": "Strict-Transport-Security",
            "present": bool(hsts),
            "value": hsts,
            "severity": "High" if not hsts else "Info",
        }
        if hsts:
            finding["has_includeSubDomains"] = "includesubdomains" in hsts.lower()
            finding["has_preload"] = "preload" in hsts.lower()
            max_age_match = re.search(r"max-age=(\d+)", hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                finding["max_age"] = max_age
                finding["max_age_sufficient"] = max_age >= 31536000
                if max_age < 31536000:
                    finding["severity"] = "Medium"
                    finding["recommendation"] = "Increase max-age to at least 31536000 (1 year)"
        else:
            finding["recommendation"] = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        return finding

    def check_csp(self, headers):
        """Analyze Content Security Policy for weaknesses."""
        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        report_only = headers.get("Content-Security-Policy-Report-Only", "")

        finding = {
            "header": "Content-Security-Policy",
            "present": bool(csp),
            "value": csp[:500] if csp else "",
            "report_only": bool(report_only),
            "severity": "High" if not csp else "Info",
            "issues": [],
        }

        if csp:
            if "'unsafe-inline'" in csp:
                finding["issues"].append("unsafe-inline allows inline script execution (XSS risk)")
                finding["severity"] = "High"
            if "'unsafe-eval'" in csp:
                finding["issues"].append("unsafe-eval allows eval() calls (XSS risk)")
                finding["severity"] = "High"
            if " * " in f" {csp} " or csp.strip().endswith("*"):
                finding["issues"].append("Wildcard (*) allows loading from any origin")
                finding["severity"] = "Medium"
            if "default-src" not in csp:
                finding["issues"].append("Missing default-src fallback directive")
            if report_only and not csp:
                finding["issues"].append("CSP is report-only, not enforcing")
                finding["severity"] = "Medium"
        else:
            finding["recommendation"] = "Implement Content-Security-Policy with script-src using nonces"

        return finding

    def check_frame_options(self, headers):
        """Check X-Frame-Options and frame-ancestors."""
        xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
        csp = headers.get("Content-Security-Policy", "")
        frame_ancestors = ""
        if "frame-ancestors" in csp:
            match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if match:
                frame_ancestors = match.group(1).strip()

        finding = {
            "header": "X-Frame-Options",
            "present": bool(xfo),
            "value": xfo,
            "frame_ancestors": frame_ancestors,
            "severity": "Medium" if not xfo and not frame_ancestors else "Info",
        }
        if not xfo and not frame_ancestors:
            finding["recommendation"] = "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"
        return finding

    def check_content_type_options(self, headers):
        """Check X-Content-Type-Options."""
        xcto = headers.get("X-Content-Type-Options", headers.get("x-content-type-options", ""))
        return {
            "header": "X-Content-Type-Options",
            "present": bool(xcto),
            "value": xcto,
            "correct": xcto.lower() == "nosniff" if xcto else False,
            "severity": "Medium" if not xcto else "Info",
            "recommendation": "Add: X-Content-Type-Options: nosniff" if not xcto else None,
        }

    def check_referrer_policy(self, headers):
        """Check Referrer-Policy."""
        rp = headers.get("Referrer-Policy", headers.get("referrer-policy", ""))
        return {
            "header": "Referrer-Policy",
            "present": bool(rp),
            "value": rp,
            "severity": "Medium" if not rp else "Info",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin" if not rp else None,
        }

    def check_permissions_policy(self, headers):
        """Check Permissions-Policy."""
        pp = headers.get("Permissions-Policy", headers.get("permissions-policy", ""))
        return {
            "header": "Permissions-Policy",
            "present": bool(pp),
            "value": pp[:200] if pp else "",
            "severity": "Low" if not pp else "Info",
            "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()" if not pp else None,
        }

    def check_info_disclosure(self, headers):
        """Check for information disclosure headers."""
        findings = []
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        for h in disclosure_headers:
            value = headers.get(h, headers.get(h.lower(), ""))
            if value:
                findings.append({
                    "header": h,
                    "value": value,
                    "severity": "Low",
                    "recommendation": f"Remove or genericize {h} header",
                })
        return findings

    def check_cookie_security(self, cookies):
        """Audit cookie security attributes."""
        findings = []
        for cookie in cookies:
            attrs = cookie.get("attributes", {})
            issues = []
            if not attrs.get("secure"):
                issues.append("Missing Secure flag")
            if not attrs.get("httponly"):
                issues.append("Missing HttpOnly flag")
            samesite = str(attrs.get("samesite", "Not set"))
            if samesite == "Not set" or samesite == "None":
                issues.append(f"SameSite={samesite}")

            if issues:
                findings.append({
                    "cookie": cookie["name"],
                    "issues": issues,
                    "severity": "High" if "Secure" in str(issues) else "Medium",
                })
        return findings

    def calculate_grade(self, header_findings):
        """Calculate a letter grade based on findings."""
        score = 100
        for f in header_findings:
            if not f.get("present", True):
                sev = f.get("severity", "Info")
                if sev == "High":
                    score -= 20
                elif sev == "Medium":
                    score -= 10
                elif sev == "Low":
                    score -= 5
            if f.get("issues"):
                score -= len(f["issues"]) * 5

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        return "F"

    def run_audit(self, paths=None):
        """Run complete security headers audit."""
        if paths is None:
            paths = ["/"]

        all_findings = []
        for path in paths:
            response_data = self.fetch_headers(path)
            if "error" in response_data:
                continue

            headers = response_data["headers"]
            findings = {
                "path": path,
                "hsts": self.check_hsts(headers),
                "csp": self.check_csp(headers),
                "x_frame_options": self.check_frame_options(headers),
                "x_content_type_options": self.check_content_type_options(headers),
                "referrer_policy": self.check_referrer_policy(headers),
                "permissions_policy": self.check_permissions_policy(headers),
                "info_disclosure": self.check_info_disclosure(headers),
                "cookie_security": self.check_cookie_security(response_data.get("cookies", [])),
            }
            all_findings.append(findings)

        header_checks = []
        if all_findings:
            f = all_findings[0]
            header_checks = [f["hsts"], f["csp"], f["x_frame_options"],
                            f["x_content_type_options"], f["referrer_policy"],
                            f["permissions_policy"]]

        report = {
            "target": self.target_url,
            "audit_date": __import__("datetime").datetime.utcnow().isoformat(),
            "grade": self.calculate_grade(header_checks),
            "findings": all_findings,
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_url> [path1,path2,...]")
        sys.exit(1)

    target_url = sys.argv[1]
    paths = sys.argv[2].split(",") if len(sys.argv) > 2 else ["/"]

    agent = SecurityHeadersAgent(target_url)
    agent.run_audit(paths)


if __name__ == "__main__":
    main()
