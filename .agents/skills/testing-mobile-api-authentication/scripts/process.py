#!/usr/bin/env python3
"""
Mobile API Authentication Tester

Tests common authentication vulnerabilities in mobile API endpoints including
JWT analysis, IDOR detection, and session management assessment.

Usage:
    python process.py --base-url https://api.target.com --token <JWT> [--output report.json]
"""

import argparse
import base64
import json
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: 'requests' required. Install: pip install requests")
    sys.exit(1)


class MobileAPIAuthTester:
    """Tests mobile API authentication and authorization."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "User-Agent": "MobileSecurityTester/1.0",
        })

    def analyze_jwt(self) -> dict:
        """Analyze JWT token structure and identify vulnerabilities."""
        parts = self.token.split(".")
        if len(parts) != 3:
            return {"is_jwt": False, "format": "opaque_or_invalid"}

        try:
            # Decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            issues = []

            # Check algorithm
            alg = header.get("alg", "unknown")
            if alg.lower() == "none":
                issues.append({"issue": "none_algorithm", "severity": "CRITICAL"})
            elif alg.lower() in ("hs256", "hs384", "hs512"):
                issues.append({"issue": "hmac_algorithm_key_brute_forceable", "severity": "MEDIUM"})

            # Check expiration
            exp = payload.get("exp")
            if not exp:
                issues.append({"issue": "no_expiration_claim", "severity": "HIGH"})
            elif exp < time.time():
                issues.append({"issue": "token_already_expired", "severity": "INFO"})
            elif exp - time.time() > 86400 * 7:
                issues.append({"issue": "excessive_token_lifetime", "severity": "MEDIUM",
                               "details": f"Expires in {(exp - time.time()) / 86400:.0f} days"})

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "ssn", "credit_card"]
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    issues.append({"issue": f"sensitive_data_in_jwt: {key}", "severity": "HIGH"})

            # Check missing claims
            if "iss" not in payload:
                issues.append({"issue": "missing_issuer_claim", "severity": "LOW"})
            if "iat" not in payload:
                issues.append({"issue": "missing_issued_at_claim", "severity": "LOW"})

            finding = {
                "check": "jwt_analysis",
                "is_jwt": True,
                "algorithm": alg,
                "claims": list(payload.keys()),
                "issues": issues,
                "severity": "HIGH" if any(i["severity"] in ("CRITICAL", "HIGH") for i in issues) else "MEDIUM",
            }
            self.findings.append(finding)
            return finding

        except Exception as e:
            return {"is_jwt": True, "error": str(e)}

    def test_missing_auth(self, endpoints: list) -> list:
        """Test endpoints without authentication."""
        results = []
        for endpoint in endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                resp = requests.get(url, verify=False, timeout=10,
                                    headers={"User-Agent": "MobileSecurityTester/1.0"})
                if resp.status_code != 401 and resp.status_code != 403:
                    result = {
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "issue": "accessible_without_auth",
                        "severity": "CRITICAL",
                    }
                    results.append(result)
            except requests.RequestException:
                pass
            time.sleep(0.5)  # Rate limiting

        if results:
            self.findings.append({
                "check": "missing_authentication",
                "owasp_api": "API2",
                "endpoints_tested": len(endpoints),
                "unprotected": len(results),
                "details": results,
                "severity": "CRITICAL",
            })
        return results

    def test_expired_token(self) -> dict:
        """Test if expired tokens are accepted."""
        # Create a JWT with expired timestamp (modifying payload)
        parts = self.token.split(".")
        if len(parts) != 3:
            return {"check": "expired_token", "skipped": True}

        try:
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            if "exp" in payload and payload["exp"] < time.time():
                # Token is already expired, test if it still works
                resp = self.session.get(f"{self.base_url}/api/v1/users/me", timeout=10)
                accepted = resp.status_code == 200

                finding = {
                    "check": "expired_token_acceptance",
                    "token_expired": True,
                    "still_accepted": accepted,
                    "severity": "CRITICAL" if accepted else "PASS",
                }
                self.findings.append(finding)
                return finding
        except Exception:
            pass

        return {"check": "expired_token", "skipped": True, "reason": "token_not_expired"}

    def test_idor(self, endpoint_template: str, valid_id: str, other_ids: list) -> list:
        """Test for IDOR by substituting object IDs."""
        results = []
        for other_id in other_ids:
            url = f"{self.base_url}{endpoint_template.replace('{id}', other_id)}"
            try:
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    results.append({
                        "endpoint": url,
                        "original_id": valid_id,
                        "tested_id": other_id,
                        "accessible": True,
                        "severity": "CRITICAL",
                    })
            except requests.RequestException:
                pass
            time.sleep(0.5)

        if results:
            self.findings.append({
                "check": "idor",
                "owasp_api": "API1",
                "vulnerable_endpoints": len(results),
                "details": results,
                "severity": "CRITICAL",
            })
        return results

    def generate_report(self) -> dict:
        """Generate authentication test report."""
        severity_counts = {}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "assessment": {
                "target": self.base_url,
                "type": "Mobile API Authentication Testing",
                "date": datetime.now().isoformat(),
            },
            "summary": {
                "total_checks": len(self.findings),
                "severity_breakdown": severity_counts,
            },
            "findings": self.findings,
        }


def main():
    parser = argparse.ArgumentParser(description="Mobile API Authentication Tester")
    parser.add_argument("--base-url", required=True, help="API base URL")
    parser.add_argument("--token", required=True, help="Bearer token (JWT or opaque)")
    parser.add_argument("--output", default="auth_test.json", help="Output report")
    parser.add_argument("--endpoints", nargs="*", default=[
        "/api/v1/users/me", "/api/v1/users", "/api/v1/admin",
    ], help="Endpoints to test")
    args = parser.parse_args()

    tester = MobileAPIAuthTester(args.base_url, args.token)

    print("[*] Analyzing token...")
    tester.analyze_jwt()

    print("[*] Testing missing authentication...")
    tester.test_missing_auth(args.endpoints)

    print("[*] Testing expired token acceptance...")
    tester.test_expired_token()

    report = tester.generate_report()
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] Report saved: {args.output}")
    print(f"[*] Findings: {report['summary']['severity_breakdown']}")


if __name__ == "__main__":
    main()
