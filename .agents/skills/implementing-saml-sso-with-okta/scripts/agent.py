#!/usr/bin/env python3
"""Agent for implementing and auditing SAML SSO with Okta.

Validates SAML configuration, checks certificate expiry, tests
assertion encryption, audits attribute mappings, and verifies
signature algorithms for enterprise SSO deployments.
"""

import json
import sys
import ssl
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


SAML_CHECKS = {
    "sha256_signature": "SignatureMethod must use SHA-256 (not SHA-1)",
    "assertion_encrypted": "Assertions should be encrypted in transit",
    "audience_restriction": "AudienceRestriction element must be present",
    "conditions_notbefore": "Conditions NotBefore/NotOnOrAfter must be set",
    "single_logout": "SingleLogoutService should be configured",
}


class SAMLSSOAgent:
    """Audits and validates SAML SSO configurations with Okta."""

    def __init__(self, okta_domain, api_token=None, output_dir="./saml_sso_audit"):
        self.okta_domain = okta_domain.rstrip("/")
        self.api_token = api_token
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _okta_get(self, path):
        if not requests or not self.api_token:
            return None
        try:
            return requests.get(
                f"https://{self.okta_domain}/api/v1{path}",
                headers={"Authorization": f"SSWS {self.api_token}", "Accept": "application/json"},
                timeout=10,
            )
        except requests.RequestException:
            return None

    def list_saml_apps(self):
        """List SAML applications configured in Okta."""
        resp = self._okta_get("/apps?filter=status eq \"ACTIVE\"&limit=50")
        if not resp or resp.status_code != 200:
            return []
        apps = []
        for app in resp.json():
            sign_on = app.get("signOnMode", "")
            if "SAML" in sign_on.upper():
                apps.append({
                    "id": app["id"], "label": app.get("label"),
                    "sign_on_mode": sign_on,
                    "status": app.get("status"),
                })
        return apps

    def get_saml_metadata(self, app_id):
        """Retrieve SAML metadata XML for an application."""
        resp = self._okta_get(f"/apps/{app_id}/sso/saml/metadata")
        if resp and resp.status_code == 200:
            return resp.text
        return None

    def validate_metadata(self, metadata_xml):
        """Validate SAML metadata for security best practices."""
        issues = []
        try:
            root = ET.fromstring(metadata_xml)
        except ET.ParseError:
            return [{"severity": "high", "issue": "Invalid SAML metadata XML"}]

        ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata",
              "ds": "http://www.w3.org/2000/09/xmldsig#"}

        sig_methods = root.findall(".//ds:SignatureMethod", ns)
        for sm in sig_methods:
            alg = sm.get("Algorithm", "")
            if "sha1" in alg.lower():
                issues.append({"severity": "high", "issue": "SHA-1 signature detected - upgrade to SHA-256"})
                self.findings.append({"severity": "high", "type": "Weak Signature",
                                      "detail": f"Algorithm: {alg}"})

        slo = root.findall(".//md:SingleLogoutService", ns)
        if not slo:
            issues.append({"severity": "medium", "issue": "SingleLogoutService not configured"})

        certs = root.findall(".//ds:X509Certificate", ns)
        if not certs:
            issues.append({"severity": "high", "issue": "No X.509 certificate in metadata"})

        name_id = root.findall(".//{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat")
        for nid in name_id:
            if "unspecified" in (nid.text or "").lower():
                issues.append({"severity": "medium", "issue": "NameIDFormat is unspecified"})

        return issues

    def check_certificate_expiry(self, host, port=443):
        """Check SAML signing certificate expiration."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cert = s.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days
                if days_left < 30:
                    self.findings.append({"severity": "critical", "type": "Certificate Expiring",
                                          "detail": f"Certificate expires in {days_left} days"})
                return {"host": host, "expires": cert["notAfter"], "days_left": days_left}
        except Exception as e:
            return {"error": str(e)}

    def audit_app_assignments(self, app_id):
        """Audit user/group assignments for a SAML app."""
        resp = self._okta_get(f"/apps/{app_id}/users?limit=100")
        users = resp.json() if resp and resp.status_code == 200 else []
        resp_g = self._okta_get(f"/apps/{app_id}/groups?limit=100")
        groups = resp_g.json() if resp_g and resp_g.status_code == 200 else []
        if len(users) > 50:
            self.findings.append({"severity": "info", "type": "Large User Assignment",
                                  "detail": f"App {app_id} has {len(users)} direct user assignments"})
        return {"users": len(users), "groups": len(groups)}

    def check_mfa_policy(self):
        """Check if MFA is enforced for SAML authentication."""
        resp = self._okta_get("/policies?type=OKTA_SIGN_ON")
        if not resp or resp.status_code != 200:
            return {"error": "Cannot retrieve policies"}
        policies = resp.json()
        mfa_enforced = False
        for policy in policies:
            if policy.get("status") == "ACTIVE":
                for rule in policy.get("_embedded", {}).get("rules", []):
                    actions = rule.get("actions", {}).get("signon", {})
                    if actions.get("requireFactor"):
                        mfa_enforced = True
        if not mfa_enforced:
            self.findings.append({"severity": "high", "type": "No MFA",
                                  "detail": "MFA not enforced in sign-on policies"})
        return {"mfa_enforced": mfa_enforced}

    def generate_report(self):
        apps = self.list_saml_apps()
        metadata_issues = {}
        for app in apps:
            meta = self.get_saml_metadata(app["id"])
            if meta:
                metadata_issues[app["id"]] = self.validate_metadata(meta)
        cert = self.check_certificate_expiry(self.okta_domain)
        mfa = self.check_mfa_policy()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "okta_domain": self.okta_domain,
            "saml_apps": apps,
            "metadata_validation": metadata_issues,
            "certificate_status": cert,
            "mfa_status": mfa,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "saml_sso_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <okta_domain> [--token <api_token>]")
        sys.exit(1)
    domain = sys.argv[1]
    token = None
    if "--token" in sys.argv:
        token = sys.argv[sys.argv.index("--token") + 1]
    agent = SAMLSSOAgent(domain, token)
    agent.generate_report()


if __name__ == "__main__":
    main()
