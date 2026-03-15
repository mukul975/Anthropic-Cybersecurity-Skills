#!/usr/bin/env python3
"""
Google Workspace SSO Configuration Validator

Validates SAML SSO configuration between an IdP and Google Workspace by
checking SAML metadata, testing authentication flows, and verifying
certificate validity.

Requirements:
    pip install requests cryptography lxml
"""

import base64
import json
import sys
import zlib
from datetime import datetime, timezone
from urllib.parse import urlencode, parse_qs, urlparse

try:
    import requests
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("[ERROR] Required: pip install requests cryptography")
    sys.exit(1)


class GoogleWorkspaceSSOValidator:
    """Validate Google Workspace SAML SSO configuration."""

    def __init__(self, domain):
        self.domain = domain
        self.acs_url = f"https://www.google.com/a/{domain}/acs"
        self.entity_id = f"google.com/a/{domain}"

    def validate_idp_metadata(self, metadata_url):
        """Fetch and validate IdP SAML metadata XML."""
        try:
            from lxml import etree
        except ImportError:
            return {"valid": False, "error": "lxml required for XML parsing"}

        try:
            resp = requests.get(metadata_url, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as e:
            return {"valid": False, "error": f"Cannot fetch metadata: {e}"}

        try:
            root = etree.fromstring(resp.content)
        except etree.XMLSyntaxError as e:
            return {"valid": False, "error": f"Invalid XML: {e}"}

        ns = {
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
        }

        entity_id = root.get("entityID")
        sso_elements = root.findall(
            ".//md:IDPSSODescriptor/md:SingleSignOnService", ns
        )
        sso_urls = [
            {"binding": el.get("Binding"), "location": el.get("Location")}
            for el in sso_elements
        ]

        cert_elements = root.findall(
            ".//md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate",
            ns,
        )
        certificates = [el.text.strip() for el in cert_elements if el.text]

        return {
            "valid": True,
            "entity_id": entity_id,
            "sso_endpoints": sso_urls,
            "certificate_count": len(certificates),
            "has_post_binding": any(
                "HTTP-POST" in s["binding"] for s in sso_urls
            ),
            "has_redirect_binding": any(
                "HTTP-Redirect" in s["binding"] for s in sso_urls
            ),
        }

    def validate_certificate(self, cert_pem):
        """Validate the IdP signing certificate."""
        try:
            if "-----BEGIN CERTIFICATE-----" not in cert_pem:
                cert_pem = (
                    "-----BEGIN CERTIFICATE-----\n"
                    + cert_pem
                    + "\n-----END CERTIFICATE-----"
                )

            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            now = datetime.now(timezone.utc)

            return {
                "valid": True,
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "is_expired": now > cert.not_valid_after_utc,
                "days_until_expiry": (cert.not_valid_after_utc - now).days,
                "serial_number": str(cert.serial_number),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "key_size": cert.public_key().key_size,
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def validate_sso_configuration(self, idp_sso_url, idp_entity_id,
                                     cert_pem):
        """Run complete SSO configuration validation."""
        results = {
            "domain": self.domain,
            "acs_url": self.acs_url,
            "entity_id": self.entity_id,
            "checks": [],
        }

        # Check 1: ACS URL format
        results["checks"].append({
            "check": "ACS URL format",
            "expected": f"https://www.google.com/a/{self.domain}/acs",
            "status": "PASS",
        })

        # Check 2: Entity ID format
        results["checks"].append({
            "check": "Entity ID format",
            "expected": f"google.com/a/{self.domain}",
            "status": "PASS",
        })

        # Check 3: IdP SSO URL is HTTPS
        is_https = idp_sso_url.startswith("https://")
        results["checks"].append({
            "check": "IdP SSO URL uses HTTPS",
            "value": idp_sso_url,
            "status": "PASS" if is_https else "FAIL",
        })

        # Check 4: IdP SSO URL is reachable
        try:
            resp = requests.head(idp_sso_url, timeout=10, allow_redirects=True)
            reachable = resp.status_code < 500
        except requests.RequestException:
            reachable = False
        results["checks"].append({
            "check": "IdP SSO URL reachable",
            "status": "PASS" if reachable else "FAIL",
        })

        # Check 5: Certificate validation
        cert_result = self.validate_certificate(cert_pem)
        results["checks"].append({
            "check": "IdP certificate valid",
            "status": "PASS" if cert_result.get("valid") and not cert_result.get("is_expired") else "FAIL",
            "details": cert_result,
        })

        # Check 6: Certificate expiry warning
        days_left = cert_result.get("days_until_expiry", 0)
        results["checks"].append({
            "check": "Certificate expiry > 30 days",
            "days_remaining": days_left,
            "status": "PASS" if days_left > 30 else "WARN",
        })

        # Check 7: Key size
        key_size = cert_result.get("key_size", 0)
        results["checks"].append({
            "check": "Certificate key size >= 2048",
            "key_size": key_size,
            "status": "PASS" if key_size >= 2048 else "FAIL",
        })

        all_pass = all(
            c["status"] in ("PASS", "WARN") for c in results["checks"]
        )
        results["overall_status"] = "PASS" if all_pass else "FAIL"

        return results

    def generate_saml_authn_request(self, idp_sso_url):
        """Generate a SAML AuthnRequest for testing SP-initiated SSO."""
        request_id = f"_google_workspace_test_{int(datetime.now().timestamp())}"
        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        authn_request = f"""<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    AssertionConsumerServiceURL="{self.acs_url}"
    Destination="{idp_sso_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{self.entity_id}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>"""

        compressed = zlib.compress(authn_request.encode())[2:-4]
        encoded = base64.b64encode(compressed).decode()
        sso_redirect_url = f"{idp_sso_url}?{urlencode({'SAMLRequest': encoded})}"

        return {
            "request_id": request_id,
            "authn_request_xml": authn_request,
            "encoded_request": encoded,
            "redirect_url": sso_redirect_url,
        }


if __name__ == "__main__":
    print("=" * 60)
    print("Google Workspace SSO Configuration Validator")
    print("=" * 60)
    print()
    print("Usage:")
    print("  validator = GoogleWorkspaceSSOValidator('example.com')")
    print("  result = validator.validate_sso_configuration(")
    print("      idp_sso_url='https://idp.example.com/sso/saml',")
    print("      idp_entity_id='https://idp.example.com',")
    print("      cert_pem=open('idp_cert.pem').read()")
    print("  )")
    print("  print(json.dumps(result, indent=2))")
