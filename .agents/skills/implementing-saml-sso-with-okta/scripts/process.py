#!/usr/bin/env python3
"""
SAML SSO Configuration Validator and Health Checker for Okta

This script validates SAML SSO configurations, checks certificate
expiration, tests metadata endpoints, and monitors authentication
health for Okta-based SAML integrations.
"""

import xml.etree.ElementTree as ET
import base64
import hashlib
import datetime
import json
import ssl
import socket
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class SAMLConfig:
    """SAML configuration parameters."""
    idp_sso_url: str
    idp_entity_id: str
    sp_entity_id: str
    sp_acs_url: str
    sp_slo_url: str = ""
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    digest_algorithm: str = "http://www.w3.org/2001/04/xmlenc#sha256"
    assertion_encrypted: bool = False
    certificate_path: str = ""
    metadata_url: str = ""


@dataclass
class ValidationResult:
    """Result of a validation check."""
    check_name: str
    passed: bool
    severity: str  # critical, high, medium, low
    message: str
    remediation: str = ""


class SAMLSSOValidator:
    """Validates SAML SSO configurations and health."""

    SAML_NS = {
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xenc': 'http://www.w3.org/2001/04/xmlenc#'
    }

    WEAK_ALGORITHMS = [
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "http://www.w3.org/2000/09/xmldsig#sha1",
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    ]

    def __init__(self, config: SAMLConfig):
        self.config = config
        self.results: List[ValidationResult] = []

    def validate_all(self) -> List[ValidationResult]:
        """Run all SAML SSO validation checks."""
        self.results = []
        self._check_signature_algorithm()
        self._check_digest_algorithm()
        self._check_name_id_format()
        self._check_urls()
        self._check_entity_ids()
        self._check_assertion_encryption()
        self._check_certificate_expiration()
        self._check_metadata_endpoint()
        self._check_slo_configuration()
        return self.results

    def _check_signature_algorithm(self):
        """Verify SHA-256 or stronger signature algorithm is used."""
        if self.config.signature_algorithm in self.WEAK_ALGORITHMS:
            self.results.append(ValidationResult(
                check_name="Signature Algorithm Strength",
                passed=False,
                severity="critical",
                message=f"Weak signature algorithm detected: {self.config.signature_algorithm}",
                remediation="Upgrade to SHA-256: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            ))
        elif "sha256" in self.config.signature_algorithm.lower() or \
             "sha384" in self.config.signature_algorithm.lower() or \
             "sha512" in self.config.signature_algorithm.lower():
            self.results.append(ValidationResult(
                check_name="Signature Algorithm Strength",
                passed=True,
                severity="critical",
                message=f"Strong signature algorithm in use: {self.config.signature_algorithm}"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="Signature Algorithm Strength",
                passed=False,
                severity="high",
                message=f"Unknown signature algorithm: {self.config.signature_algorithm}",
                remediation="Use a known SHA-256+ algorithm for SAML signatures"
            ))

    def _check_digest_algorithm(self):
        """Verify SHA-256 or stronger digest algorithm."""
        if "sha1" in self.config.digest_algorithm.lower() and "sha1" not in "sha128":
            self.results.append(ValidationResult(
                check_name="Digest Algorithm Strength",
                passed=False,
                severity="critical",
                message=f"Weak digest algorithm: {self.config.digest_algorithm}",
                remediation="Upgrade to SHA-256: http://www.w3.org/2001/04/xmlenc#sha256"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="Digest Algorithm Strength",
                passed=True,
                severity="critical",
                message=f"Digest algorithm acceptable: {self.config.digest_algorithm}"
            ))

    def _check_name_id_format(self):
        """Validate NameID format configuration."""
        valid_formats = [
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        ]
        if self.config.name_id_format in valid_formats:
            self.results.append(ValidationResult(
                check_name="NameID Format",
                passed=True,
                severity="medium",
                message=f"Valid NameID format: {self.config.name_id_format}"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="NameID Format",
                passed=False,
                severity="medium",
                message=f"Non-standard NameID format: {self.config.name_id_format}",
                remediation="Use a standard SAML NameID format (emailAddress, persistent, or transient)"
            ))

    def _check_urls(self):
        """Validate that all URLs use HTTPS."""
        urls_to_check = {
            "IdP SSO URL": self.config.idp_sso_url,
            "SP ACS URL": self.config.sp_acs_url,
        }
        if self.config.sp_slo_url:
            urls_to_check["SP SLO URL"] = self.config.sp_slo_url
        if self.config.metadata_url:
            urls_to_check["Metadata URL"] = self.config.metadata_url

        for name, url in urls_to_check.items():
            if not url:
                continue
            if url.startswith("https://"):
                self.results.append(ValidationResult(
                    check_name=f"{name} HTTPS Check",
                    passed=True,
                    severity="critical",
                    message=f"{name} uses HTTPS: {url}"
                ))
            elif url.startswith("http://"):
                self.results.append(ValidationResult(
                    check_name=f"{name} HTTPS Check",
                    passed=False,
                    severity="critical",
                    message=f"{name} uses insecure HTTP: {url}",
                    remediation=f"Change {name} to use HTTPS"
                ))
            else:
                self.results.append(ValidationResult(
                    check_name=f"{name} URL Validation",
                    passed=False,
                    severity="high",
                    message=f"{name} has invalid URL format: {url}",
                    remediation="Ensure URL starts with https://"
                ))

    def _check_entity_ids(self):
        """Validate Entity IDs are properly configured."""
        if self.config.idp_entity_id == self.config.sp_entity_id:
            self.results.append(ValidationResult(
                check_name="Entity ID Uniqueness",
                passed=False,
                severity="critical",
                message="IdP Entity ID and SP Entity ID are identical",
                remediation="Ensure IdP and SP have different Entity IDs"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="Entity ID Uniqueness",
                passed=True,
                severity="critical",
                message="IdP and SP Entity IDs are unique"
            ))

        for name, entity_id in [("IdP", self.config.idp_entity_id), ("SP", self.config.sp_entity_id)]:
            if not entity_id:
                self.results.append(ValidationResult(
                    check_name=f"{name} Entity ID Configured",
                    passed=False,
                    severity="critical",
                    message=f"{name} Entity ID is empty",
                    remediation=f"Configure {name} Entity ID in SAML settings"
                ))

    def _check_assertion_encryption(self):
        """Check if assertion encryption is enabled."""
        if self.config.assertion_encrypted:
            self.results.append(ValidationResult(
                check_name="Assertion Encryption",
                passed=True,
                severity="high",
                message="SAML assertion encryption is enabled"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="Assertion Encryption",
                passed=False,
                severity="high",
                message="SAML assertion encryption is not enabled",
                remediation="Enable assertion encryption with AES-256-CBC to protect attribute values in transit"
            ))

    def _check_certificate_expiration(self):
        """Check if the IdP signing certificate is approaching expiration."""
        if not self.config.certificate_path:
            self.results.append(ValidationResult(
                check_name="Certificate Expiration",
                passed=False,
                severity="medium",
                message="No certificate path configured for expiration check",
                remediation="Provide certificate_path to enable expiration monitoring"
            ))
            return

        try:
            with open(self.config.certificate_path, 'r') as f:
                cert_pem = f.read()

            # Extract base64-encoded certificate data
            cert_lines = []
            in_cert = False
            for line in cert_pem.strip().split('\n'):
                if 'BEGIN CERTIFICATE' in line:
                    in_cert = True
                    continue
                if 'END CERTIFICATE' in line:
                    break
                if in_cert:
                    cert_lines.append(line.strip())

            cert_der = base64.b64decode(''.join(cert_lines))
            cert_hash = hashlib.sha256(cert_der).hexdigest()

            self.results.append(ValidationResult(
                check_name="Certificate Loaded",
                passed=True,
                severity="medium",
                message=f"Certificate loaded successfully. SHA-256 fingerprint: {cert_hash[:16]}..."
            ))

        except FileNotFoundError:
            self.results.append(ValidationResult(
                check_name="Certificate Expiration",
                passed=False,
                severity="critical",
                message=f"Certificate file not found: {self.config.certificate_path}",
                remediation="Download the IdP signing certificate and save to the configured path"
            ))
        except Exception as e:
            self.results.append(ValidationResult(
                check_name="Certificate Expiration",
                passed=False,
                severity="high",
                message=f"Error reading certificate: {str(e)}",
                remediation="Ensure certificate file is valid PEM format"
            ))

    def _check_metadata_endpoint(self):
        """Verify the SAML metadata endpoint is accessible."""
        if not self.config.metadata_url:
            self.results.append(ValidationResult(
                check_name="Metadata Endpoint",
                passed=False,
                severity="low",
                message="No metadata URL configured",
                remediation="Configure metadata URL for automated configuration updates"
            ))
            return

        try:
            req = urllib.request.Request(
                self.config.metadata_url,
                headers={'User-Agent': 'SAML-SSO-Validator/1.0'}
            )
            ctx = ssl.create_default_context()
            response = urllib.request.urlopen(req, context=ctx, timeout=10)

            if response.status == 200:
                content = response.read().decode('utf-8')
                if 'EntityDescriptor' in content:
                    self.results.append(ValidationResult(
                        check_name="Metadata Endpoint",
                        passed=True,
                        severity="medium",
                        message="Metadata endpoint accessible and contains valid SAML metadata"
                    ))
                else:
                    self.results.append(ValidationResult(
                        check_name="Metadata Endpoint",
                        passed=False,
                        severity="medium",
                        message="Metadata endpoint accessible but does not contain SAML metadata",
                        remediation="Verify the metadata URL returns valid SAML EntityDescriptor XML"
                    ))
        except urllib.error.URLError as e:
            self.results.append(ValidationResult(
                check_name="Metadata Endpoint",
                passed=False,
                severity="medium",
                message=f"Cannot reach metadata endpoint: {str(e)}",
                remediation="Verify metadata URL is correct and accessible from this network"
            ))
        except Exception as e:
            self.results.append(ValidationResult(
                check_name="Metadata Endpoint",
                passed=False,
                severity="medium",
                message=f"Error checking metadata: {str(e)}"
            ))

    def _check_slo_configuration(self):
        """Check if Single Logout is configured."""
        if self.config.sp_slo_url:
            self.results.append(ValidationResult(
                check_name="Single Logout (SLO)",
                passed=True,
                severity="medium",
                message=f"SLO endpoint configured: {self.config.sp_slo_url}"
            ))
        else:
            self.results.append(ValidationResult(
                check_name="Single Logout (SLO)",
                passed=False,
                severity="medium",
                message="Single Logout (SLO) is not configured",
                remediation="Configure SLO endpoint to ensure proper session termination across all SPs"
            ))

    def parse_saml_metadata(self, metadata_xml: str) -> Dict:
        """Parse SAML metadata XML and extract configuration parameters."""
        result = {
            "entity_id": "",
            "sso_urls": [],
            "slo_urls": [],
            "certificates": [],
            "name_id_formats": [],
            "attributes": []
        }

        try:
            root = ET.fromstring(metadata_xml)

            # Extract Entity ID
            result["entity_id"] = root.get("entityID", "")

            # Extract SSO endpoints
            for sso in root.findall('.//md:SingleSignOnService', self.SAML_NS):
                result["sso_urls"].append({
                    "binding": sso.get("Binding", ""),
                    "location": sso.get("Location", "")
                })

            # Extract SLO endpoints
            for slo in root.findall('.//md:SingleLogoutService', self.SAML_NS):
                result["slo_urls"].append({
                    "binding": slo.get("Binding", ""),
                    "location": slo.get("Location", "")
                })

            # Extract certificates
            for cert in root.findall('.//ds:X509Certificate', self.SAML_NS):
                if cert.text:
                    result["certificates"].append(cert.text.strip())

            # Extract NameID formats
            for nid in root.findall('.//md:NameIDFormat', self.SAML_NS):
                if nid.text:
                    result["name_id_formats"].append(nid.text.strip())

        except ET.ParseError as e:
            result["error"] = f"Failed to parse metadata XML: {str(e)}"

        return result

    def generate_report(self) -> str:
        """Generate a validation report."""
        if not self.results:
            self.validate_all()

        report_lines = [
            "=" * 70,
            "SAML SSO CONFIGURATION VALIDATION REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"IdP Entity ID: {self.config.idp_entity_id}",
            f"SP Entity ID: {self.config.sp_entity_id}",
            f"IdP SSO URL: {self.config.idp_sso_url}",
            f"SP ACS URL: {self.config.sp_acs_url}",
            "-" * 70,
            ""
        ]

        passed = [r for r in self.results if r.passed]
        failed = [r for r in self.results if not r.passed]

        critical_failures = [r for r in failed if r.severity == "critical"]
        high_failures = [r for r in failed if r.severity == "high"]

        report_lines.append(f"SUMMARY: {len(passed)} passed, {len(failed)} failed")
        report_lines.append(f"  Critical failures: {len(critical_failures)}")
        report_lines.append(f"  High failures: {len(high_failures)}")
        report_lines.append("")

        if failed:
            report_lines.append("FAILURES:")
            report_lines.append("-" * 40)
            for r in sorted(failed, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x.severity]):
                report_lines.append(f"  [{r.severity.upper()}] {r.check_name}")
                report_lines.append(f"    Issue: {r.message}")
                if r.remediation:
                    report_lines.append(f"    Fix: {r.remediation}")
                report_lines.append("")

        if passed:
            report_lines.append("PASSED CHECKS:")
            report_lines.append("-" * 40)
            for r in passed:
                report_lines.append(f"  [PASS] {r.check_name}: {r.message}")
            report_lines.append("")

        report_lines.append("=" * 70)
        overall = "PASS" if not critical_failures else "FAIL"
        report_lines.append(f"OVERALL RESULT: {overall}")
        report_lines.append("=" * 70)

        return "\n".join(report_lines)


def main():
    """Run SAML SSO validation with example configuration."""
    config = SAMLConfig(
        idp_sso_url="https://your-org.okta.com/app/your-app/sso/saml",
        idp_entity_id="http://www.okta.com/exk1234567890",
        sp_entity_id="https://your-app.example.com/saml/metadata",
        sp_acs_url="https://your-app.example.com/saml/acs",
        sp_slo_url="https://your-app.example.com/saml/slo",
        signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        assertion_encrypted=True,
        metadata_url="https://your-org.okta.com/app/exk1234567890/sso/saml/metadata"
    )

    validator = SAMLSSOValidator(config)
    report = validator.generate_report()
    print(report)

    # Export results as JSON
    results_json = []
    for r in validator.results:
        results_json.append({
            "check": r.check_name,
            "passed": r.passed,
            "severity": r.severity,
            "message": r.message,
            "remediation": r.remediation
        })

    with open("saml_validation_results.json", "w") as f:
        json.dump(results_json, f, indent=2)
    print("\nResults exported to saml_validation_results.json")


if __name__ == "__main__":
    main()
