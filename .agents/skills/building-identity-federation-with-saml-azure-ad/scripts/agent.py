#!/usr/bin/env python3
"""SAML Azure AD Federation Agent - Configures and validates SAML SSO with Azure AD."""

import json
import logging
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def fetch_federation_metadata(tenant_id):
    """Fetch Azure AD SAML federation metadata."""
    url = f"https://login.microsoftonline.com/{tenant_id}/federationmetadata/2007-06/federationmetadata.xml"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    logger.info("Fetched federation metadata for tenant %s", tenant_id)
    return resp.text


def parse_metadata(xml_text):
    """Parse SAML federation metadata XML."""
    ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
    root = ET.fromstring(xml_text)
    idp_desc = root.find(".//md:IDPSSODescriptor", ns)
    sso_services = []
    if idp_desc is not None:
        for sso in idp_desc.findall("md:SingleSignOnService", ns):
            sso_services.append({"binding": sso.get("Binding"), "location": sso.get("Location")})
    certs = []
    for cert_elem in root.findall(".//ds:X509Certificate", ns):
        if cert_elem.text:
            certs.append(cert_elem.text.strip()[:100] + "...")
    entity_id = root.get("entityID", "")
    return {"entity_id": entity_id, "sso_services": sso_services, "certificates": certs}


def generate_sp_metadata(entity_id, acs_url, slo_url=None):
    """Generate Service Provider SAML metadata."""
    metadata = {
        "entityID": entity_id,
        "assertionConsumerService": {"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "location": acs_url},
        "nameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }
    if slo_url:
        metadata["singleLogoutService"] = {"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "location": slo_url}
    return metadata


def validate_configuration(idp_metadata, sp_config):
    """Validate SAML federation configuration."""
    findings = []
    if not idp_metadata.get("sso_services"):
        findings.append({"issue": "No SSO services in IdP metadata", "severity": "critical"})
    if not idp_metadata.get("certificates"):
        findings.append({"issue": "No signing certificates in metadata", "severity": "critical"})
    if not sp_config.get("assertionConsumerService", {}).get("location", "").startswith("https://"):
        findings.append({"issue": "ACS URL not using HTTPS", "severity": "high"})
    http_redirect = any("HTTP-Redirect" in s.get("binding", "") for s in idp_metadata.get("sso_services", []))
    http_post = any("HTTP-POST" in s.get("binding", "") for s in idp_metadata.get("sso_services", []))
    if not http_post:
        findings.append({"issue": "HTTP-POST binding not available", "severity": "medium"})
    return {"valid": len([f for f in findings if f["severity"] == "critical"]) == 0, "findings": findings}


def generate_report(idp_metadata, sp_config, validation):
    """Generate SAML federation report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "idp_metadata": idp_metadata,
        "sp_configuration": sp_config,
        "validation": validation,
    }
    status = "VALID" if validation["valid"] else "INVALID"
    print(f"SAML REPORT: {status}, {len(validation['findings'])} findings")
    return report


def main():
    parser = argparse.ArgumentParser(description="SAML Azure AD Federation Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--sp-entity-id", required=True, help="Service Provider entity ID")
    parser.add_argument("--acs-url", required=True, help="Assertion Consumer Service URL")
    parser.add_argument("--slo-url", help="Single Logout URL")
    parser.add_argument("--output", default="saml_report.json")
    args = parser.parse_args()

    xml_text = fetch_federation_metadata(args.tenant_id)
    idp_metadata = parse_metadata(xml_text)
    sp_config = generate_sp_metadata(args.sp_entity_id, args.acs_url, args.slo_url)
    validation = validate_configuration(idp_metadata, sp_config)

    report = generate_report(idp_metadata, sp_config, validation)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
