#!/usr/bin/env python3
"""
Azure AD Federation Configuration Auditor

Validates federation configuration between on-premises AD FS and Azure AD,
checks certificate health, and monitors federation authentication events.

Requirements:
    pip install msal requests cryptography
"""

import json
import sys
from datetime import datetime, timezone

try:
    import requests
    import msal
    from cryptography import x509
except ImportError:
    print("[ERROR] Required: pip install msal requests cryptography")
    sys.exit(1)


class FederationAuditor:
    """Audit Azure AD federation configuration and health."""

    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.token = self._get_token(tenant_id, client_id, client_secret)

    def _get_token(self, tenant_id, client_id, client_secret):
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" in result:
            return result["access_token"]
        raise Exception(f"Auth failed: {result.get('error_description')}")

    def _graph_get(self, endpoint):
        headers = {"Authorization": f"Bearer {self.token}"}
        resp = requests.get(
            f"https://graph.microsoft.com/v1.0{endpoint}",
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    def get_domains(self):
        """List all domains and their authentication type."""
        result = self._graph_get("/domains")
        domains = []
        for domain in result.get("value", []):
            domains.append({
                "id": domain["id"],
                "isVerified": domain.get("isVerified", False),
                "authenticationType": domain.get("authenticationType", "Unknown"),
                "isDefault": domain.get("isDefault", False),
                "isRoot": domain.get("isRoot", False),
            })
        return domains

    def get_federation_config(self, domain_id):
        """Get federation configuration for a specific domain."""
        try:
            result = self._graph_get(
                f"/domains/{domain_id}/federationConfiguration"
            )
            configs = result.get("value", [])
            return configs[0] if configs else None
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def validate_adfs_metadata(self, metadata_url):
        """Fetch and validate AD FS federation metadata endpoint."""
        try:
            resp = requests.get(metadata_url, timeout=15)
            resp.raise_for_status()

            from lxml import etree
            root = etree.fromstring(resp.content)
            ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}

            entity_id = root.get("entityID")
            certs = root.findall(
                ".//md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo"
                "/ds:X509Data/ds:X509Certificate",
                {**ns, "ds": "http://www.w3.org/2000/09/xmldsig#"},
            )

            return {
                "reachable": True,
                "entity_id": entity_id,
                "certificate_count": len(certs),
                "metadata_size": len(resp.content),
            }
        except requests.RequestException as e:
            return {"reachable": False, "error": str(e)}
        except Exception as e:
            return {"reachable": True, "parse_error": str(e)}

    def check_certificate_expiry(self, cert_base64):
        """Check federation signing certificate expiration."""
        try:
            import base64
            cert_der = base64.b64decode(cert_base64)
            cert = x509.load_der_x509_certificate(cert_der)
            now = datetime.now(timezone.utc)
            days_left = (cert.not_valid_after_utc - now).days

            return {
                "subject": cert.subject.rfc4514_string(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "days_until_expiry": days_left,
                "is_expired": days_left < 0,
                "needs_renewal": days_left < 30,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_signin_logs(self, federated_domain, top=50):
        """Get recent sign-in logs for federated users."""
        try:
            result = self._graph_get(
                f"/auditLogs/signIns?"
                f"$filter=userPrincipalName endswith '{federated_domain}'"
                f"&$top={top}&$orderby=createdDateTime desc"
            )
            logs = []
            for log in result.get("value", []):
                logs.append({
                    "user": log.get("userPrincipalName"),
                    "createdDateTime": log.get("createdDateTime"),
                    "status": log.get("status", {}).get("errorCode", 0),
                    "statusDetail": log.get("status", {}).get("failureReason", "Success"),
                    "appDisplayName": log.get("appDisplayName"),
                    "authenticationProtocol": log.get("authenticationProtocol"),
                    "ipAddress": log.get("ipAddress"),
                })
            return logs
        except requests.HTTPError:
            return []

    def generate_federation_audit_report(self):
        """Generate comprehensive federation health report."""
        domains = self.get_domains()
        federated_domains = [d for d in domains if d["authenticationType"] == "Federated"]

        report = {
            "report_title": "Azure AD Federation Audit Report",
            "tenant_id": self.tenant_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_domains": len(domains),
            "federated_domains": len(federated_domains),
            "domain_details": [],
            "findings": [],
        }

        for domain in federated_domains:
            domain_id = domain["id"]
            fed_config = self.get_federation_config(domain_id)

            domain_detail = {
                "domain": domain_id,
                "is_verified": domain["isVerified"],
                "federation_config": fed_config is not None,
            }

            if fed_config:
                issuer = fed_config.get("issuerUri", "")
                sign_in_url = fed_config.get("passiveSignInUri", "")
                domain_detail["issuer_uri"] = issuer
                domain_detail["sign_in_url"] = sign_in_url

                signing_cert = fed_config.get("signingCertificate", "")
                if signing_cert:
                    cert_health = self.check_certificate_expiry(signing_cert)
                    domain_detail["certificate_health"] = cert_health

                    if cert_health.get("is_expired"):
                        report["findings"].append({
                            "severity": "Critical",
                            "domain": domain_id,
                            "finding": "Federation signing certificate is EXPIRED",
                            "action": "Immediately rotate certificate in AD FS and update Azure AD",
                        })
                    elif cert_health.get("needs_renewal"):
                        report["findings"].append({
                            "severity": "High",
                            "domain": domain_id,
                            "finding": f"Federation certificate expires in {cert_health['days_until_expiry']} days",
                            "action": "Schedule certificate rotation before expiry",
                        })

            report["domain_details"].append(domain_detail)

        return report


if __name__ == "__main__":
    print("=" * 60)
    print("Azure AD Federation Configuration Auditor")
    print("=" * 60)
    print()
    print("Usage:")
    print("  auditor = FederationAuditor(tenant_id, client_id, secret)")
    print("  report = auditor.generate_federation_audit_report()")
    print("  print(json.dumps(report, indent=2))")
    print()
    print("Required Microsoft Graph permissions:")
    print("  - Domain.Read.All")
    print("  - AuditLog.Read.All")
    print("  - Directory.Read.All")
