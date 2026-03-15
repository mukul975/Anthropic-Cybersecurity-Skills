#!/usr/bin/env python3
"""
OAuth 2.0 Authorization Flow Security Auditor

Validates OAuth 2.0 configurations, tests PKCE implementation,
checks token security, and audits scope assignments for compliance
with OAuth 2.1 and RFC 9700 best practices.
"""

import hashlib
import base64
import secrets
import json
import time
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class OAuthConfig:
    """OAuth 2.0 configuration to audit."""
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    issuer: str = ""
    client_id: str = ""
    redirect_uris: List[str] = field(default_factory=list)
    scopes_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    response_types_supported: List[str] = field(default_factory=list)
    pkce_required: bool = True
    token_endpoint_auth_methods: List[str] = field(default_factory=list)


@dataclass
class AuditFinding:
    """Individual audit finding."""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: str = ""
    reference: str = ""


class PKCEHelper:
    """PKCE code verifier and challenge generation."""

    @staticmethod
    def generate_code_verifier(length: int = 128) -> str:
        """Generate a cryptographically random code verifier (43-128 chars)."""
        if length < 43 or length > 128:
            raise ValueError("Code verifier length must be between 43 and 128")
        unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        return ''.join(secrets.choice(unreserved) for _ in range(length))

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Compute S256 code challenge from code verifier."""
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    @staticmethod
    def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
        """Verify PKCE code_verifier matches code_challenge."""
        computed = PKCEHelper.generate_code_challenge(code_verifier)
        return secrets.compare_digest(computed, code_challenge)

    @staticmethod
    def generate_state() -> str:
        """Generate a cryptographically random state parameter."""
        return secrets.token_urlsafe(32)


class OAuth2Auditor:
    """Audits OAuth 2.0 configurations against security best practices."""

    DEPRECATED_GRANTS = ["implicit", "password"]
    SECURE_AUTH_METHODS = [
        "private_key_jwt",
        "tls_client_auth",
        "self_signed_tls_client_auth"
    ]

    def __init__(self, config: OAuthConfig):
        self.config = config
        self.findings: List[AuditFinding] = []

    def audit_all(self) -> List[AuditFinding]:
        """Run all OAuth 2.0 security audits."""
        self.findings = []
        self._audit_grant_types()
        self._audit_pkce_requirement()
        self._audit_redirect_uris()
        self._audit_scopes()
        self._audit_endpoints_https()
        self._audit_token_endpoint_auth()
        self._audit_response_types()
        self._audit_revocation_endpoint()
        self._audit_jwks_endpoint()
        self._audit_discovery_endpoint()
        return self.findings

    def _audit_grant_types(self):
        """Check for deprecated or insecure grant types."""
        for grant in self.config.grant_types_supported:
            if grant in self.DEPRECATED_GRANTS:
                self.findings.append(AuditFinding(
                    category="Grant Types",
                    severity="critical",
                    title=f"Deprecated grant type: {grant}",
                    description=f"The '{grant}' grant type is removed in OAuth 2.1 and is insecure.",
                    recommendation=f"Remove '{grant}' grant type. Use authorization_code with PKCE instead.",
                    reference="RFC 9700 Section 2.1"
                ))

        if "authorization_code" not in self.config.grant_types_supported:
            self.findings.append(AuditFinding(
                category="Grant Types",
                severity="high",
                title="Authorization Code grant not supported",
                description="The most secure interactive grant type is not enabled.",
                recommendation="Enable authorization_code grant type with PKCE.",
                reference="OAuth 2.1 Draft"
            ))

        if "refresh_token" not in self.config.grant_types_supported:
            self.findings.append(AuditFinding(
                category="Grant Types",
                severity="medium",
                title="Refresh token grant not supported",
                description="Without refresh tokens, users must re-authenticate more frequently or access tokens must have longer lifetimes.",
                recommendation="Enable refresh_token grant with token rotation.",
                reference="RFC 6749 Section 6"
            ))

        if not any(g in self.DEPRECATED_GRANTS for g in self.config.grant_types_supported):
            self.findings.append(AuditFinding(
                category="Grant Types",
                severity="info",
                title="No deprecated grant types detected",
                description="All configured grant types are aligned with OAuth 2.1 requirements."
            ))

    def _audit_pkce_requirement(self):
        """Check if PKCE is required for authorization code flow."""
        if "authorization_code" in self.config.grant_types_supported:
            if self.config.pkce_required:
                self.findings.append(AuditFinding(
                    category="PKCE",
                    severity="info",
                    title="PKCE is required for authorization code flow",
                    description="PKCE enforcement is correctly enabled, preventing code interception attacks."
                ))
            else:
                self.findings.append(AuditFinding(
                    category="PKCE",
                    severity="critical",
                    title="PKCE is not required",
                    description="Authorization code flow without PKCE is vulnerable to code interception attacks.",
                    recommendation="Enforce PKCE (code_challenge_method=S256) for all authorization code requests.",
                    reference="RFC 7636, OAuth 2.1 Draft"
                ))

    def _audit_redirect_uris(self):
        """Check redirect URI security."""
        for uri in self.config.redirect_uris:
            if '*' in uri:
                self.findings.append(AuditFinding(
                    category="Redirect URIs",
                    severity="critical",
                    title=f"Wildcard redirect URI: {uri}",
                    description="Wildcard redirect URIs enable open redirect attacks and token theft.",
                    recommendation="Use exact redirect URI matching. Register each URI explicitly.",
                    reference="RFC 9700 Section 4.1"
                ))
            elif uri.startswith("http://") and "localhost" not in uri and "127.0.0.1" not in uri:
                self.findings.append(AuditFinding(
                    category="Redirect URIs",
                    severity="high",
                    title=f"Non-HTTPS redirect URI: {uri}",
                    description="HTTP redirect URIs expose authorization codes in transit.",
                    recommendation="Use HTTPS for all production redirect URIs.",
                    reference="RFC 6749 Section 3.1.2.1"
                ))
            elif uri.startswith("http://localhost") or uri.startswith("http://127.0.0.1"):
                self.findings.append(AuditFinding(
                    category="Redirect URIs",
                    severity="low",
                    title=f"Localhost redirect URI: {uri}",
                    description="Localhost redirect URI detected. Acceptable for native apps per RFC 8252.",
                    reference="RFC 8252 Section 7.3"
                ))

        if not self.config.redirect_uris:
            self.findings.append(AuditFinding(
                category="Redirect URIs",
                severity="medium",
                title="No redirect URIs configured for audit",
                description="Could not audit redirect URIs - none provided in configuration."
            ))

    def _audit_scopes(self):
        """Audit scope configuration for least privilege."""
        overly_broad = ["*", "all", "admin", "root", "superuser"]
        for scope in self.config.scopes_supported:
            if scope.lower() in overly_broad:
                self.findings.append(AuditFinding(
                    category="Scopes",
                    severity="high",
                    title=f"Overly broad scope: {scope}",
                    description="This scope grants excessive permissions violating least privilege.",
                    recommendation="Replace with granular scopes (e.g., read:users, write:orders).",
                    reference="NIST SP 800-53 AC-6"
                ))

        if self.config.scopes_supported:
            granular_pattern = any(':' in s or '.' in s for s in self.config.scopes_supported)
            if not granular_pattern:
                self.findings.append(AuditFinding(
                    category="Scopes",
                    severity="medium",
                    title="Scopes may lack granularity",
                    description="Scopes do not follow resource:action pattern (e.g., read:users).",
                    recommendation="Design scopes using resource:action notation for fine-grained access control."
                ))

    def _audit_endpoints_https(self):
        """Verify all OAuth endpoints use HTTPS."""
        endpoints = {
            "Authorization": self.config.authorization_endpoint,
            "Token": self.config.token_endpoint,
            "Revocation": self.config.revocation_endpoint,
            "UserInfo": self.config.userinfo_endpoint,
            "JWKS": self.config.jwks_uri,
        }
        for name, url in endpoints.items():
            if not url:
                continue
            if not url.startswith("https://"):
                self.findings.append(AuditFinding(
                    category="Transport Security",
                    severity="critical",
                    title=f"{name} endpoint not using HTTPS",
                    description=f"{name} endpoint ({url}) is not secured with TLS.",
                    recommendation=f"Configure {name} endpoint to use HTTPS.",
                    reference="RFC 6749 Section 3.1"
                ))

    def _audit_token_endpoint_auth(self):
        """Check token endpoint authentication methods."""
        if not self.config.token_endpoint_auth_methods:
            return

        if "client_secret_post" in self.config.token_endpoint_auth_methods and \
           "client_secret_basic" in self.config.token_endpoint_auth_methods:
            self.findings.append(AuditFinding(
                category="Client Authentication",
                severity="medium",
                title="Basic/POST client authentication supported",
                description="client_secret_basic and client_secret_post transmit secrets in requests.",
                recommendation="Prefer private_key_jwt or tls_client_auth for higher assurance.",
                reference="RFC 9700"
            ))

        has_secure = any(m in self.SECURE_AUTH_METHODS for m in self.config.token_endpoint_auth_methods)
        if has_secure:
            self.findings.append(AuditFinding(
                category="Client Authentication",
                severity="info",
                title="Strong client authentication methods available",
                description="Server supports certificate-based or JWT-based client authentication."
            ))

        if "none" in self.config.token_endpoint_auth_methods:
            self.findings.append(AuditFinding(
                category="Client Authentication",
                severity="high",
                title="Unauthenticated token endpoint access allowed",
                description="Token endpoint accepts requests without client authentication.",
                recommendation="Require PKCE for public clients and client authentication for confidential clients."
            ))

    def _audit_response_types(self):
        """Check for insecure response types."""
        insecure_types = ["token", "id_token"]
        for rt in self.config.response_types_supported:
            if rt in insecure_types:
                self.findings.append(AuditFinding(
                    category="Response Types",
                    severity="high",
                    title=f"Implicit response type enabled: {rt}",
                    description=f"Response type '{rt}' exposes tokens in browser URL/history.",
                    recommendation="Use 'code' response type with PKCE instead.",
                    reference="OAuth 2.1 Draft, RFC 9700"
                ))

    def _audit_revocation_endpoint(self):
        """Check if token revocation endpoint is configured."""
        if not self.config.revocation_endpoint:
            self.findings.append(AuditFinding(
                category="Token Revocation",
                severity="high",
                title="No token revocation endpoint configured",
                description="Without revocation, compromised tokens cannot be invalidated before expiry.",
                recommendation="Implement RFC 7009 token revocation endpoint.",
                reference="RFC 7009"
            ))

    def _audit_jwks_endpoint(self):
        """Check JWKS endpoint availability for token verification."""
        if not self.config.jwks_uri:
            self.findings.append(AuditFinding(
                category="Token Verification",
                severity="medium",
                title="No JWKS URI configured",
                description="Resource servers need JWKS endpoint to verify JWT signatures.",
                recommendation="Publish JWKS endpoint for token signature verification."
            ))

    def _audit_discovery_endpoint(self):
        """Check OpenID Connect Discovery metadata."""
        if not self.config.issuer:
            return

        discovery_url = f"{self.config.issuer.rstrip('/')}/.well-known/openid-configuration"
        try:
            req = urllib.request.Request(
                discovery_url,
                headers={'User-Agent': 'OAuth2-Auditor/1.0'}
            )
            ctx = ssl.create_default_context()
            response = urllib.request.urlopen(req, context=ctx, timeout=10)

            if response.status == 200:
                metadata = json.loads(response.read().decode('utf-8'))
                self.findings.append(AuditFinding(
                    category="Discovery",
                    severity="info",
                    title="OpenID Connect Discovery endpoint accessible",
                    description=f"Discovery metadata available at {discovery_url}"
                ))

                # Check for PKCE support in discovery
                if "code_challenge_methods_supported" in metadata:
                    methods = metadata["code_challenge_methods_supported"]
                    if "S256" in methods:
                        self.findings.append(AuditFinding(
                            category="PKCE",
                            severity="info",
                            title="S256 PKCE method supported",
                            description="Server advertises S256 code challenge method support."
                        ))
                    if "plain" in methods:
                        self.findings.append(AuditFinding(
                            category="PKCE",
                            severity="high",
                            title="Plain PKCE method supported",
                            description="'plain' code challenge method does not provide security.",
                            recommendation="Require S256 only. Disable plain method.",
                            reference="RFC 7636 Section 4.2"
                        ))
        except Exception as e:
            self.findings.append(AuditFinding(
                category="Discovery",
                severity="low",
                title="Cannot reach discovery endpoint",
                description=f"Error accessing {discovery_url}: {str(e)}"
            ))

    def generate_report(self) -> str:
        """Generate audit report."""
        if not self.findings:
            self.audit_all()

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

        lines = [
            "=" * 70,
            "OAUTH 2.0 SECURITY AUDIT REPORT",
            "=" * 70,
            f"Issuer: {self.config.issuer or 'N/A'}",
            f"Authorization Endpoint: {self.config.authorization_endpoint}",
            f"Token Endpoint: {self.config.token_endpoint}",
            f"Grant Types: {', '.join(self.config.grant_types_supported)}",
            f"PKCE Required: {self.config.pkce_required}",
            "-" * 70,
            ""
        ]

        by_severity = {}
        for f in sorted_findings:
            by_severity.setdefault(f.severity, []).append(f)

        total = len(self.findings)
        critical = len(by_severity.get("critical", []))
        high = len(by_severity.get("high", []))

        lines.append(f"TOTAL FINDINGS: {total}")
        lines.append(f"  Critical: {critical} | High: {high} | Medium: {len(by_severity.get('medium', []))} | Low: {len(by_severity.get('low', []))} | Info: {len(by_severity.get('info', []))}")
        lines.append("")

        for f in sorted_findings:
            icon = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]", "low": "[~]", "info": "[i]"}.get(f.severity, "[?]")
            lines.append(f"{icon} [{f.severity.upper()}] {f.title}")
            lines.append(f"    Category: {f.category}")
            lines.append(f"    {f.description}")
            if f.recommendation:
                lines.append(f"    Recommendation: {f.recommendation}")
            if f.reference:
                lines.append(f"    Reference: {f.reference}")
            lines.append("")

        overall = "FAIL" if critical > 0 else "NEEDS IMPROVEMENT" if high > 0 else "PASS"
        lines.append("=" * 70)
        lines.append(f"OVERALL: {overall}")
        lines.append("=" * 70)

        return "\n".join(lines)


def main():
    """Run OAuth 2.0 security audit with example configuration."""
    config = OAuthConfig(
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/oauth/token",
        revocation_endpoint="https://auth.example.com/oauth/revoke",
        userinfo_endpoint="https://auth.example.com/userinfo",
        jwks_uri="https://auth.example.com/.well-known/jwks.json",
        issuer="https://auth.example.com",
        client_id="my-app-client",
        redirect_uris=[
            "https://app.example.com/callback",
            "http://localhost:3000/callback"
        ],
        scopes_supported=["openid", "profile", "email", "read:users", "write:users"],
        grant_types_supported=["authorization_code", "refresh_token", "client_credentials"],
        response_types_supported=["code"],
        pkce_required=True,
        token_endpoint_auth_methods=["client_secret_basic", "private_key_jwt"]
    )

    auditor = OAuth2Auditor(config)
    report = auditor.generate_report()
    print(report)

    # Demo PKCE generation
    print("\n--- PKCE Demo ---")
    verifier = PKCEHelper.generate_code_verifier(128)
    challenge = PKCEHelper.generate_code_challenge(verifier)
    state = PKCEHelper.generate_state()
    print(f"Code Verifier: {verifier[:40]}...")
    print(f"Code Challenge (S256): {challenge}")
    print(f"State: {state}")
    print(f"Verification: {PKCEHelper.verify_pkce(verifier, challenge)}")


if __name__ == "__main__":
    main()
