# API Reference: Implementing SAML SSO with Okta

## Okta Admin API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/apps` | GET | List applications (filter by SAML) |
| `/api/v1/apps/{id}/sso/saml/metadata` | GET | Retrieve SAML metadata XML |
| `/api/v1/apps/{id}/users` | GET | List user assignments |
| `/api/v1/apps/{id}/groups` | GET | List group assignments |
| `/api/v1/policies?type=OKTA_SIGN_ON` | GET | Check MFA policies |

## SAML Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| SHA-256 signature | High | SignatureMethod must not use SHA-1 |
| Assertion encryption | Medium | Encrypt assertions in transit |
| AudienceRestriction | High | Must limit assertion audience |
| Certificate expiry | Critical | Monitor signing cert expiration |
| SingleLogoutService | Medium | SLO endpoint should be configured |
| MFA enforcement | High | Require MFA for SAML authentication |

## SAML XML Namespaces

| Prefix | URI |
|--------|-----|
| md | `urn:oasis:names:tc:SAML:2.0:metadata` |
| ds | `http://www.w3.org/2000/09/xmldsig#` |
| saml | `urn:oasis:names:tc:SAML:2.0:assertion` |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Okta API communication |
| `xml.etree.ElementTree` | stdlib | SAML metadata parsing |
| `ssl` | stdlib | Certificate expiry checking |

## References

- Okta SAML Docs: https://developer.okta.com/docs/concepts/saml/
- Okta API: https://developer.okta.com/docs/reference/api/apps/
- OWASP SAML Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
