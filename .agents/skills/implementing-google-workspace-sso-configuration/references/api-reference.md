# API Reference: Implementing Google Workspace SSO Configuration

## SAML 2.0 Endpoints

| Endpoint | URL |
|----------|-----|
| SP ACS URL | `https://accounts.google.com/samlrp/acs?rpid=RPID` |
| SP Entity ID | `google.com/a/DOMAIN` |
| SP Metadata | `https://accounts.google.com/samlrp/metadata?rpid=RPID` |

## Admin Console Path

```
Admin Console > Security > Authentication > SSO with third-party IdP
```

## SAML Configuration Fields

| Field | Description |
|-------|-------------|
| Sign-in page URL | IdP SSO endpoint (HTTPS required) |
| Sign-out page URL | IdP SLO endpoint |
| Change password URL | IdP password change page |
| Verification certificate | IdP X.509 signing cert (PEM, RSA 2048+) |
| Domain-specific issuer | Use domain in SAML issuer |

## Certificate Validation (Python cryptography)

```python
from cryptography import x509
cert = x509.load_pem_x509_certificate(pem_data)
print(cert.not_valid_after_utc)
print(cert.subject.rfc4514_string())
print(cert.public_key().key_size)
```

## Admin SDK Reports API (Login Activity)

```python
from googleapiclient.discovery import build
service = build("admin", "reports_v1", credentials=creds)
activities = service.activities().list(
    userKey="all", applicationName="login",
    eventName="login_success").execute()
```

## Common IdP Providers

| IdP | SAML SSO URL Pattern |
|-----|---------------------|
| Okta | `https://DOMAIN.okta.com/app/APP_ID/sso/saml` |
| Azure AD | `https://login.microsoftonline.com/TENANT/saml2` |
| ADFS | `https://ADFS_HOST/adfs/ls/` |
| Ping Identity | `https://sso.connect.pingidentity.com/sso/sp/initsso` |

### References

- Google Workspace SSO: https://support.google.com/a/answer/60224
- SAML 2.0 Admin Guide: https://support.google.com/a/answer/6349809
- Admin SDK: https://developers.google.com/admin-sdk/reports/v1/guides/manage-audit-login
