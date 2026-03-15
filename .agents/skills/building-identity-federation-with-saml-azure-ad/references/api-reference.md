# API Reference: SAML Azure AD Federation

## Federation Metadata URL
```
https://login.microsoftonline.com/{tenant-id}/federationmetadata/2007-06/federationmetadata.xml
```

## SAML 2.0 Endpoints
| Endpoint | URL |
|----------|-----|
| SSO (POST) | `https://login.microsoftonline.com/{tenant}/saml2` |
| SSO (Redirect) | `https://login.microsoftonline.com/{tenant}/saml2` |
| Logout | `https://login.microsoftonline.com/{tenant}/saml2` |

## SP Metadata Required Fields
| Field | Description |
|-------|-------------|
| `entityID` | SP unique identifier |
| `AssertionConsumerService` | ACS URL (POST binding) |
| `NameIDFormat` | emailAddress or persistent |
| `SingleLogoutService` | SLO URL (optional) |

## XML Namespaces
```python
ns = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}
```

## SAML Bindings
| Binding | URI |
|---------|-----|
| HTTP-POST | `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST` |
| HTTP-Redirect | `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect` |
| SOAP | `urn:oasis:names:tc:SAML:2.0:bindings:SOAP` |

## Azure AD Graph API (App Registration)
```
POST https://graph.microsoft.com/v1.0/servicePrincipals
Authorization: Bearer TOKEN
{
  "appId": "app-id",
  "preferredSingleSignOnMode": "saml",
  "loginUrl": "https://app.example.com/login"
}
```

## Validation Checks
| Check | Severity |
|-------|----------|
| HTTPS on ACS URL | High |
| Certificate present | Critical |
| HTTP-POST binding available | Medium |
| NameID format configured | Medium |
