# API Reference: Implementing Identity Verification for Zero Trust

## CISA Zero Trust Maturity Model - Identity Pillar

| Level | Description | Requirements |
|-------|-------------|-------------|
| Traditional | Password-based, static policies | Basic auth |
| Initial | MFA deployed, basic conditional access | MFA for all users |
| Advanced | Phishing-resistant MFA, risk-based | FIDO2, risk signals |
| Optimal | Continuous verification, passwordless | Behavioral analytics |

## Azure AD Conditional Access API

```python
import requests
headers = {"Authorization": "Bearer <token>"}
policies = requests.get(
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    headers=headers).json()
```

## FIDO2/WebAuthn Registration

```javascript
const credential = await navigator.credentials.create({
    publicKey: {
        rp: { name: "Example Corp" },
        user: { id: userId, name: email, displayName: name },
        challenge: serverChallenge,
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required" },
    }
});
```

## Conditional Access Signals

| Signal | Source | Zero Trust Level |
|--------|--------|-----------------|
| Device compliance | MDM/Intune | Initial |
| Location/IP | Network context | Initial |
| User risk | Identity Protection | Advanced |
| Sign-in risk | Real-time analysis | Advanced |
| Session behavior | UEBA | Optimal |

## Okta Authentication Policies API

```bash
curl -X GET "https://DOMAIN.okta.com/api/v1/policies?type=ACCESS_POLICY" \
  -H "Authorization: SSWS <token>"
```

### References

- CISA Zero Trust Maturity Model: https://www.cisa.gov/zero-trust-maturity-model
- NIST SP 800-207: https://csrc.nist.gov/pubs/sp/800/207/final
- FIDO Alliance: https://fidoalliance.org/fido2/
