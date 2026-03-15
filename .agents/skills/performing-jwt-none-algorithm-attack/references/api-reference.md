# API Reference — Performing JWT None Algorithm Attack

## Libraries Used
- **base64**: Base64url encoding/decoding for JWT components
- **hmac / hashlib**: HMAC-SHA256 signing for algorithm confusion attacks
- **json**: JWT header/payload serialization
- **requests** (optional): Test forged tokens against live endpoints

## CLI Interface
```
python agent.py decode --token <jwt_string>
python agent.py forge --token <jwt_string> [--claims '{"role":"admin"}']
python agent.py confuse --token <jwt_string> [--pubkey public.pem]
python agent.py test --url <api_endpoint> --token <original_jwt>
```

## Core Functions

### `decode_jwt(token)` — Decode JWT without verification
Returns header, payload, and vulnerability checks: alg=none, no expiry, expired, no issuer.

### `forge_none_token(token, modify_claims)` — Create alg=none variants
Generates 6 variants: `none`, `None`, `NONE`, `nOnE`, empty signature, no trailing dot.

### `test_alg_confusion(token, public_key_file)` — Algorithm confusion attack
Tests RS256-to-HS256 downgrade using RSA public key as HMAC secret.

### `test_jwt_endpoint(url, original_token, forged_tokens)` — Validate against API
Sends forged tokens to target endpoint. Reports CRITICAL if any variant accepted.

## JWT None Variants Tested
| Variant | Algorithm Header |
|---------|-----------------|
| alg_none | `"alg": "none"` |
| alg_None | `"alg": "None"` |
| alg_NONE | `"alg": "NONE"` |
| alg_nOnE | `"alg": "nOnE"` |
| empty_sig | No signature segment |

## Severity Classification
- **CRITICAL**: Any none-algorithm token accepted by server
- **INFO**: All forged tokens rejected

## Dependencies
```
pip install requests  # optional, for endpoint testing
```
