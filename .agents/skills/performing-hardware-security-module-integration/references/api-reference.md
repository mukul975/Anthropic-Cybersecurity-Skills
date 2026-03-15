# API Reference — Performing Hardware Security Module Integration

## Libraries Used
- **python-pkcs11**: Python PKCS#11 wrapper for HSM cryptographic operations
- **json**: JSON serialization for audit reports

## CLI Interface
```
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 slots
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 objects
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 gen-rsa --label mykey --bits 2048
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 gen-ec --label myec
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 sign-verify --key-label mykey
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 mechanisms
python agent.py --lib /usr/lib/softhsm/libsofthsm2.so --token MyToken --pin 1234 full
```

## Core Functions

### `load_library(lib_path)` — Load PKCS#11 shared library
Calls `pkcs11.lib(lib_path)` to initialize the PKCS#11 provider.

### `enumerate_slots(lib)` — List slots and token info
Iterates `lib.get_slots(token_present=True)`. Returns token label, manufacturer,
model, serial, initialization status, and supported mechanism list.

### `list_objects(lib, token_label, pin)` — Inventory stored keys
Opens authenticated session, calls `session.get_objects()`. Returns object class,
label, key type, key length, and object ID.

### `generate_rsa_keypair(lib, token_label, pin, key_label, bits)` — RSA key generation
Calls `session.generate_keypair(KeyType.RSA, bits, store=True, label=key_label)`.

### `generate_ec_keypair(lib, token_label, pin, key_label)` — EC P-256 key generation
Creates domain parameters for secp256r1 via `encode_named_curve_parameters`,
then calls `ecparams.generate_keypair()`.

### `sign_and_verify(lib, token_label, pin, key_label)` — Signing test
Signs with `priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)`.
Verifies with `pub.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)`.

### `query_mechanisms(lib, token_label)` — Algorithm support audit
Enumerates all mechanisms with min/max key sizes from the slot.

### `full_audit(lib, token_label, pin)` — Comprehensive compliance report

## PKCS#11 Object Classes
| Class | Description |
|-------|-------------|
| PUBLIC_KEY | RSA/EC public keys |
| PRIVATE_KEY | RSA/EC private keys (non-extractable) |
| SECRET_KEY | Symmetric keys (AES, DES3) |
| CERTIFICATE | X.509 certificates |

## FIPS 140-2 Required Mechanisms
RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, SHA512_RSA_PKCS,
ECDSA, ECDSA_SHA256, AES_CBC, AES_GCM, SHA256, SHA384, SHA512

## Common PKCS#11 Libraries
| HSM | Library Path |
|-----|-------------|
| SoftHSM2 | `/usr/lib/softhsm/libsofthsm2.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |
| YubiHSM2 | `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so` |
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |

## Dependencies
- `python-pkcs11` >= 0.7.0
- PKCS#11 shared library for target HSM
- Initialized token with user PIN
