# HSM Key Storage Configuration Template

## HSM Selection Matrix

| HSM | FIPS Level | Cloud | On-Premise | Cost |
|-----|-----------|-------|-----------|------|
| SoftHSM2 | N/A (dev) | N/A | Yes | Free |
| AWS CloudHSM | 140-2 L3 | Yes | No | ~$1.60/hr |
| Azure Dedicated HSM | 140-2 L3 | Yes | No | ~$5,500/mo |
| Thales Luna | 140-2 L3 | Both | Yes | License |
| YubiHSM 2 | 140-2 L3 | No | Yes | ~$650 |

## PKCS#11 Key Attributes

```
CKA_TOKEN = True          # Persistent storage
CKA_PRIVATE = True        # Requires login
CKA_SENSITIVE = True      # Cannot be revealed in clear
CKA_EXTRACTABLE = False   # Cannot be exported
CKA_MODIFIABLE = False    # Cannot change attributes
CKA_LABEL = "my-key"      # Human-readable label
CKA_ID = <byte_string>    # Unique identifier
```

## Key Ceremony Checklist

- [ ] Prepare air-gapped workstation with HSM
- [ ] Assemble M-of-N key custodians (quorum)
- [ ] Initialize HSM and set SO/User PINs
- [ ] Generate root CA key in HSM (non-extractable)
- [ ] Generate and sign root CA certificate
- [ ] Export root CA certificate (public only)
- [ ] Verify certificate independently
- [ ] Secure HSM in physical vault
- [ ] Document ceremony in audit log
- [ ] Distribute key custodian tokens/smart cards
