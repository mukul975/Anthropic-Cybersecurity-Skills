# HSM Key Storage — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| boto3 | `pip install boto3` | AWS CloudHSM and KMS API |
| python-pkcs11 | `pip install python-pkcs11` | PKCS#11 interface for HSM operations |

## Key boto3 CloudHSMv2 Methods

| Method | Description |
|--------|-------------|
| `describe_clusters()` | List CloudHSM clusters |
| `describe_backups()` | List cluster backups |
| `create_cluster(HsmType, SubnetIds)` | Create new cluster |
| `create_hsm(ClusterId, AvailabilityZone)` | Add HSM to cluster |
| `initialize_cluster(ClusterId, SignedCert, TrustAnchor)` | Initialize cluster |

## Key boto3 KMS Methods (Custom Key Store)

| Method | Description |
|--------|-------------|
| `create_custom_key_store()` | Create KMS custom key store backed by CloudHSM |
| `describe_key(KeyId)` | Get key metadata including CustomKeyStoreId |
| `create_key(Origin="AWS_CLOUDHSM", CustomKeyStoreId=)` | Create key in HSM |

## PKCS#11 Operations

| Function | Description |
|----------|-------------|
| `C_Initialize` | Initialize PKCS#11 library |
| `C_OpenSession` | Open session with HSM |
| `C_Login` | Authenticate with HSM PIN |
| `C_GenerateKeyPair` | Generate asymmetric key pair |
| `C_Sign / C_Verify` | Cryptographic signing operations |

## HSM Types

| Type | Use Case |
|------|----------|
| AWS CloudHSM | Cloud-native FIPS 140-2 Level 3 |
| Thales Luna | On-premises enterprise HSM |
| nCipher nShield | High-assurance code signing |

## External References

- [AWS CloudHSM Docs](https://docs.aws.amazon.com/cloudhsm/)
- [boto3 CloudHSMv2](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudhsmv2.html)
- [PKCS#11 Standard](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
