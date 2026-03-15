# Workflows - HSM for Key Storage

## Workflow 1: SoftHSM2 Initialization

```bash
# Install SoftHSM2
# Ubuntu: apt install softhsm2
# macOS: brew install softhsm

# Initialize a token
softhsm2-util --init-token --slot 0 --label "MyToken" --pin 1234 --so-pin 5678

# List tokens
softhsm2-util --show-slots
```

## Workflow 2: Key Generation via PKCS#11

```
[Connect to HSM]
(open session, login with PIN)
      |
[Generate Key]:
  Symmetric: AES-256 (CKM_AES_KEY_GEN)
  Asymmetric: RSA-4096 (CKM_RSA_PKCS_KEY_PAIR_GEN)
  Asymmetric: EC P-256 (CKM_EC_KEY_PAIR_GEN)
      |
[Set Key Attributes]:
  CKA_EXTRACTABLE = False
  CKA_SENSITIVE = True
  CKA_TOKEN = True (persistent)
  CKA_LABEL = "my-key-001"
      |
[Key Stored in HSM]
(returns handle, not key material)
```

## Workflow 3: Cryptographic Operations

```
[Application Request]
      |
[Open PKCS#11 Session]
      |
[Find Key by Label/ID]
      |
[Perform Operation on HSM]:
  Sign:    C_SignInit + C_Sign
  Verify:  C_VerifyInit + C_Verify
  Encrypt: C_EncryptInit + C_Encrypt
  Decrypt: C_DecryptInit + C_Decrypt
      |
[Return Result to Application]
(key never leaves HSM)
      |
[Close Session]
```

## Workflow 4: HSM Key Ceremony (Root CA)

```
[Prepare Air-Gapped HSM Station]
      |
[Multi-Person Authentication]
(M-of-N key custodians present)
      |
[Generate Root CA Key in HSM]
(CKA_EXTRACTABLE=False)
      |
[Sign Root CA Certificate]
(self-signed, 20-year validity)
      |
[Export Root CA Certificate]
(public certificate only)
      |
[Secure HSM in Safe/Vault]
(offline until next signing ceremony)
```
