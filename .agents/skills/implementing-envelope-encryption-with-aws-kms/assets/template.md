# Envelope Encryption with AWS KMS Template

## Prerequisites Checklist

- [ ] AWS account with KMS access
- [ ] IAM policy allows kms:GenerateDataKey, kms:Decrypt, kms:ReEncrypt
- [ ] KMS Customer Managed Key (CMK) created
- [ ] CloudTrail logging enabled for KMS events
- [ ] boto3 and cryptography Python libraries installed

## IAM Policy Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
    }
  ]
}
```

## KMS Key Policy Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyAdministration",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/KeyAdmin"},
      "Action": [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
        "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
        "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowKeyUsage",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/AppRole"},
      "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:ReEncrypt*"],
      "Resource": "*"
    }
  ]
}
```

## Quick Reference

```python
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

kms = boto3.client('kms')

# Encrypt
resp = kms.generate_data_key(KeyId='alias/my-key', KeySpec='AES_256')
plaintext_key = resp['Plaintext']
encrypted_key = resp['CiphertextBlob']

nonce = os.urandom(12)
ciphertext = AESGCM(plaintext_key).encrypt(nonce, data, None)
# Store: encrypted_key + nonce + ciphertext

# Decrypt
resp = kms.decrypt(CiphertextBlob=encrypted_key)
plaintext_key = resp['Plaintext']
data = AESGCM(plaintext_key).decrypt(nonce, ciphertext, None)
```

## Cost Estimation

| Operation | Price | Notes |
|-----------|-------|-------|
| KMS API requests | $0.03 per 10,000 | GenerateDataKey, Decrypt |
| CMK storage | $1.00 per month | Per customer managed key |
| Key rotation | Free | Automatic annual rotation |
