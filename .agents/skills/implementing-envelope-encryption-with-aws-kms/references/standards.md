# Standards and References - Envelope Encryption with AWS KMS

## AWS Documentation

### AWS KMS Developer Guide
- **URL**: https://docs.aws.amazon.com/kms/latest/developerguide/
- **Envelope Encryption**: https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping

### AWS KMS API Reference
- **GenerateDataKey**: https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html
- **Decrypt**: https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
- **ReEncrypt**: https://docs.aws.amazon.com/kms/latest/APIReference/API_ReEncrypt.html

### AWS Encryption SDK
- **URL**: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/
- **Python**: https://aws-encryption-sdk-python.readthedocs.io/

## Cryptographic Standards

### NIST SP 800-57 Part 1 - Key Management
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **Relevance**: Key hierarchy and key wrapping concepts

### NIST SP 800-38F - Key Wrap
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-38f/final
- **Description**: AES Key Wrap specification used by KMS internally

### FIPS 140-2 Level 2 (KMS HSMs)
- **Description**: KMS HSMs are validated at FIPS 140-2 Level 2 (Level 3 for CloudHSM)

## Compliance Frameworks

### PCI DSS v4.0 Requirement 3
- Key management with separation of DEK and KEK
- KMS satisfies key management requirements

### SOC 2 Type II
- AWS KMS is SOC 2 compliant
- Encryption controls map to CC6.1 (logical access controls)

### HIPAA
- KMS encryption satisfies encryption requirements for ePHI
- BAA required with AWS

## Python Libraries

### boto3 (AWS SDK for Python)
- **URL**: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html
- **PyPI**: https://pypi.org/project/boto3/

### aws-encryption-sdk
- **URL**: https://pypi.org/project/aws-encryption-sdk/
- **Description**: High-level envelope encryption with caching
