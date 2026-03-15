# Standards and References - HSM for Key Storage

## Primary Standards

### PKCS#11 v3.0 (Cryptoki)
- **URL**: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
- **Description**: Standard API for cryptographic token interface

### FIPS 140-2 / FIPS 140-3
- **URL**: https://csrc.nist.gov/publications/detail/fips/140/3/final
- **Description**: Security requirements for cryptographic modules
- **CMVP**: https://csrc.nist.gov/projects/cryptographic-module-validation-program

### NIST SP 800-57 Part 1 Rev. 5
- **URL**: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **Description**: Key management recommendations (HSM storage for high-value keys)

## HSM Products

### SoftHSM2 (Development/Testing)
- **URL**: https://www.opendnssec.org/softhsm/
- **GitHub**: https://github.com/opendnssec/SoftHSMv2
- **Description**: Software-only PKCS#11 implementation for testing

### AWS CloudHSM
- **URL**: https://docs.aws.amazon.com/cloudhsm/
- **FIPS**: 140-2 Level 3
- **PKCS#11**: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html

### Azure Dedicated HSM
- **URL**: https://docs.microsoft.com/en-us/azure/dedicated-hsm/
- **FIPS**: 140-2 Level 3 (Thales Luna)

### Thales Luna HSM
- **URL**: https://cpl.thalesgroup.com/encryption/hardware-security-modules
- **FIPS**: 140-2 Level 3

## Python Libraries

### python-pkcs11
- **URL**: https://python-pkcs11.readthedocs.io/
- **PyPI**: https://pypi.org/project/python-pkcs11/

### PyKCS11
- **URL**: https://github.com/LudovicRousseau/PyKCS11
- **PyPI**: https://pypi.org/project/PyKCS11/
