# Certificate Authority Configuration Template

## CA Directory Structure

```
pki/
  root-ca/
    private/root-ca.key
    certs/root-ca.crt
    serial.json
    index.json
  intermediate-ca/
    private/intermediate-ca.key
    certs/intermediate-ca.crt
    certs/ca-chain.crt
    certs/issued/
    crl/intermediate.crl
    serial.json
    index.json
```

## OpenSSL Configuration Template (openssl.cnf)

```ini
[ca]
default_ca = CA_default

[CA_default]
dir               = ./ca
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/ca.key
certificate       = $dir/certs/ca.crt
default_md        = sha256
default_days      = 365
policy            = policy_strict

[policy_strict]
countryName       = match
organizationName  = match
commonName        = supplied

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[v3_intermediate_ca]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[server_cert]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
```

## Certificate Issuance Checklist

- [ ] Verify CSR subject and SAN entries
- [ ] Validate key strength (minimum 2048-bit RSA or P-256 ECDSA)
- [ ] Check domain ownership or authorization
- [ ] Set appropriate validity period
- [ ] Include correct extensions (EKU, constraints)
- [ ] Sign with intermediate CA (never root)
- [ ] Record in certificate database
- [ ] Provide full chain to requester
