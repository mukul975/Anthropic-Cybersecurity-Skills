# Workflows - Certificate Authority with OpenSSL

## Workflow 1: Build Two-Tier CA Hierarchy

```
[Generate Root CA Key] (RSA 4096 / ECDSA P-384)
      |
[Create Root CA Self-Signed Certificate]
(validity: 20 years, basicConstraints: CA:TRUE)
      |
[Store Root CA Key Offline]
      |
[Generate Intermediate CA Key]
      |
[Create Intermediate CA CSR]
      |
[Sign Intermediate CSR with Root CA]
(pathLenConstraint: 0, keyUsage: keyCertSign, cRLSign)
      |
[Create CA Chain Bundle]
(intermediate.crt + root.crt)
```

## Workflow 2: Issue End-Entity Certificate

```
[Applicant Generates Key + CSR]
      |
[Submit CSR to Intermediate CA]
      |
[Validate CSR]
(check subject, SAN, key strength)
      |
[Sign with Intermediate CA Key]
(basicConstraints: CA:FALSE)
(extendedKeyUsage: serverAuth / clientAuth)
      |
[Issue Certificate]
      |
[Record in Certificate Database]
```

## Workflow 3: Certificate Revocation

```
[Revocation Request]
      |
[Verify Authorization]
      |
[Revoke Certificate]
(record serial number + reason + date)
      |
[Generate Updated CRL]
(sign with CA key, set nextUpdate)
      |
[Publish CRL to Distribution Point]
      |
[Update OCSP Responder Database]
```

## Workflow 4: OpenSSL CA Commands

```bash
# 1. Create CA directory structure
mkdir -p ca/{certs,crl,newcerts,private}
touch ca/index.txt
echo 1000 > ca/serial
echo 1000 > ca/crlnumber

# 2. Generate Root CA
openssl genrsa -aes256 -out ca/private/ca.key 4096
openssl req -config ca/openssl.cnf -key ca/private/ca.key \
    -new -x509 -days 7300 -sha256 -extensions v3_ca -out ca/certs/ca.crt

# 3. Generate Intermediate CA
openssl genrsa -aes256 -out intermediate/private/intermediate.key 4096
openssl req -config intermediate/openssl.cnf \
    -key intermediate/private/intermediate.key -new -sha256 -out intermediate/csr/intermediate.csr
openssl ca -config ca/openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha256 -in intermediate/csr/intermediate.csr \
    -out intermediate/certs/intermediate.crt

# 4. Issue server certificate
openssl req -config intermediate/openssl.cnf \
    -key server.key -new -sha256 -out server.csr
openssl ca -config intermediate/openssl.cnf -extensions server_cert \
    -days 365 -notext -md sha256 -in server.csr -out server.crt
```
