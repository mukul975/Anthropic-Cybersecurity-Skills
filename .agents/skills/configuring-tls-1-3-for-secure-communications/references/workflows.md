# Workflows - Configuring TLS 1.3

## Workflow 1: TLS 1.3 Handshake (1-RTT)

```
Client                              Server
  |                                    |
  |--- ClientHello ------------------>|
  |    (supported_versions: TLS 1.3)  |
  |    (key_share: x25519)            |
  |    (signature_algorithms)         |
  |    (cipher_suites)                |
  |                                    |
  |<-- ServerHello -------------------|
  |    (selected cipher suite)        |
  |    (key_share: x25519)            |
  |<-- {EncryptedExtensions} ---------|
  |<-- {Certificate} -----------------|
  |<-- {CertificateVerify} -----------|
  |<-- {Finished} --------------------|
  |                                    |
  |--- {Finished} ------------------->|
  |                                    |
  |<== Application Data ==============>|
```

## Workflow 2: nginx TLS 1.3 Configuration

```
1. Check OpenSSL version (>= 1.1.1)
   $ openssl version

2. Generate ECDSA certificate
   $ openssl ecparam -genkey -name prime256v1 -out server.key
   $ openssl req -new -x509 -key server.key -out server.crt -days 365

3. Configure nginx
   Edit /etc/nginx/nginx.conf

4. Test configuration
   $ nginx -t

5. Reload nginx
   $ systemctl reload nginx

6. Verify TLS 1.3
   $ openssl s_client -connect localhost:443 -tls1_3
```

## Workflow 3: TLS Configuration Validation

```
[Server] --> [openssl s_client test]
                  |
          [Check protocol version]
          [Check cipher suite]
          [Check certificate chain]
                  |
          [testssl.sh full scan]
                  |
          [Check for vulnerabilities]
          - BEAST, POODLE, Heartbleed
          - ROBOT, DROWN, FREAK
          - Weak ciphers, expired certs
                  |
          [SSL Labs grade assessment]
          Target: A+ rating
```

## Workflow 4: Certificate Lifecycle

```
[Generate Key Pair]
      |
[Create CSR] --> [Submit to CA]
                       |
               [CA Issues Certificate]
                       |
               [Install Certificate]
                       |
               [Configure OCSP Stapling]
                       |
               [Set Up Auto-Renewal]
               (certbot / ACME)
                       |
               [Monitor Expiration]
```
