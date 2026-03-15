---
name: performing-ssl-tls-inspection-configuration
description: Configure SSL/TLS inspection on network security devices to decrypt, inspect, and re-encrypt HTTPS traffic for threat detection while managing certificates, exemptions, and privacy compliance.
domain: cybersecurity
subdomain: network-security
tags: [ssl-inspection, tls-decryption, https-inspection, certificate-management, proxy, man-in-the-middle, network-security, forward-proxy]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing SSL/TLS Inspection Configuration

## Overview

SSL/TLS inspection (also called SSL decryption, HTTPS inspection, or TLS break-and-inspect) intercepts encrypted traffic between clients and servers to inspect the cleartext content for malware, data exfiltration, policy violations, and command-and-control communications. The inspection device acts as a trusted man-in-the-middle, terminating the TLS session from the client, inspecting the plaintext content, and establishing a new TLS session to the destination server. With over 95% of web traffic now encrypted, organizations without TLS inspection have a massive blind spot. This skill covers configuring TLS inspection on next-generation firewalls, deploying trusted CA certificates, managing exemptions for certificate-pinned applications, and ensuring compliance with privacy regulations.

## Prerequisites

- Next-generation firewall or secure web gateway with TLS inspection capability
- Internal Certificate Authority (CA) for signing inspection certificates
- Endpoint certificate management (GPO, MDM, or manual deployment)
- Privacy and legal review for TLS inspection scope
- Understanding of PKI, X.509 certificates, and TLS handshake

## Core Concepts

### SSL/TLS Inspection Modes

| Mode | Direction | Description |
|------|-----------|-------------|
| **SSL Forward Proxy** | Outbound | Intercepts client-to-internet HTTPS connections |
| **SSL Inbound Inspection** | Inbound | Decrypts traffic destined for internal servers |
| **SSH Proxy** | Both | Inspects SSH tunneled traffic |

### Forward Proxy Process

```
Client                  Firewall/Proxy              Web Server
  │                         │                          │
  │──TLS ClientHello──────→│                          │
  │                         │──TLS ClientHello───────→│
  │                         │←─TLS ServerHello────────│
  │                         │  (real server cert)      │
  │                         │                          │
  │                         │  [Validates server cert]  │
  │                         │  [Generates proxy cert   │
  │                         │   signed by internal CA]  │
  │                         │                          │
  │←─TLS ServerHello───────│                          │
  │  (proxy-signed cert)    │                          │
  │                         │                          │
  │──Encrypted data────────→│  [Decrypt, Inspect]      │
  │                         │──Encrypted data────────→│
  │←─Encrypted data─────────│  [Decrypt, Inspect]      │
  │                         │←─Encrypted data─────────│
```

### Certificate Trust Chain

```
Enterprise Root CA
  └── Subordinate CA (SSL Inspection)
        └── Dynamically Generated Server Certificates
             (CN matches requested server)
```

## Implementation Steps

### Step 1: Generate Internal CA for SSL Inspection

```bash
# Create private key for SSL Inspection CA
openssl genrsa -aes256 -out ssl-inspect-ca.key 4096

# Create CA certificate (5 year validity)
openssl req -new -x509 -key ssl-inspect-ca.key \
  -sha256 -days 1825 \
  -out ssl-inspect-ca.crt \
  -subj "/C=US/ST=California/O=Corp Inc/OU=Network Security/CN=Corp SSL Inspection CA" \
  -extensions v3_ca \
  -config <(cat <<EOF
[req]
distinguished_name = req_dn
x509_extensions = v3_ca

[req_dn]

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
)

# Verify certificate
openssl x509 -in ssl-inspect-ca.crt -text -noout
```

### Step 2: Deploy CA Certificate to Endpoints

**Windows (Group Policy):**

```powershell
# Import CA cert to trusted root store via GPO
# Computer Configuration > Policies > Windows Settings >
# Security Settings > Public Key Policies > Trusted Root CAs

# Or deploy via PowerShell
Import-Certificate -FilePath "\\server\share\ssl-inspect-ca.crt" `
  -CertStoreLocation "Cert:\LocalMachine\Root"

# Verify deployment
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
    $_.Subject -like "*SSL Inspection CA*"
}
```

**macOS (MDM profile or manual):**

```bash
# Install via command line
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ssl-inspect-ca.crt
```

**Linux:**

```bash
# Ubuntu/Debian
sudo cp ssl-inspect-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# RHEL/CentOS
sudo cp ssl-inspect-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

### Step 3: Configure Palo Alto SSL Forward Proxy

```
# Import CA certificate to firewall
# Device > Certificate Management > Certificates > Import

# Set as Forward Trust CA
set shared certificate SSL-Inspect-CA forward-trust-certificate yes

# Create Decryption Profile
set profiles decryption Corporate-Decrypt ssl-forward-proxy block-expired-certificate yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy block-untrusted-issuer yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy block-unknown-cert yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy restrict-cert-exts yes
set profiles decryption Corporate-Decrypt ssl-forward-proxy strip-alpn no

# Minimum TLS version
set profiles decryption Corporate-Decrypt ssl-protocol-settings min-version tls1-2
set profiles decryption Corporate-Decrypt ssl-protocol-settings max-version max

# Decryption policy - decrypt outbound HTTPS
set rulebase decryption rules Decrypt-Outbound from Trust to Untrust
set rulebase decryption rules Decrypt-Outbound source any
set rulebase decryption rules Decrypt-Outbound destination any
set rulebase decryption rules Decrypt-Outbound service any
set rulebase decryption rules Decrypt-Outbound action decrypt
set rulebase decryption rules Decrypt-Outbound type ssl-forward-proxy
set rulebase decryption rules Decrypt-Outbound profile Corporate-Decrypt
```

### Step 4: Configure Exemptions

Certain applications and categories must be excluded from TLS inspection:

```
# Exempt certificate-pinned applications
set rulebase decryption rules No-Decrypt-Pinned from Trust to Untrust
set rulebase decryption rules No-Decrypt-Pinned application [ apple-update microsoft-update dropbox-base ]
set rulebase decryption rules No-Decrypt-Pinned action no-decrypt

# Exempt privacy-sensitive categories
set rulebase decryption rules No-Decrypt-Privacy from Trust to Untrust
set rulebase decryption rules No-Decrypt-Privacy category [ health-and-medicine financial-services ]
set rulebase decryption rules No-Decrypt-Privacy action no-decrypt

# Exempt specific high-trust domains
set rulebase decryption rules No-Decrypt-Trusted from Trust to Untrust
set rulebase decryption rules No-Decrypt-Trusted destination [ bank-of-america.com chase.com healthcare.gov ]
set rulebase decryption rules No-Decrypt-Trusted action no-decrypt
```

### Step 5: Configure Inbound Inspection for Internal Servers

```
# Import server certificate and private key
# Device > Certificate Management > Certificates > Import

# Inbound inspection policy
set rulebase decryption rules Inspect-WebServers from Untrust to DMZ
set rulebase decryption rules Inspect-WebServers destination [ 10.0.20.10 10.0.20.11 ]
set rulebase decryption rules Inspect-WebServers service service-https
set rulebase decryption rules Inspect-WebServers action decrypt
set rulebase decryption rules Inspect-WebServers type ssl-inbound-inspection
set rulebase decryption rules Inspect-WebServers profile Corporate-Decrypt
```

### Step 6: Validate SSL Inspection

```bash
# Test from client - verify certificate issuer is internal CA
openssl s_client -connect www.google.com:443 -servername www.google.com 2>/dev/null | \
  openssl x509 -noout -issuer -subject

# Expected output (with inspection active):
# issuer= /C=US/O=Corp Inc/OU=Network Security/CN=Corp SSL Inspection CA
# subject= /CN=www.google.com

# Verify no certificate errors in browser
# Check firewall decryption logs for errors

# Test with curl
curl -v https://www.example.com 2>&1 | grep "issuer"

# Check decryption statistics on firewall
show system setting ssl-decrypt memory
show system setting ssl-decrypt certificate-cache
show counter global filter category ssl
```

## Performance Considerations

| Factor | Impact | Mitigation |
|--------|--------|-----------|
| CPU overhead | 50-80% increase per session | Hardware SSL acceleration, dedicated decrypt appliance |
| Throughput reduction | 40-60% typical | Size decryption hardware for peak encrypted traffic |
| Latency increase | 1-5ms additional | Place inspection close to users |
| TLS 1.3 0-RTT | Cannot inspect 0-RTT data | Block 0-RTT or accept risk |
| Certificate pinning | Inspection fails | Add to exemption list |
| QUIC/HTTP3 | Bypasses traditional proxy | Block QUIC, force HTTP/2 |

## Compliance and Privacy

- **Employee Notice** - Notify users that network traffic is subject to inspection
- **Privacy Exemptions** - Exclude healthcare, financial, and legally privileged traffic
- **Data Handling** - Inspected cleartext must not be logged or stored unnecessarily
- **GDPR Compliance** - Document lawful basis for processing encrypted personal data
- **Certificate Pinning** - Maintain exemption list for applications using HPKP or built-in pins

## Best Practices

- **Start with Logging** - Deploy in detect-only mode first to identify certificate-pinned applications
- **Maintain Exemption List** - Keep a curated list of applications requiring decryption bypass
- **Block QUIC** - Block UDP/443 to force HTTP/2 through TLS inspection
- **Monitor Certificate Errors** - Track decryption errors in firewall logs
- **TLS 1.2 Minimum** - Enforce TLS 1.2 as minimum version; block SSLv3 and TLS 1.0/1.1
- **Key Protection** - Store inspection CA private key in HSM for production environments
- **Regular CA Rotation** - Plan for CA certificate rotation before expiration

## References

- [Palo Alto SSL Decryption](https://docs.paloaltonetworks.com/network-security/decryption)
- [Cisco SSL/TLS Proxy](https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/security/ios-xe-17/security-book-xe/m-ssl-proxy.html)
- [NIST SP 800-52 Rev 2 - TLS Configuration](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [US-CERT Alert on HTTPS Inspection](https://www.cisa.gov/news-events/alerts/2017/03/13/https-interception-weakens-tls-security)
