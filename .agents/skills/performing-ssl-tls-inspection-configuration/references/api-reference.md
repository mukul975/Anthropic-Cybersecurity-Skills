# API Reference: SSL/TLS Inspection Configuration

## Inspection Validation Commands

| Command | Description |
|---------|-------------|
| `openssl s_client -connect host:443 -servername host` | Check certificate issuer |
| `curl -v https://host 2>&1 \| grep issuer` | Verify inspection via curl |
| `show system setting ssl-decrypt memory` | PAN-OS decryption stats |
| `show counter global filter category ssl` | PAN-OS SSL counters |

## CA Deployment Commands

### Windows (GPO/PowerShell)
| Command | Description |
|---------|-------------|
| `Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\LocalMachine\Root` | Install CA cert |
| `Get-ChildItem Cert:\LocalMachine\Root \| Where Subject -like "*CA*"` | Verify deployment |

### Linux
| Command | Description |
|---------|-------------|
| `cp ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates` | Ubuntu/Debian |
| `cp ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust` | RHEL/CentOS |

### macOS
| Command | Description |
|---------|-------------|
| `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt` | Install CA |

## Palo Alto SSL Decryption Policy

| Setting | Description |
|---------|-------------|
| `ssl-forward-proxy` | Outbound HTTPS inspection |
| `ssl-inbound-inspection` | Inbound to internal servers |
| `block-expired-certificate yes` | Block expired server certs |
| `min-version tls1-2` | Enforce TLS 1.2 minimum |

## Exemption Categories

| Category | Reason |
|----------|--------|
| Certificate-pinned apps | Apple Update, Microsoft Update, Dropbox |
| Healthcare/Financial | HIPAA/PCI privacy requirements |
| Legal privilege | Attorney-client communication |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `ssl` | stdlib | TLS handshake, version testing |
| `socket` | stdlib | TCP connections |
| `subprocess` | stdlib | PowerShell CA verification |

## References

- Palo Alto SSL Decryption: https://docs.paloaltonetworks.com/network-security/decryption
- NIST SP 800-52 Rev 2: https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final
- US-CERT HTTPS Inspection: https://www.cisa.gov/news-events/alerts/2017/03/13/https-interception-weakens-tls-security
