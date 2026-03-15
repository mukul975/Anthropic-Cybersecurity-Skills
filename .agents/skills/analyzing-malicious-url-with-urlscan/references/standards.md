# Standards & References: Analyzing Malicious URLs with URLScan

## MITRE ATT&CK References
- **T1566.002**: Phishing: Spearphishing Link
- **T1204.001**: User Execution: Malicious Link
- **T1608.005**: Stage Capabilities: Link Target
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1102**: Web Service (for C2 via web)

## URLScan.io API Reference
| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/scan/` | POST | Submit URL for scanning |
| `/api/v1/result/{uuid}/` | GET | Get scan results |
| `/api/v1/search/?q=` | GET | Search scan database |
| `/api/v1/result/{uuid}/screenshot/` | GET | Get page screenshot |
| `/api/v1/result/{uuid}/dom/` | GET | Get rendered DOM |

### Search Query Syntax
- `domain:example.com` - Search by domain
- `ip:1.2.3.4` - Search by IP
- `server:nginx` - Search by web server
- `filename:login.php` - Search by filename
- `hash:abc123` - Search by resource hash
- `page.domain:example.com AND date:>now-7d` - Combined queries

## Industry Standards
- **NIST SP 800-83**: Guide to Malware Incident Prevention and Handling
- **NIST SP 800-86**: Guide to Integrating Forensic Techniques into Incident Response
- **RFC 3986**: Uniform Resource Identifier (URI) syntax

## URL Classification Indicators
| Indicator | Risk Level | Description |
|---|---|---|
| Domain age < 7 days | Critical | Very recently registered |
| Domain age < 30 days | High | Recently registered |
| Free TLS cert (Let's Encrypt) with brand impersonation | High | Common phishing pattern |
| URL shortener | Medium | Obfuscates destination |
| Credential input form on non-brand domain | Critical | Credential harvesting |
| JavaScript obfuscation | High | Evasion technique |
| Multiple redirects | Medium | Chain obfuscation |
| Data URI scheme | High | Inline content, hard to trace |
