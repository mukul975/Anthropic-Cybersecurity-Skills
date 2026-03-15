# Standards and References - Web Application Scanning with Nikto

## Industry Standards
- **OWASP Testing Guide v4.2**: Web application security testing methodology
- **NIST SP 800-115**: Technical Guide to Information Security Testing and Assessment
- **PCI DSS v4.0 Req 6.4**: Address common coding vulnerabilities in development
- **PCI DSS v4.0 Req 11.3.3**: Perform external vulnerability scans via ASV

## Nikto Resources
- Nikto GitHub Repository: https://github.com/sullo/nikto
- Nikto Documentation: https://cirt.net/Nikto2
- Nikto Plugin Database: https://github.com/sullo/nikto/tree/master/plugins
- Nikto Cheat Sheet: https://highon.coffee/blog/nikto-cheat-sheet/

## Complementary Web Scanning Tools
| Tool | Purpose | URL |
|------|---------|-----|
| OWASP ZAP | Application-level scanning | https://www.zaproxy.org/ |
| Nuclei | Template-based scanning | https://github.com/projectdiscovery/nuclei |
| testssl.sh | SSL/TLS assessment | https://testssl.sh/ |
| Wapiti | Web application fuzzer | https://wapiti-scanner.github.io/ |
| WhatWeb | Web technology fingerprinting | https://github.com/urbanadventurer/WhatWeb |

## Nikto Tuning Reference
| Code | Category | Description |
|------|----------|-------------|
| 0 | File Upload | Checks for file upload vulnerabilities |
| 1 | Interesting File | Files commonly seen in server logs |
| 2 | Misconfiguration | Default files and misconfigurations |
| 3 | Information Disclosure | Information leakage through headers/pages |
| 4 | Injection (XSS) | Cross-site scripting and HTML injection |
| 5 | Remote File Retrieval | Inside web root file access |
| 6 | Denial of Service | DoS vulnerability checks |
| 7 | Remote File Retrieval | Server-wide file access |
| 8 | Command Execution | RCE and remote shell vulnerabilities |
| 9 | SQL Injection | SQL injection vulnerability checks |
| a | Authentication Bypass | Authentication bypass techniques |
| b | Software Identification | Server and software version detection |
| c | Remote Source Inclusion | RFI/LFI vulnerability checks |
| d | WebService | Web service specific vulnerabilities |
| e | Administrative Console | Admin interface discovery |
