# Standards Reference: Certificate Pinning Bypass

## OWASP Mobile Top 10 2024
| ID | Risk | Relevance |
|----|------|-----------|
| M5 | Insecure Communication | Pinning assessment as part of network security |
| M7 | Insufficient Binary Protections | Pinning as binary-level protection |

## OWASP MASVS v2.0
| Control | Description |
|---------|-------------|
| MASVS-NETWORK-1 | App uses TLS for all network communication |
| MASVS-NETWORK-2 | App performs certificate pinning for critical connections |
| MASVS-RESILIENCE-1 | App detects and responds to running in instrumented environment |

## CWE Mappings
| CWE | Title |
|-----|-------|
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
