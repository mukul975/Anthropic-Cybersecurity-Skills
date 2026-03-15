# Standards Reference: Android Intent Vulnerabilities

## OWASP Mobile Top 10 2024
| ID | Risk | Intent Relevance |
|----|------|-----------------|
| M4 | Insufficient Input/Output Validation | Intent parameter injection |
| M8 | Security Misconfiguration | Exported components without permission guards |

## OWASP MASVS v2.0 - MASVS-PLATFORM
| Control | Test |
|---------|------|
| MASVS-PLATFORM-1 | Verify exported components require appropriate permissions |
| MASVS-PLATFORM-2 | Verify intent data is validated before processing |

## CWE Mappings
| CWE | Title | Vector |
|-----|-------|--------|
| CWE-926 | Improper Export of Android Application Components | Exported without permission |
| CWE-927 | Use of Implicit Intent for Sensitive Communication | Sensitive data in implicit intents |
| CWE-925 | Improper Verification of Intent by Broadcast Receiver | Missing sender verification |
| CWE-89 | SQL Injection | Content provider query injection |
| CWE-22 | Path Traversal | Content provider path traversal |
