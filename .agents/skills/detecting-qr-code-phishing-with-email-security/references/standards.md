# Standards & References: Detecting QR Code Phishing

## Industry Statistics (2025-2026)
- Quishing incidents grew from 46,000 to 250,000 between Aug-Nov 2025 (Kaspersky)
- 89.3% of QR code phishing targets credential theft
- 12% of January 2026 attacks used ASCII text-based QR codes
- Only 36% of quishing incidents accurately identified by recipients
- 25% year-over-year growth in quishing incidents

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment (QR in PDF/image)
- **T1566.002**: Phishing: Spearphishing Link (QR-encoded URL)
- **T1204.001**: User Execution: Malicious Link (user scans QR)
- **T1598.003**: Phishing for Information: Spearphishing Link

## Quishing Attack Patterns
| Pattern | Description | Detection Difficulty |
|---|---|---|
| Inline QR image | QR code embedded directly in email body | Medium |
| PDF attachment QR | QR code inside attached PDF document | High |
| Split QR code | QR divided into two benign-looking images | Very High |
| ASCII QR code | QR rendered as text characters | Very High |
| Nested QR code | QR within QR with intermediate redirect | High |
| Styled QR code | Artistic QR with logos/colors | Medium |

## Common Quishing Themes
- MFA enrollment/reset requiring QR scan
- Document signing via QR code
- Voicemail notification with QR access
- Package delivery QR confirmation
- IT security update requiring QR authentication
- Shared document access via QR

## Detection Technologies
- Multimodal AI (OCR + deep image + NLP)
- Computer vision QR code detection
- URL reputation analysis for decoded URLs
- Mobile threat defense QR scanning
- Behavioral analysis of image-only emails
