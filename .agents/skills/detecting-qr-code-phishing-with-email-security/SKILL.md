---
name: detecting-qr-code-phishing-with-email-security
description: Detect and prevent QR code phishing (quishing) attacks that bypass traditional email security by embedding malicious URLs in QR code images within emails.
domain: cybersecurity
subdomain: phishing-defense
tags: [quishing, qr-code, phishing, email-security, image-analysis, ocr, mobile-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Detecting QR Code Phishing with Email Security

## Overview
QR code phishing (quishing) is a rapidly growing attack vector where malicious URLs are embedded in QR code images within phishing emails. Quishing incidents grew fivefold from 46,000 to 250,000 between August and November 2025, with credential phishing comprising 89.3% of detected incidents. Traditional email security filters struggle because QR codes cannot be read by humans or standard URL scanners, and when scanned, users typically use personal mobile devices that lack corporate security controls. Attackers have evolved to use split QR codes (two separate images), nested QR codes, and ASCII text-based QR codes to evade detection.

## Prerequisites
- Email security gateway with image analysis capabilities
- Understanding of QR code structure and encoding
- Mobile device management (MDM) or mobile threat defense solution
- Security awareness training program
- SIEM platform for correlation and alerting

## Key Concepts

### Why Quishing Works
1. **Bypasses URL Scanners**: Traditional gateways scan text-based URLs but cannot decode image-embedded URLs
2. **Shifts to Unprotected Devices**: Corporate email arrives on secured systems but QR scan occurs on personal mobile devices
3. **User Trust**: QR codes are normalized in daily life (payments, menus, parking)
4. **Low Detection Rate**: Only 36% of quishing incidents are accurately identified by recipients

### Evasion Techniques (2025)
- **Split QR Codes**: QR code divided into two separate images that look benign individually (Gabagool PhaaS kit)
- **Nested QR Codes**: QR code within a QR code, with first scan leading to intermediate page
- **ASCII QR Codes**: QR rendered as text characters instead of images, bypassing image analysis (12% of attacks in Jan 2026)
- **Styled/Artistic QR Codes**: Custom-designed QR codes with logos that evade pattern matching
- **PDF Attachment QR**: QR code embedded in PDF attachment rather than email body

### Detection Challenges
- Pattern-based detection faces trade-off: aggressive tuning causes false positives, cautious tuning causes misses
- Average similarity score of 0.209 between quishing and legitimate QR emails
- QR codes in image attachments require OCR and deep image processing

## Implementation Steps

### Step 1: Enable Image-Based Threat Detection
- Configure email gateway to scan embedded images for QR codes
- Enable OCR processing on image attachments (PNG, JPG, GIF, BMP)
- Deploy multimodal AI that combines image processing, OCR, and NLP analysis
- Configure PDF scanning to detect QR codes within attachments
- Set up detection for ASCII/text-based QR code rendering

### Step 2: Configure QR Code URL Analysis
- Extract URLs from detected QR codes and submit to URL reputation services
- Apply same URL scanning policies to QR-extracted URLs as text-based URLs
- Enable real-time sandbox analysis for QR-decoded destination pages
- Configure time-of-click protection for QR-extracted URLs where possible
- Block known phishing domains extracted from QR codes

### Step 3: Deploy Mobile-Side Protection
- Implement mobile threat defense (MTD) with QR code scanning capability
- Deploy Palo Alto ALFA or equivalent safe-by-design QR scanning
- Configure MDM policies to warn users before opening scanned URLs
- Enable corporate VPN/secure browser for QR-scanned destinations
- Block known credential harvesting domains at the mobile proxy level

### Step 4: Build Detection Rules
- Alert on emails containing only an image and minimal text (common quishing pattern)
- Flag emails with QR code images from external first-time senders
- Detect urgency language combined with QR code presence
- Alert on emails impersonating IT/security team requesting QR scan for MFA setup
- Monitor for common quishing themes: MFA reset, document signing, voicemail notification

### Step 5: Train Users on Quishing Recognition
- Update security awareness program to include QR code phishing scenarios
- Conduct quishing simulation campaigns using controlled QR codes
- Teach users to verify QR destination URLs before entering credentials
- Establish reporting process for suspicious QR code emails
- Distribute guidance on safe QR scanning practices

## Tools & Resources
- **Barracuda Multimodal AI**: OCR + deep image processing for QR detection
- **Palo Alto ALFA**: Safe-by-design QR code scanning assessment
- **Microsoft Defender for O365**: QR code detection in email images
- **Proofpoint TAP**: Image-based threat analysis with QR decoding
- **Lookout/Zimperium**: Mobile threat defense with QR scanning

## Validation
- QR code phishing emails detected in controlled testing
- Split QR code and ASCII QR code evasion techniques caught
- QR-extracted URLs submitted to sandbox analysis
- Mobile devices alert on malicious QR destinations
- User reporting rate for quishing simulations exceeds 50%
- False positive rate for QR detection below 1%
