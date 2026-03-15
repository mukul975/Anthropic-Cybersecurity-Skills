#!/usr/bin/env python3
"""
QR Code Phishing (Quishing) Detection Engine

Detects QR codes in images and email content, extracts encoded URLs,
and checks them against known phishing indicators.

Usage:
    python process.py scan-image --image qr_image.png
    python process.py scan-email --eml-file message.eml
    python process.py check-url --url "https://example.com/login"
"""

import argparse
import json
import re
import sys
import base64
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False


@dataclass
class QRCodeFinding:
    """A detected QR code and its analysis."""
    source: str = ""
    decoded_url: str = ""
    domain: str = ""
    is_suspicious: bool = False
    risk_score: int = 0
    indicators: list = field(default_factory=list)


@dataclass
class QuishingAnalysis:
    """Complete quishing analysis result."""
    source_file: str = ""
    qr_codes_found: int = 0
    findings: list = field(default_factory=list)
    email_indicators: list = field(default_factory=list)
    overall_risk: str = "low"
    recommended_action: str = ""


# Suspicious URL patterns for credential phishing
SUSPICIOUS_URL_PATTERNS = [
    r'login|signin|sign-in|log-in',
    r'verify|verification|validate',
    r'account|password|credential',
    r'microsoft|office365|outlook|sharepoint',
    r'google|gmail|workspace',
    r'secure|security|auth',
    r'update|confirm|suspend',
    r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$',
    r'bit\.ly|tinyurl|t\.co|is\.gd|cutt\.ly',
]

# Known phishing infrastructure patterns
PHISHING_INFRA_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address URLs
    r'[a-z0-9]{20,}\.web\.app',  # Firebase hosting abuse
    r'[a-z0-9]{20,}\.netlify\.app',  # Netlify abuse
    r'[a-z0-9-]+\.glitch\.me',  # Glitch abuse
    r'[a-z0-9-]+\.workers\.dev',  # Cloudflare workers abuse
]

# Common quishing email indicators
QUISHING_EMAIL_PATTERNS = [
    r'scan\s+(this|the)\s+qr\s+code',
    r'scan\s+to\s+(verify|authenticate|confirm|access)',
    r'multi.?factor\s+authentication',
    r'mfa\s+(setup|enrollment|reset|update)',
    r'voicemail\s+(notification|message)',
    r'document\s+(sign|signing|review)',
    r'security\s+update\s+required',
    r'action\s+required',
]


def analyze_url(url: str) -> QRCodeFinding:
    """Analyze a URL extracted from a QR code for phishing indicators."""
    finding = QRCodeFinding(decoded_url=url)

    try:
        parsed = urlparse(url)
        finding.domain = parsed.netloc
    except Exception:
        finding.indicators.append("Could not parse URL")
        finding.is_suspicious = True
        finding.risk_score = 50
        return finding

    score = 0

    # Check suspicious URL patterns
    url_lower = url.lower()
    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, url_lower):
            finding.indicators.append(f"Suspicious URL pattern: {pattern}")
            score += 15

    # Check phishing infrastructure patterns
    for pattern in PHISHING_INFRA_PATTERNS:
        if re.search(pattern, url_lower):
            finding.indicators.append(f"Known phishing infrastructure pattern: {pattern}")
            score += 25

    # Check for URL shorteners (hiding true destination)
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly',
                  'rebrand.ly', 'ow.ly', 'buff.ly']
    if finding.domain in shorteners:
        finding.indicators.append(f"URL shortener detected: {finding.domain}")
        score += 20

    # Check for IP address URL
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', finding.domain):
        finding.indicators.append("URL uses IP address instead of domain name")
        score += 30

    # Check for excessive subdomains (common in phishing)
    subdomain_count = finding.domain.count('.')
    if subdomain_count > 3:
        finding.indicators.append(f"Excessive subdomains ({subdomain_count})")
        score += 15

    # Check for homoglyph characters in domain
    non_ascii = [c for c in finding.domain if ord(c) > 127]
    if non_ascii:
        finding.indicators.append("Non-ASCII characters in domain (possible homoglyph)")
        score += 25

    # Check protocol
    if not url.startswith('https://'):
        finding.indicators.append("URL does not use HTTPS")
        score += 10

    finding.risk_score = min(score, 100)
    finding.is_suspicious = score >= 30

    return finding


def scan_image_for_qr(image_path: str) -> list:
    """Scan an image file for QR codes and extract URLs."""
    findings = []

    if not HAS_PIL:
        print("Pillow not installed. Install with: pip install Pillow", file=sys.stderr)
        return findings
    if not HAS_PYZBAR:
        print("pyzbar not installed. Install with: pip install pyzbar", file=sys.stderr)
        return findings

    try:
        img = Image.open(image_path)
        decoded_objects = qr_decode(img)

        for obj in decoded_objects:
            data = obj.data.decode('utf-8', errors='replace')
            if data.startswith(('http://', 'https://', 'www.')):
                url = data if data.startswith('http') else f'https://{data}'
                finding = analyze_url(url)
                finding.source = image_path
                findings.append(finding)
            else:
                finding = QRCodeFinding(
                    source=image_path,
                    decoded_url=data,
                    indicators=["QR code contains non-URL data"],
                    risk_score=10
                )
                findings.append(finding)

    except Exception as e:
        print(f"Error scanning image: {e}", file=sys.stderr)

    return findings


def scan_email_content(eml_content: str) -> QuishingAnalysis:
    """Analyze email content for quishing indicators."""
    analysis = QuishingAnalysis()
    body_lower = eml_content.lower()

    # Check for quishing email patterns
    for pattern in QUISHING_EMAIL_PATTERNS:
        if re.search(pattern, body_lower):
            analysis.email_indicators.append(f"Quishing language pattern: {pattern}")

    # Check for image-heavy email with minimal text
    text_content = re.sub(r'<[^>]+>', '', eml_content)
    text_content = re.sub(r'\s+', ' ', text_content).strip()
    has_images = bool(re.search(r'<img|Content-Type:\s*image/', eml_content, re.IGNORECASE))
    text_words = len(text_content.split())

    if has_images and text_words < 50:
        analysis.email_indicators.append(
            "Image-heavy email with minimal text (common quishing pattern)"
        )

    # Check for base64-encoded images
    b64_images = re.findall(
        r'Content-Type:\s*image/\w+.*?Content-Transfer-Encoding:\s*base64\s*\n\n([\w+/=\n]+)',
        eml_content, re.DOTALL | re.IGNORECASE
    )

    if b64_images and HAS_PIL and HAS_PYZBAR:
        for i, b64_data in enumerate(b64_images):
            try:
                clean_data = b64_data.replace('\n', '')
                img_bytes = base64.b64decode(clean_data)
                import io
                img = Image.open(io.BytesIO(img_bytes))
                decoded = qr_decode(img)
                for obj in decoded:
                    data = obj.data.decode('utf-8', errors='replace')
                    if data.startswith(('http://', 'https://')):
                        finding = analyze_url(data)
                        finding.source = f"embedded_image_{i}"
                        analysis.findings.append(finding)
                        analysis.qr_codes_found += 1
            except Exception:
                continue

    # Calculate overall risk
    indicator_count = len(analysis.email_indicators)
    has_suspicious_qr = any(f.is_suspicious for f in analysis.findings)

    if has_suspicious_qr and indicator_count >= 2:
        analysis.overall_risk = "critical"
        analysis.recommended_action = "BLOCK and alert SOC"
    elif has_suspicious_qr or indicator_count >= 3:
        analysis.overall_risk = "high"
        analysis.recommended_action = "QUARANTINE for manual review"
    elif indicator_count >= 1:
        analysis.overall_risk = "medium"
        analysis.recommended_action = "TAG with QR phishing warning banner"
    else:
        analysis.overall_risk = "low"
        analysis.recommended_action = "DELIVER normally"

    return analysis


def format_report(analysis: QuishingAnalysis) -> str:
    """Format analysis as readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append("  QR CODE PHISHING (QUISHING) ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"  QR Codes Found: {analysis.qr_codes_found}")
    lines.append(f"  Overall Risk: {analysis.overall_risk.upper()}")
    lines.append(f"  Action: {analysis.recommended_action}")

    if analysis.email_indicators:
        lines.append(f"\n  [EMAIL INDICATORS] ({len(analysis.email_indicators)})")
        for i, ind in enumerate(analysis.email_indicators, 1):
            lines.append(f"    {i}. {ind}")

    if analysis.findings:
        lines.append(f"\n  [QR CODE FINDINGS] ({len(analysis.findings)})")
        for i, finding in enumerate(analysis.findings, 1):
            lines.append(f"    {i}. URL: {finding.decoded_url}")
            lines.append(f"       Domain: {finding.domain}")
            lines.append(f"       Risk Score: {finding.risk_score}/100")
            lines.append(f"       Suspicious: {'YES' if finding.is_suspicious else 'No'}")
            for ind in finding.indicators:
                lines.append(f"       - {ind}")

    lines.append("=" * 60)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="QR Code Phishing Detection")
    subparsers = parser.add_subparsers(dest="command")

    img_parser = subparsers.add_parser("scan-image", help="Scan image for QR codes")
    img_parser.add_argument("--image", required=True)

    eml_parser = subparsers.add_parser("scan-email", help="Scan email for quishing")
    eml_parser.add_argument("--eml-file", required=True)

    url_parser = subparsers.add_parser("check-url", help="Check URL from QR code")
    url_parser.add_argument("--url", required=True)

    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.command == "scan-image":
        findings = scan_image_for_qr(args.image)
        analysis = QuishingAnalysis(
            source_file=args.image,
            qr_codes_found=len(findings),
            findings=findings
        )
        if args.json:
            print(json.dumps(asdict(analysis), indent=2))
        else:
            print(format_report(analysis))

    elif args.command == "scan-email":
        with open(args.eml_file, 'r', errors='replace') as f:
            content = f.read()
        analysis = scan_email_content(content)
        analysis.source_file = args.eml_file
        if args.json:
            print(json.dumps(asdict(analysis), indent=2))
        else:
            print(format_report(analysis))

    elif args.command == "check-url":
        finding = analyze_url(args.url)
        if args.json:
            print(json.dumps(asdict(finding), indent=2))
        else:
            print(f"URL: {finding.decoded_url}")
            print(f"Domain: {finding.domain}")
            print(f"Risk Score: {finding.risk_score}/100")
            print(f"Suspicious: {'YES' if finding.is_suspicious else 'No'}")
            for ind in finding.indicators:
                print(f"  - {ind}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
