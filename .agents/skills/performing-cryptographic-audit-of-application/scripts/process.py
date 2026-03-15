#!/usr/bin/env python3
"""
Cryptographic Audit Scanner

Scans Python source files and configuration files for cryptographic
weaknesses including deprecated algorithms, insecure modes, hardcoded
secrets, and weak key derivation parameters.

Requirements:
    pip install cryptography

Usage:
    python process.py scan --target ./myapp --output audit_report.json
    python process.py scan --target ./myapp/crypto.py --output report.json
    python process.py test-samples  # Run against built-in test samples
"""

import os
import re
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A cryptographic audit finding."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    cwe_id: Optional[str] = None


WEAK_HASH_PATTERNS = [
    (r"\bmd5\b", "MD5", "CWE-328"),
    (r"\bsha1\b", "SHA-1", "CWE-328"),
    (r"\bSHA1\b", "SHA-1", "CWE-328"),
    (r"\bMD5\b", "MD5", "CWE-328"),
    (r"hashlib\.md5", "MD5 via hashlib", "CWE-328"),
    (r"hashlib\.sha1", "SHA-1 via hashlib", "CWE-328"),
    (r"hashes\.MD5", "MD5 via cryptography", "CWE-328"),
    (r"hashes\.SHA1", "SHA-1 via cryptography", "CWE-328"),
]

WEAK_CIPHER_PATTERNS = [
    (r"\bDES\b(?!3)", "DES", "CWE-327"),
    (r"\bRC4\b", "RC4", "CWE-327"),
    (r"\bRC2\b", "RC2", "CWE-327"),
    (r"\bBlowfish\b", "Blowfish", "CWE-327"),
    (r"algorithms\.TripleDES", "3DES", "CWE-327"),
    (r"MODE_ECB", "ECB mode", "CWE-327"),
    (r"AES\.MODE_ECB", "AES-ECB mode", "CWE-327"),
]

HARDCODED_SECRET_PATTERNS = [
    (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "Hardcoded password", "CWE-798"),
    (r'(?:secret|api_?key|token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded secret/key", "CWE-798"),
    (r'(?:private_?key|priv_?key)\s*=\s*["\'][^"\']+["\']', "Hardcoded private key", "CWE-798"),
    (r'["\']-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Embedded private key", "CWE-798"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "CWE-798"),
]

WEAK_KDF_PATTERNS = [
    (r'iterations\s*=\s*(\d+)', "KDF iterations check", "CWE-916"),
    (r'PBKDF2.*iterations.*?(\d+)', "PBKDF2 iterations", "CWE-916"),
]

INSECURE_RANDOM_PATTERNS = [
    (r'\brandom\.random\b', "Insecure random (use secrets/os.urandom)", "CWE-338"),
    (r'\brandom\.randint\b', "Insecure random for crypto", "CWE-338"),
    (r'\brandom\.choice\b(?!.*secrets)', "Insecure random choice", "CWE-338"),
    (r'\brandom\.seed\b', "Seeded random (predictable)", "CWE-338"),
]

DEPRECATED_TLS_PATTERNS = [
    (r'SSLv2', "SSLv2 protocol", "CWE-326"),
    (r'SSLv3', "SSLv3 protocol (POODLE)", "CWE-326"),
    (r'TLSv1[^._23]', "TLS 1.0 protocol", "CWE-326"),
    (r'TLSv1_1\b', "TLS 1.1 protocol", "CWE-326"),
    (r'PROTOCOL_SSLv23', "Legacy SSL context", "CWE-326"),
    (r'ssl\.PROTOCOL_TLS(?!_CLIENT)', "Permissive TLS context", "CWE-326"),
    (r'verify_mode\s*=\s*ssl\.CERT_NONE', "TLS certificate verification disabled", "CWE-295"),
    (r'check_hostname\s*=\s*False', "TLS hostname checking disabled", "CWE-297"),
]


def scan_file(file_path: str) -> List[Finding]:
    """Scan a single file for cryptographic weaknesses."""
    findings = []

    try:
        content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Cannot read {file_path}: {e}")
        return findings

    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Weak hash algorithms
        for pattern, algo_name, cwe in WEAK_HASH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    category="Weak Hashing",
                    title=f"Use of weak hash algorithm: {algo_name}",
                    description=f"{algo_name} is cryptographically broken and should not be used for security purposes (signatures, integrity, password hashing).",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    remediation=f"Replace {algo_name} with SHA-256 or SHA-3. For password hashing, use Argon2id or bcrypt.",
                    cwe_id=cwe,
                ))

        # Weak ciphers and modes
        for pattern, algo_name, cwe in WEAK_CIPHER_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    severity="HIGH",
                    category="Weak Encryption",
                    title=f"Use of insecure cipher or mode: {algo_name}",
                    description=f"{algo_name} is deprecated or insecure. ECB mode leaks patterns in ciphertext.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    remediation="Use AES-256-GCM for authenticated encryption. Never use ECB mode.",
                    cwe_id=cwe,
                ))

        # Hardcoded secrets
        for pattern, desc, cwe in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                sanitized = re.sub(r'["\'][^"\']+["\']', '"***REDACTED***"', stripped)
                findings.append(Finding(
                    severity="CRITICAL",
                    category="Hardcoded Secret",
                    title=f"Potential hardcoded secret: {desc}",
                    description="Secrets should never be hardcoded in source code. They can be extracted from version control history.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=sanitized[:200],
                    remediation="Store secrets in environment variables, AWS Secrets Manager, HashiCorp Vault, or similar.",
                    cwe_id=cwe,
                ))

        # Weak KDF parameters
        for pattern, desc, cwe in WEAK_KDF_PATTERNS:
            match = re.search(pattern, line)
            if match:
                try:
                    iterations = int(match.group(1))
                    if iterations < 100_000:
                        findings.append(Finding(
                            severity="HIGH",
                            category="Weak Key Derivation",
                            title=f"Insufficient KDF iterations: {iterations}",
                            description=f"PBKDF2 with {iterations} iterations is too low. OWASP recommends minimum 600,000 for PBKDF2-SHA256.",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=stripped[:200],
                            remediation="Increase PBKDF2 iterations to 600,000+ or switch to Argon2id.",
                            cwe_id=cwe,
                        ))
                except (ValueError, IndexError):
                    pass

        # Insecure random
        for pattern, desc, cwe in INSECURE_RANDOM_PATTERNS:
            if re.search(pattern, line):
                if "import" not in stripped:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Insecure Randomness",
                        title=f"Insecure random number generation: {desc}",
                        description="Python's random module is not cryptographically secure. Use os.urandom() or secrets module.",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=stripped[:200],
                        remediation="Use os.urandom(), secrets.token_bytes(), or secrets.token_hex() for cryptographic operations.",
                        cwe_id=cwe,
                    ))

        # Deprecated TLS
        for pattern, desc, cwe in DEPRECATED_TLS_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    severity="HIGH",
                    category="Deprecated Protocol",
                    title=f"Insecure TLS/SSL configuration: {desc}",
                    description=f"Deprecated or insecure protocol/configuration detected. {desc} is vulnerable to known attacks.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=stripped[:200],
                    remediation="Use TLS 1.2+ with strong cipher suites. Enable certificate verification and hostname checking.",
                    cwe_id=cwe,
                ))

    return findings


def scan_directory(target_dir: str, extensions: Optional[List[str]] = None) -> List[Finding]:
    """Scan all matching files in a directory."""
    if extensions is None:
        extensions = [".py", ".js", ".ts", ".java", ".go", ".yml", ".yaml", ".json", ".conf", ".cfg", ".ini", ".env"]

    all_findings = []
    target_path = Path(target_dir)

    if target_path.is_file():
        return scan_file(str(target_path))

    for ext in extensions:
        for file in target_path.rglob(f"*{ext}"):
            if ".git" in str(file) or "node_modules" in str(file) or "__pycache__" in str(file):
                continue
            findings = scan_file(str(file))
            all_findings.extend(findings)

    return all_findings


def generate_report(findings: List[Finding], target: str) -> Dict:
    """Generate a structured audit report."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    category_counts = {}

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    overall_risk = "LOW"
    if severity_counts["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"

    return {
        "audit_target": target,
        "total_findings": len(findings),
        "overall_risk": overall_risk,
        "severity_summary": severity_counts,
        "category_summary": category_counts,
        "findings": [asdict(f) for f in findings],
        "recommendations": [
            "Replace all deprecated hash algorithms (MD5, SHA-1) with SHA-256 or SHA-3",
            "Replace DES/3DES/RC4 with AES-256-GCM",
            "Never use ECB mode; use GCM for authenticated encryption",
            "Move all hardcoded secrets to a secrets manager",
            "Use PBKDF2 with 600,000+ iterations or switch to Argon2id",
            "Use os.urandom() or secrets module for cryptographic randomness",
            "Enforce TLS 1.2+ and disable all legacy protocols",
            "Enable certificate verification and hostname checking",
        ],
    }


def test_with_samples():
    """Test the scanner with known-bad samples."""
    samples = '''
import hashlib
import random

password = "SuperSecret123!"
api_key = "sk-abcdef1234567890abcdef"

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def generate_token():
    return random.randint(100000, 999999)

from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)

import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
ctx.verify_mode = ssl.CERT_NONE
ctx.check_hostname = False
'''
    # Write temp sample file
    sample_path = Path("__crypto_audit_test_sample.py")
    sample_path.write_text(samples)

    findings = scan_file(str(sample_path))
    report = generate_report(findings, str(sample_path))

    print(json.dumps(report, indent=2))
    print(f"\nTotal findings: {report['total_findings']}")
    print(f"Overall risk: {report['overall_risk']}")

    sample_path.unlink()
    return report


def main():
    parser = argparse.ArgumentParser(description="Cryptographic Audit Scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan target for crypto weaknesses")
    scan.add_argument("--target", "-t", required=True, help="File or directory to scan")
    scan.add_argument("--output", "-o", help="Output report file (JSON)")

    subparsers.add_parser("test-samples", help="Test with built-in weak samples")

    args = parser.parse_args()

    if args.command == "scan":
        findings = scan_directory(args.target)
        report = generate_report(findings, args.target)
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2))
            logger.info(f"Report saved to {args.output}")
        print(json.dumps(report, indent=2))
    elif args.command == "test-samples":
        test_with_samples()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
