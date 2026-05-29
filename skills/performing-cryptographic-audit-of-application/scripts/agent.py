#!/usr/bin/env python3
"""Application cryptographic audit agent.

Audits application code and configurations for cryptographic weaknesses
including weak algorithms, insecure key sizes, hardcoded keys, deprecated
protocols, and missing certificate validation. Scans source files, config
files, and TLS endpoints.
"""
import argparse
import json
import os
import re
import ssl
import socket
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


WEAK_PATTERNS = {
    "weak_hash": {
        "pattern": r'\b(MD5|md5|SHA1|sha1|SHA-1)\b(?!.*hmac)',
        "severity": "HIGH",
        "description": "Weak hash algorithm detected (MD5/SHA1)",
        "recommendation": "Use SHA-256 or SHA-3",
    },
    "weak_cipher": {
        "pattern": r'\b(DES|3DES|RC4|RC2|Blowfish|IDEA)\b',
        "severity": "HIGH",
        "description": "Weak cipher algorithm detected",
        "recommendation": "Use AES-256-GCM or ChaCha20-Poly1305",
    },
    "ecb_mode": {
        "pattern": r'\b(ECB|MODE_ECB|ecb)\b',
        "severity": "CRITICAL",
        "description": "ECB mode detected - does not provide semantic security",
        "recommendation": "Use GCM, CBC with HMAC, or CTR mode",
    },
    "hardcoded_key": {
        "pattern": r'(?:key|secret|password|token)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        "severity": "CRITICAL",
        "description": "Possible hardcoded cryptographic key or secret",
        "recommendation": "Use environment variables or a secrets manager",
    },
    "small_rsa_key": {
        "pattern": r'(?:key_?size|bits)\s*[=:]\s*(?:512|768|1024)\b',
        "severity": "CRITICAL",
        "description": "RSA key size too small (<2048 bits)",
        "recommendation": "Use minimum 2048-bit, preferably 4096-bit RSA keys",
    },
    "weak_random": {
        "pattern": r'\b(?:random\.random|math\.random|Math\.random|rand\(\)|srand)\b',
        "severity": "HIGH",
        "description": "Non-cryptographic random number generator used",
        "recommendation": "Use secrets module, os.urandom, or crypto.getRandomValues",
    },
    "ssl_no_verify": {
        "pattern": r'(?:verify\s*=\s*False|CERT_NONE|SSL_VERIFY_NONE|InsecureRequestWarning|verify_ssl\s*=\s*False)',
        "severity": "HIGH",
        "description": "TLS certificate verification disabled",
        "recommendation": "Enable certificate verification in all TLS connections",
    },
    "tls_v1": {
        "pattern": r'(?:TLSv1[^._23]|SSLv[23]|PROTOCOL_TLS(?!v1_[23])|TLS_1_0|TLS_1_1)',
        "severity": "HIGH",
        "description": "Deprecated TLS/SSL protocol version detected",
        "recommendation": "Use TLS 1.2 or TLS 1.3 minimum",
    },
    "padding_oracle": {
        "pattern": r'(?:PKCS1v15|pkcs1_v1_5|PKCS5Padding)(?!.*OAEP)',
        "severity": "MEDIUM",
        "description": "PKCS#1 v1.5 padding used (vulnerable to padding oracle attacks)",
        "recommendation": "Use OAEP padding for RSA, or switch to AEAD ciphers",
    },
    "static_iv": {
        "pattern": r'(?:iv|IV|nonce)\s*[=:]\s*(?:b?["\'][^"\']{1,32}["\']|bytes\([^)]*\))',
        "severity": "HIGH",
        "description": "Possible static/hardcoded IV or nonce",
        "recommendation": "Generate random IV/nonce for each encryption operation",
    },
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".c", ".cpp",
    ".h", ".yaml", ".yml", ".json", ".xml", ".conf", ".cfg", ".ini", ".env",
    ".toml", ".properties",
}


def scan_file(file_path):
    """Scan a single file for cryptographic weaknesses."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except (IOError, PermissionError):
        return findings

    for line_num, line in enumerate(lines, 1):
        for rule_id, rule in WEAK_PATTERNS.items():
            if re.search(rule["pattern"], line):
                findings.append({
                    "rule": rule_id,
                    "file": file_path,
                    "line": line_num,
                    "content": line.strip()[:120],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                })
    return findings


def scan_directory(directory, extensions=None, exclude_dirs=None):
    """Recursively scan a directory for cryptographic weaknesses."""
    if extensions is None:
        extensions = SCAN_EXTENSIONS
    if exclude_dirs is None:
        exclude_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv",
                        "vendor", "dist", "build", ".tox"}

    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in extensions:
                continue
            full_path = os.path.join(root, fname)
            findings = scan_file(full_path)
            all_findings.extend(findings)
            files_scanned += 1

    print(f"[+] Scanned {files_scanned} files, found {len(all_findings)} issues")
    return all_findings, files_scanned


def audit_tls_endpoint(host, port=443):
    """Audit TLS configuration of a remote endpoint."""
    findings = []
    print(f"[*] Auditing TLS: {host}:{port}")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

                findings.append({
                    "check": "TLS Protocol",
                    "value": protocol,
                    "severity": "CRITICAL" if "TLSv1.0" in protocol or "TLSv1.1" in protocol
                               else "INFO",
                    "description": f"Negotiated protocol: {protocol}",
                })

                if cipher:
                    cipher_name, tls_ver, key_bits = cipher
                    findings.append({
                        "check": "Cipher Suite",
                        "value": cipher_name,
                        "severity": "HIGH" if any(w in cipher_name for w in ["RC4", "DES", "NULL", "EXPORT"])
                                   else "INFO",
                        "description": f"Cipher: {cipher_name} ({key_bits} bits)",
                    })

                if HAS_CRYPTO and cert_der:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                    days_remaining = (not_after - datetime.now(timezone.utc)).days

                    pub_key = cert.public_key()
                    key_size = getattr(pub_key, 'key_size', 0)
                    sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_hash_algorithm)

                    findings.append({
                        "check": "Certificate Expiry",
                        "value": f"{days_remaining} days",
                        "severity": "CRITICAL" if days_remaining < 0
                                   else "HIGH" if days_remaining < 30
                                   else "MEDIUM" if days_remaining < 90
                                   else "INFO",
                        "description": f"Expires: {not_after.isoformat()} ({days_remaining} days)",
                    })
                    findings.append({
                        "check": "Key Size",
                        "value": f"{key_size} bits",
                        "severity": "CRITICAL" if key_size < 2048
                                   else "MEDIUM" if key_size < 4096
                                   else "INFO",
                    })
                    findings.append({
                        "check": "Signature Algorithm",
                        "value": str(sig_algo),
                        "severity": "HIGH" if "sha1" in str(sig_algo).lower() else "INFO",
                    })

    except ssl.SSLError as e:
        findings.append({"check": "TLS Connection", "severity": "CRITICAL",
                         "description": f"SSL error: {e}"})
    except socket.timeout:
        findings.append({"check": "TLS Connection", "severity": "HIGH",
                         "description": "Connection timed out"})
    except Exception as e:
        findings.append({"check": "TLS Connection", "severity": "HIGH",
                         "description": f"Error: {e}"})

    return findings


def format_summary(code_findings, tls_findings, files_scanned, target):
    """Print audit summary."""
    all_findings = code_findings + tls_findings
    print(f"\n{'='*60}")
    print("  Cryptographic Audit Report")
    print(f"{'='*60}")
    print(f"  Target         : {target}")
    print(f"  Files Scanned  : {files_scanned}")
    print(f"  Code Findings  : {len(code_findings)}")
    print(f"  TLS Findings   : {len(tls_findings)}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    if code_findings:
        by_rule = {}
        for f in code_findings:
            by_rule.setdefault(f["rule"], []).append(f)
        print("\n  Code Issues by Rule:")
        for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
            print(f"    {rule:25s}: {len(items)} ({items[0]['severity']})")

        print("\n  Top Code Findings:")
        for f in code_findings[:15]:
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f"    [{f['severity']:8s}] {f['file']}:{f['line']} - {f['description']}")

    if tls_findings:
        print("\n  TLS Audit Results:")
        for f in tls_findings:
            print(f"    [{f['severity']:8s}] {f.get('check', '')}: "
                  f"{f.get('value', f.get('description', ''))}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Application cryptographic audit agent"
    )
    parser.add_argument("--target", required=True,
                        help="Source directory to scan or TLS host to audit")
    parser.add_argument("--tls-port", type=int, default=443,
                        help="TLS port for endpoint audit (default: 443)")
    parser.add_argument("--tls-only", action="store_true",
                        help="Only audit TLS endpoint, skip code scan")
    parser.add_argument("--code-only", action="store_true",
                        help="Only scan code, skip TLS audit")
    parser.add_argument("--exclude-dirs", nargs="+",
                        help="Additional directories to exclude from scan")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    code_findings = []
    tls_findings = []
    files_scanned = 0

    if not args.tls_only and os.path.isdir(args.target):
        exclude = {"node_modules", ".git", "__pycache__", "venv", ".venv", "vendor"}
        if args.exclude_dirs:
            exclude.update(args.exclude_dirs)
        code_findings, files_scanned = scan_directory(args.target, exclude_dirs=exclude)

    if not args.code_only and not os.path.isdir(args.target):
        tls_findings = audit_tls_endpoint(args.target, args.tls_port)
    elif not args.code_only and os.path.isdir(args.target):
        pass  # Can't audit TLS on a directory

    severity_counts = format_summary(code_findings, tls_findings, files_scanned, args.target)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Crypto Audit",
        "target": args.target,
        "files_scanned": files_scanned,
        "severity_counts": severity_counts,
        "code_findings": code_findings,
        "tls_findings": tls_findings,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
