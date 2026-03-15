#!/usr/bin/env python3
"""Certificate Authority management agent using OpenSSL and cryptography library."""

import json
import sys
import argparse
import subprocess
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import timedelta
except ImportError:
    print("Install: pip install cryptography")
    sys.exit(1)


def generate_ca_certificate(cn="Internal Root CA", org="Organization", days=3650):
    """Generate a self-signed root CA certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                          crl_sign=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, encipher_only=False,
                                          decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def generate_server_cert(ca_cert, ca_key, cn, san_names, days=365):
    """Generate a server certificate signed by the CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    san = x509.SubjectAlternativeName([x509.DNSName(n) for n in san_names])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=days))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return cert, key


def audit_certificate(cert_path):
    """Audit an existing certificate for security issues."""
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data)
    issues = []
    if cert.public_key().key_size < 2048:
        issues.append({"issue": "Weak key size", "severity": "HIGH",
                        "detail": f"Key size {cert.public_key().key_size} < 2048"})
    if cert.not_valid_after_utc.replace(tzinfo=None) < datetime.utcnow():
        issues.append({"issue": "Certificate expired", "severity": "CRITICAL",
                        "detail": f"Expired on {cert.not_valid_after_utc}"})
    days_remaining = (cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()).days
    if 0 < days_remaining < 30:
        issues.append({"issue": "Certificate expiring soon", "severity": "HIGH",
                        "detail": f"{days_remaining} days remaining"})
    sig_algo = cert.signature_hash_algorithm
    if sig_algo and sig_algo.name in ("sha1", "md5"):
        issues.append({"issue": f"Weak signature algorithm: {sig_algo.name}", "severity": "HIGH"})
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": str(cert.not_valid_before_utc),
        "not_after": str(cert.not_valid_after_utc),
        "key_size": cert.public_key().key_size,
        "serial": cert.serial_number,
        "issues": issues,
    }


def run_audit(cert_path=None, generate=False, cn=None, org=None):
    """Execute CA operations."""
    print(f"\n{'='*60}")
    print(f"  CERTIFICATE AUTHORITY AGENT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    if cert_path:
        info = audit_certificate(cert_path)
        print(f"--- CERTIFICATE AUDIT ---")
        print(f"  Subject: {info['subject']}")
        print(f"  Issuer: {info['issuer']}")
        print(f"  Valid: {info['not_before']} to {info['not_after']}")
        print(f"  Key Size: {info['key_size']}")
        print(f"  Issues: {len(info['issues'])}")
        for i in info["issues"]:
            print(f"    [{i['severity']}] {i['issue']}: {i.get('detail', '')}")
        return info

    if generate:
        cert, key = generate_ca_certificate(cn=cn or "Internal Root CA", org=org or "Org")
        print(f"--- CA CERTIFICATE GENERATED ---")
        print(f"  Subject: {cert.subject.rfc4514_string()}")
        print(f"  Serial: {cert.serial_number}")
        return {"status": "generated", "subject": cert.subject.rfc4514_string()}

    return {}


def main():
    parser = argparse.ArgumentParser(description="Certificate Authority Agent")
    parser.add_argument("--audit", help="Path to PEM certificate to audit")
    parser.add_argument("--generate", action="store_true", help="Generate new CA")
    parser.add_argument("--cn", help="Common name for CA cert")
    parser.add_argument("--org", help="Organization name")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.audit, args.generate, args.cn, args.org)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
