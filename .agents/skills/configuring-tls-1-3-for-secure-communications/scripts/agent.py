#!/usr/bin/env python3
"""TLS 1.3 configuration audit agent using ssl and cryptography libraries."""

import json
import sys
import argparse
import ssl
import socket
from datetime import datetime

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Install: pip install cryptography")
    sys.exit(1)


def check_tls_versions(host, port=443):
    """Check supported TLS versions on a server."""
    results = {}
    protocols = {
        "TLSv1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }
    for version_name, version in protocols.items():
        if version is None:
            results[version_name] = {"supported": False, "note": "Not available in this Python build"}
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results[version_name] = {
                        "supported": True,
                        "cipher": ssock.cipher()[0],
                        "severity": "CRITICAL" if "1.0" in version_name or "1.1" in version_name else "INFO",
                    }
        except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
            results[version_name] = {"supported": False}
    return results


def get_certificate_info(host, port=443):
    """Retrieve and analyze server certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert)
                days_remaining = (cert.not_valid_after_utc.replace(tzinfo=None) - datetime.utcnow()).days
                return {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_after": str(cert.not_valid_after_utc),
                    "days_remaining": days_remaining,
                    "key_size": cert.public_key().key_size,
                    "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
                    "issues": [],
                }
    except Exception as e:
        return {"error": str(e)}


def check_cipher_suites(host, port=443):
    """Check negotiated cipher suites."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return {
                    "negotiated_cipher": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                    "tls13_ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256",
                                       "TLS_CHACHA20_POLY1305_SHA256"],
                }
    except Exception as e:
        return {"error": str(e)}


def run_audit(host, port=443):
    """Execute TLS 1.3 configuration audit."""
    print(f"\n{'='*60}")
    print(f"  TLS 1.3 CONFIGURATION AUDIT")
    print(f"  Target: {host}:{port}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    versions = check_tls_versions(host, port)
    print(f"--- TLS VERSION SUPPORT ---")
    for ver, info in versions.items():
        status = "SUPPORTED" if info.get("supported") else "NOT SUPPORTED"
        sev = info.get("severity", "")
        print(f"  {ver}: {status} {f'[{sev}]' if sev else ''}")

    cert = get_certificate_info(host, port)
    print(f"\n--- CERTIFICATE ---")
    if "error" not in cert:
        print(f"  Subject: {cert['subject']}")
        print(f"  Issuer: {cert['issuer']}")
        print(f"  Expires: {cert['not_after']} ({cert['days_remaining']} days)")
        print(f"  Key size: {cert['key_size']}")

    cipher = check_cipher_suites(host, port)
    print(f"\n--- CIPHER SUITE ---")
    if "error" not in cipher:
        print(f"  Negotiated: {cipher['negotiated_cipher']}")
        print(f"  Protocol: {cipher['protocol']}")

    return {"versions": versions, "certificate": cert, "cipher": cipher}


def main():
    parser = argparse.ArgumentParser(description="TLS 1.3 Audit Agent")
    parser.add_argument("--host", required=True, help="Target hostname")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args.host, args.port)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
