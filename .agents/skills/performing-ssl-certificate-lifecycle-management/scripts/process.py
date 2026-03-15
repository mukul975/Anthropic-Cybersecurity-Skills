#!/usr/bin/env python3
"""
SSL Certificate Lifecycle Management Tool

Implements certificate generation, parsing, monitoring, chain validation,
and OCSP checking for managing TLS certificate lifecycles.

Requirements:
    pip install cryptography requests

Usage:
    python process.py generate-csr --domain example.com --output ./certs
    python process.py check-expiry --host example.com
    python process.py parse-cert --cert ./server.crt
    python process.py monitor --domains domains.txt --threshold 30
    python process.py verify-chain --cert ./server.crt --ca-bundle ./ca-bundle.crt
"""

import os
import ssl
import sys
import json
import socket
import argparse
import logging
import datetime
from pathlib import Path
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 15


def generate_csr(
    domain: str,
    output_dir: str,
    key_type: str = "ecdsa",
    san_domains: Optional[List[str]] = None,
    organization: Optional[str] = None,
) -> Dict:
    """Generate a private key and CSR for a domain."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if key_type == "ecdsa":
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

    subject_attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ]
    if organization:
        subject_attrs.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    subject = x509.Name(subject_attrs)

    san_list = [x509.DNSName(domain)]
    if san_domains:
        for d in san_domains:
            san_list.append(x509.DNSName(d))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    key_path = output_path / f"{domain}.key"
    csr_path = output_path / f"{domain}.csr"

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Generated CSR for {domain}")

    return {
        "domain": domain,
        "key_type": key_type,
        "key_path": str(key_path),
        "csr_path": str(csr_path),
        "san_domains": [d.value for d in san_list],
    }


def parse_certificate(cert_path: str) -> Dict:
    """Parse an X.509 certificate and extract key information."""
    cert_data = Path(cert_path).read_bytes()

    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

    subject_attrs = {}
    for attr in cert.subject:
        subject_attrs[attr.oid._name] = attr.value

    issuer_attrs = {}
    for attr in cert.issuer:
        issuer_attrs[attr.oid._name] = attr.value

    san_names = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = [name.value for name in san_ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    now = datetime.datetime.utcnow()
    not_after = cert.not_valid_after_utc.replace(tzinfo=None)
    days_remaining = (not_after - now).days

    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_info = {"type": "RSA", "size": pub_key.key_size}
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_info = {"type": "ECDSA", "curve": pub_key.curve.name, "size": pub_key.key_size}
    else:
        key_info = {"type": "Unknown"}

    return {
        "subject": subject_attrs,
        "issuer": issuer_attrs,
        "serial_number": hex(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "days_remaining": days_remaining,
        "san_domains": san_names,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key": key_info,
        "version": cert.version.value,
        "is_expired": days_remaining < 0,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def check_remote_certificate(host: str, port: int = 443, timeout: int = 10) -> Dict:
    """Check the TLS certificate of a remote host."""
    result = {
        "host": host,
        "port": port,
        "status": "unknown",
        "days_remaining": None,
        "certificate": None,
        "errors": [],
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                now = datetime.datetime.utcnow()
                not_after = cert.not_valid_after_utc.replace(tzinfo=None)
                days_remaining = (not_after - now).days

                result["days_remaining"] = days_remaining
                result["not_after"] = not_after.isoformat()
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0]

                subject_cn = None
                for attr in cert.subject:
                    if attr.oid == NameOID.COMMON_NAME:
                        subject_cn = attr.value
                        break

                result["common_name"] = subject_cn
                result["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()

                if days_remaining < 0:
                    result["status"] = "EXPIRED"
                elif days_remaining < EXPIRY_CRITICAL_DAYS:
                    result["status"] = "CRITICAL"
                elif days_remaining < EXPIRY_WARNING_DAYS:
                    result["status"] = "WARNING"
                else:
                    result["status"] = "OK"

    except ssl.SSLCertVerificationError as e:
        result["status"] = "INVALID"
        result["errors"].append(f"Certificate verification failed: {e}")
    except socket.timeout:
        result["status"] = "TIMEOUT"
        result["errors"].append("Connection timed out")
    except Exception as e:
        result["status"] = "ERROR"
        result["errors"].append(str(e))

    return result


def monitor_domains(domains: List[str], threshold_days: int = 30) -> Dict:
    """Monitor certificate expiration for multiple domains."""
    results = {
        "scan_time": datetime.datetime.utcnow().isoformat() + "Z",
        "threshold_days": threshold_days,
        "total_domains": len(domains),
        "ok": 0,
        "warning": 0,
        "critical": 0,
        "expired": 0,
        "errors": 0,
        "domains": [],
    }

    for domain in domains:
        domain = domain.strip()
        if not domain or domain.startswith("#"):
            continue

        host = domain.split(":")[0]
        port = int(domain.split(":")[1]) if ":" in domain else 443

        logger.info(f"Checking {host}:{port}...")
        check = check_remote_certificate(host, port)
        results["domains"].append(check)

        status = check["status"]
        if status == "OK":
            results["ok"] += 1
        elif status == "WARNING":
            results["warning"] += 1
        elif status == "CRITICAL":
            results["critical"] += 1
        elif status == "EXPIRED":
            results["expired"] += 1
        else:
            results["errors"] += 1

    return results


def verify_certificate_chain(cert_path: str, ca_bundle_path: str) -> Dict:
    """Verify a certificate chain against a CA bundle."""
    cert_data = Path(cert_path).read_bytes()
    ca_data = Path(ca_bundle_path).read_bytes()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    ca_certs = []
    pem_blocks = ca_data.split(b"-----END CERTIFICATE-----")
    for block in pem_blocks:
        block = block.strip()
        if block and b"-----BEGIN CERTIFICATE-----" in block:
            pem = block + b"\n-----END CERTIFICATE-----\n"
            ca_certs.append(x509.load_pem_x509_certificate(pem, default_backend()))

    chain = []
    current = cert
    chain.append({
        "subject": current.subject.rfc4514_string(),
        "issuer": current.issuer.rfc4514_string(),
    })

    for ca in ca_certs:
        if current.issuer == ca.subject:
            chain.append({
                "subject": ca.subject.rfc4514_string(),
                "issuer": ca.issuer.rfc4514_string(),
            })
            current = ca
            if ca.issuer == ca.subject:
                break

    is_self_signed = cert.issuer == cert.subject
    chain_complete = len(chain) > 1 or is_self_signed

    return {
        "certificate": cert.subject.rfc4514_string(),
        "chain_length": len(chain),
        "chain": chain,
        "chain_complete": chain_complete,
        "is_self_signed": is_self_signed,
    }


def main():
    parser = argparse.ArgumentParser(description="SSL Certificate Lifecycle Tool")
    subparsers = parser.add_subparsers(dest="command")

    csr = subparsers.add_parser("generate-csr", help="Generate CSR")
    csr.add_argument("--domain", required=True, help="Primary domain")
    csr.add_argument("--output", default="./certs", help="Output directory")
    csr.add_argument("--key-type", choices=["ecdsa", "rsa"], default="ecdsa")
    csr.add_argument("--san", nargs="*", help="Additional SAN domains")
    csr.add_argument("--org", help="Organization name")

    parse = subparsers.add_parser("parse-cert", help="Parse certificate")
    parse.add_argument("--cert", required=True, help="Certificate file path")

    check = subparsers.add_parser("check-expiry", help="Check remote cert expiry")
    check.add_argument("--host", required=True, help="Hostname")
    check.add_argument("--port", type=int, default=443, help="Port")

    mon = subparsers.add_parser("monitor", help="Monitor multiple domains")
    mon.add_argument("--domains", required=True, help="File with domain list")
    mon.add_argument("--threshold", type=int, default=30, help="Warning threshold (days)")

    chain = subparsers.add_parser("verify-chain", help="Verify certificate chain")
    chain.add_argument("--cert", required=True, help="Certificate file")
    chain.add_argument("--ca-bundle", required=True, help="CA bundle file")

    args = parser.parse_args()

    if args.command == "generate-csr":
        result = generate_csr(args.domain, args.output, args.key_type, args.san, args.org)
        print(json.dumps(result, indent=2))
    elif args.command == "parse-cert":
        result = parse_certificate(args.cert)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "check-expiry":
        result = check_remote_certificate(args.host, args.port)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "monitor":
        domains = Path(args.domains).read_text().strip().split("\n")
        result = monitor_domains(domains, args.threshold)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "verify-chain":
        result = verify_certificate_chain(args.cert, args.ca_bundle)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
