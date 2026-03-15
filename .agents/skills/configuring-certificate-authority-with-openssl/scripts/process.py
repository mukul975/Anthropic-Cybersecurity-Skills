#!/usr/bin/env python3
"""
Certificate Authority Builder using Python cryptography library.

Builds a complete two-tier CA hierarchy (Root CA + Intermediate CA)
and issues server/client certificates programmatically.

Requirements:
    pip install cryptography

Usage:
    python process.py build-ca --output ./pki --org "My Organization"
    python process.py issue-cert --ca-dir ./pki --domain server.example.com --type server
    python process.py revoke --ca-dir ./pki --serial 1001
    python process.py generate-crl --ca-dir ./pki
"""

import os
import sys
import json
import argparse
import logging
import datetime
from pathlib import Path
from typing import Dict, Optional, List

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def generate_key(key_type: str = "rsa", key_size: int = 4096):
    """Generate a private key."""
    if key_type == "ecdsa":
        return ec.generate_private_key(ec.SECP384R1(), default_backend())
    return rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )


def save_key(key, path: Path, passphrase: Optional[str] = None):
    """Save a private key to PEM file."""
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    ))


def save_cert(cert, path: Path):
    """Save a certificate to PEM file."""
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def build_root_ca(
    output_dir: Path,
    organization: str,
    country: str = "US",
    validity_years: int = 20,
) -> Dict:
    """Build a Root CA with self-signed certificate."""
    ca_dir = output_dir / "root-ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "certs").mkdir(exist_ok=True)
    (ca_dir / "private").mkdir(exist_ok=True)

    key = generate_key("rsa", 4096)
    save_key(key, ca_dir / "private" / "root-ca.key")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{organization} Root CA"),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_years * 365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA384(), default_backend())
    )

    save_cert(cert, ca_dir / "certs" / "root-ca.crt")

    # Initialize serial number tracker
    (ca_dir / "serial.json").write_text(json.dumps({"next_serial": 1001}))
    (ca_dir / "index.json").write_text(json.dumps({"certificates": []}))

    logger.info(f"Root CA created: {ca_dir}")
    return {
        "type": "root-ca",
        "subject": subject.rfc4514_string(),
        "key_path": str(ca_dir / "private" / "root-ca.key"),
        "cert_path": str(ca_dir / "certs" / "root-ca.crt"),
        "serial_number": hex(cert.serial_number),
        "valid_until": cert.not_valid_after_utc.isoformat(),
    }


def build_intermediate_ca(
    output_dir: Path,
    organization: str,
    country: str = "US",
    validity_years: int = 10,
) -> Dict:
    """Build an Intermediate CA signed by the Root CA."""
    root_dir = output_dir / "root-ca"
    int_dir = output_dir / "intermediate-ca"
    int_dir.mkdir(parents=True, exist_ok=True)
    (int_dir / "certs").mkdir(exist_ok=True)
    (int_dir / "private").mkdir(exist_ok=True)

    root_key_data = (root_dir / "private" / "root-ca.key").read_bytes()
    root_key = serialization.load_pem_private_key(root_key_data, password=None, backend=default_backend())

    root_cert_data = (root_dir / "certs" / "root-ca.crt").read_bytes()
    root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())

    int_key = generate_key("rsa", 4096)
    save_key(int_key, int_dir / "private" / "intermediate-ca.key")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{organization} Intermediate CA"),
    ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_years * 365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA384(), default_backend())
    )

    save_cert(cert, int_dir / "certs" / "intermediate-ca.crt")

    # Create chain file
    chain = cert.public_bytes(serialization.Encoding.PEM) + root_cert.public_bytes(serialization.Encoding.PEM)
    (int_dir / "certs" / "ca-chain.crt").write_bytes(chain)

    # Initialize serial and index
    (int_dir / "serial.json").write_text(json.dumps({"next_serial": 2001}))
    (int_dir / "index.json").write_text(json.dumps({"certificates": [], "revoked": []}))

    logger.info(f"Intermediate CA created: {int_dir}")
    return {
        "type": "intermediate-ca",
        "subject": subject.rfc4514_string(),
        "key_path": str(int_dir / "private" / "intermediate-ca.key"),
        "cert_path": str(int_dir / "certs" / "intermediate-ca.crt"),
        "chain_path": str(int_dir / "certs" / "ca-chain.crt"),
        "serial_number": hex(cert.serial_number),
        "valid_until": cert.not_valid_after_utc.isoformat(),
    }


def issue_certificate(
    ca_dir: Path,
    domain: str,
    cert_type: str = "server",
    validity_days: int = 365,
    san_domains: Optional[List[str]] = None,
) -> Dict:
    """Issue a certificate from the Intermediate CA."""
    int_dir = ca_dir / "intermediate-ca"

    int_key_data = (int_dir / "private" / "intermediate-ca.key").read_bytes()
    int_key = serialization.load_pem_private_key(int_key_data, password=None, backend=default_backend())

    int_cert_data = (int_dir / "certs" / "intermediate-ca.crt").read_bytes()
    int_cert = x509.load_pem_x509_certificate(int_cert_data, default_backend())

    # Read and update serial
    serial_data = json.loads((int_dir / "serial.json").read_text())
    serial_num = serial_data["next_serial"]
    serial_data["next_serial"] = serial_num + 1
    (int_dir / "serial.json").write_text(json.dumps(serial_data))

    # Generate end-entity key
    ee_key = generate_key("ecdsa")
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    san_list = [x509.DNSName(domain)]
    if san_domains:
        for d in san_domains:
            san_list.append(x509.DNSName(d))

    if cert_type == "server":
        eku = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    elif cert_type == "client":
        eku = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
    else:
        eku = x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(int_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(serial_num)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                key_cert_sign=False, crl_sign=False,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(eku, critical=False)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
            critical=False,
        )
        .sign(int_key, hashes.SHA256(), default_backend())
    )

    certs_dir = int_dir / "certs" / "issued"
    certs_dir.mkdir(exist_ok=True)

    save_key(ee_key, certs_dir / f"{domain}.key")
    save_cert(cert, certs_dir / f"{domain}.crt")

    # Update index
    index_data = json.loads((int_dir / "index.json").read_text())
    index_data["certificates"].append({
        "serial": serial_num,
        "domain": domain,
        "type": cert_type,
        "issued": now.isoformat(),
        "expires": (now + datetime.timedelta(days=validity_days)).isoformat(),
        "status": "valid",
    })
    (int_dir / "index.json").write_text(json.dumps(index_data, indent=2))

    logger.info(f"Issued {cert_type} certificate for {domain} (serial: {serial_num})")
    return {
        "domain": domain,
        "serial": serial_num,
        "type": cert_type,
        "key_path": str(certs_dir / f"{domain}.key"),
        "cert_path": str(certs_dir / f"{domain}.crt"),
        "chain_path": str(int_dir / "certs" / "ca-chain.crt"),
        "valid_until": cert.not_valid_after_utc.isoformat(),
    }


def revoke_certificate(ca_dir: Path, serial: int, reason: str = "unspecified") -> Dict:
    """Revoke a certificate by serial number."""
    int_dir = ca_dir / "intermediate-ca"
    index_data = json.loads((int_dir / "index.json").read_text())

    reason_map = {
        "unspecified": x509.ReasonFlags.unspecified,
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    }

    found = False
    for cert_entry in index_data["certificates"]:
        if cert_entry["serial"] == serial:
            cert_entry["status"] = "revoked"
            cert_entry["revoked_at"] = datetime.datetime.utcnow().isoformat()
            cert_entry["revocation_reason"] = reason
            found = True
            break

    if not found:
        raise ValueError(f"Certificate with serial {serial} not found")

    if "revoked" not in index_data:
        index_data["revoked"] = []

    index_data["revoked"].append({
        "serial": serial,
        "revoked_at": datetime.datetime.utcnow().isoformat(),
        "reason": reason,
    })

    (int_dir / "index.json").write_text(json.dumps(index_data, indent=2))
    logger.info(f"Revoked certificate serial {serial} (reason: {reason})")

    return {"serial": serial, "status": "revoked", "reason": reason}


def generate_crl(ca_dir: Path, validity_days: int = 30) -> Dict:
    """Generate a Certificate Revocation List."""
    int_dir = ca_dir / "intermediate-ca"

    int_key_data = (int_dir / "private" / "intermediate-ca.key").read_bytes()
    int_key = serialization.load_pem_private_key(int_key_data, password=None, backend=default_backend())

    int_cert_data = (int_dir / "certs" / "intermediate-ca.crt").read_bytes()
    int_cert = x509.load_pem_x509_certificate(int_cert_data, default_backend())

    index_data = json.loads((int_dir / "index.json").read_text())

    now = datetime.datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(int_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + datetime.timedelta(days=validity_days))

    reason_map = {
        "unspecified": x509.ReasonFlags.unspecified,
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    }

    for entry in index_data.get("revoked", []):
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(entry["serial"])
            .revocation_date(datetime.datetime.fromisoformat(entry["revoked_at"]))
            .add_extension(
                x509.CRLReason(reason_map.get(entry.get("reason", "unspecified"), x509.ReasonFlags.unspecified)),
                critical=False,
            )
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(int_key, hashes.SHA256(), default_backend())

    crl_path = int_dir / "crl" / "intermediate.crl"
    crl_path.parent.mkdir(exist_ok=True)
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Generated CRL with {len(index_data.get('revoked', []))} revoked certificates")
    return {
        "crl_path": str(crl_path),
        "revoked_count": len(index_data.get("revoked", [])),
        "next_update": (now + datetime.timedelta(days=validity_days)).isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Certificate Authority Builder")
    subparsers = parser.add_subparsers(dest="command")

    build = subparsers.add_parser("build-ca", help="Build complete CA hierarchy")
    build.add_argument("--output", "-o", default="./pki", help="Output directory")
    build.add_argument("--org", required=True, help="Organization name")
    build.add_argument("--country", default="US", help="Country code")

    issue = subparsers.add_parser("issue-cert", help="Issue a certificate")
    issue.add_argument("--ca-dir", required=True, help="CA directory")
    issue.add_argument("--domain", required=True, help="Domain name")
    issue.add_argument("--type", choices=["server", "client", "both"], default="server")
    issue.add_argument("--days", type=int, default=365, help="Validity days")
    issue.add_argument("--san", nargs="*", help="Additional SAN domains")

    rev = subparsers.add_parser("revoke", help="Revoke a certificate")
    rev.add_argument("--ca-dir", required=True, help="CA directory")
    rev.add_argument("--serial", type=int, required=True, help="Serial number")
    rev.add_argument("--reason", default="unspecified", help="Revocation reason")

    crl = subparsers.add_parser("generate-crl", help="Generate CRL")
    crl.add_argument("--ca-dir", required=True, help="CA directory")
    crl.add_argument("--days", type=int, default=30, help="CRL validity days")

    args = parser.parse_args()

    if args.command == "build-ca":
        output = Path(args.output)
        root = build_root_ca(output, args.org, args.country)
        intermediate = build_intermediate_ca(output, args.org, args.country)
        print(json.dumps({"root_ca": root, "intermediate_ca": intermediate}, indent=2))
    elif args.command == "issue-cert":
        result = issue_certificate(
            Path(args.ca_dir), args.domain, args.type, args.days, args.san
        )
        print(json.dumps(result, indent=2))
    elif args.command == "revoke":
        result = revoke_certificate(Path(args.ca_dir), args.serial, args.reason)
        print(json.dumps(result, indent=2))
    elif args.command == "generate-crl":
        result = generate_crl(Path(args.ca_dir), args.days)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
