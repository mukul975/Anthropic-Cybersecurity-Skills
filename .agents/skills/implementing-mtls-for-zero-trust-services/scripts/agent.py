#!/usr/bin/env python3
"""Agent for implementing and auditing mutual TLS between services."""

import os
import ssl
import json
import socket
import argparse
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_ca(common_name="Internal mTLS CA", days_valid=3650):
    """Generate a self-signed CA certificate and key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Team"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def issue_service_cert(ca_key, ca_cert, service_name, san_dns=None, days_valid=365):
    """Issue a service certificate signed by the CA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, service_name),
    ])
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(datetime.utcnow())
               .not_valid_after(datetime.utcnow() + timedelta(days=days_valid))
               .add_extension(x509.ExtendedKeyUsage([
                   ExtendedKeyUsageOID.CLIENT_AUTH,
                   ExtendedKeyUsageOID.SERVER_AUTH,
               ]), critical=False))
    dns_names = [x509.DNSName(service_name)]
    if san_dns:
        dns_names.extend([x509.DNSName(d) for d in san_dns])
    builder = builder.add_extension(
        x509.SubjectAlternativeName(dns_names), critical=False,
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def save_pem(key, cert, key_path, cert_path):
    """Save key and certificate to PEM files."""
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def verify_mtls_endpoint(host, port, ca_cert_path, client_cert_path, client_key_path):
    """Test mTLS connectivity to an endpoint."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(client_cert_path, client_key_path)
    context.load_verify_locations(ca_cert_path)
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                peer_cert = ssock.getpeercert()
                return {
                    "host": host,
                    "port": port,
                    "status": "SUCCESS",
                    "peer_subject": dict(x[0] for x in peer_cert.get("subject", ())),
                    "peer_issuer": dict(x[0] for x in peer_cert.get("issuer", ())),
                    "not_after": peer_cert.get("notAfter", ""),
                    "tls_version": ssock.version(),
                }
    except Exception as e:
        return {"host": host, "port": port, "status": "FAILED", "error": str(e)}


def audit_certificates(cert_dir):
    """Audit all certificates in a directory for expiration and key size."""
    findings = []
    from pathlib import Path
    for cert_path in Path(cert_dir).glob("*.pem"):
        try:
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            days_remaining = (cert.not_valid_after_utc - datetime.utcnow()).days
            key_size = cert.public_key().key_size
            finding = {
                "file": str(cert_path),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_after": str(cert.not_valid_after_utc),
                "days_remaining": days_remaining,
                "key_size": key_size,
                "serial": str(cert.serial_number),
            }
            if days_remaining < 30:
                finding["severity"] = "CRITICAL" if days_remaining < 7 else "HIGH"
            elif key_size < 2048:
                finding["severity"] = "HIGH"
            else:
                finding["severity"] = "OK"
            findings.append(finding)
        except Exception as e:
            findings.append({"file": str(cert_path), "error": str(e)})
    return findings


def main():
    parser = argparse.ArgumentParser(description="mTLS Zero Trust Agent")
    parser.add_argument("--output-dir", default="./certs")
    parser.add_argument("--audit-dir", help="Directory of certs to audit")
    parser.add_argument("--verify-host", help="Host to test mTLS connection")
    parser.add_argument("--verify-port", type=int, default=443)
    parser.add_argument("--output", default="mtls_report.json")
    parser.add_argument("--action", choices=[
        "generate_ca", "issue_cert", "verify", "audit", "full_setup"
    ], default="full_setup")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}
    os.makedirs(args.output_dir, exist_ok=True)

    if args.action in ("generate_ca", "full_setup"):
        ca_key, ca_cert = generate_ca()
        save_pem(ca_key, ca_cert,
                 f"{args.output_dir}/ca-key.pem", f"{args.output_dir}/ca.pem")
        report["results"]["ca"] = {"subject": ca_cert.subject.rfc4514_string()}
        print(f"[+] CA certificate generated")

    if args.action in ("issue_cert", "full_setup"):
        ca_key_path = f"{args.output_dir}/ca-key.pem"
        ca_cert_path = f"{args.output_dir}/ca.pem"
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        services = ["api-gateway", "auth-service", "data-service"]
        for svc in services:
            svc_key, svc_cert = issue_service_cert(ca_key, ca_cert, svc)
            save_pem(svc_key, svc_cert,
                     f"{args.output_dir}/{svc}-key.pem", f"{args.output_dir}/{svc}.pem")
            print(f"[+] Issued certificate for {svc}")

    if args.action in ("audit", "full_setup") and (args.audit_dir or args.output_dir):
        audit_dir = args.audit_dir or args.output_dir
        audit_results = audit_certificates(audit_dir)
        report["results"]["audit"] = audit_results
        expiring = [a for a in audit_results if a.get("severity") in ("CRITICAL", "HIGH")]
        print(f"[+] Audited {len(audit_results)} certs, {len(expiring)} expiring soon")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
