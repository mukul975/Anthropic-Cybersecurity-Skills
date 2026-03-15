#!/usr/bin/env python3
"""
TLS 1.3 Configuration and Validation Tool

Implements TLS 1.3 server/client testing, configuration generation,
and vulnerability scanning using Python's ssl module and OpenSSL.

Requirements:
    pip install cryptography

Usage:
    python process.py test-server --host example.com --port 443
    python process.py generate-nginx --domain example.com --cert-path /etc/ssl
    python process.py generate-cert --domain example.com --output ./certs
    python process.py check-ciphers --host example.com
"""

import os
import ssl
import sys
import json
import socket
import argparse
import logging
import subprocess
import datetime
from pathlib import Path
from typing import Optional, Dict, List

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TLS_13_CIPHERS = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

RECOMMENDED_TLS_12_CIPHERS = [
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
]


def test_tls_connection(host: str, port: int = 443, timeout: int = 10) -> Dict:
    """Test TLS connection to a server and report protocol details."""
    results = {
        "host": host,
        "port": port,
        "tls_13_supported": False,
        "tls_12_supported": False,
        "protocol_version": None,
        "cipher_suite": None,
        "certificate": None,
        "issues": [],
    }

    # Test TLS 1.3
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                results["tls_13_supported"] = True
                results["protocol_version"] = ssock.version()
                cipher = ssock.cipher()
                results["cipher_suite"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                }
                cert = ssock.getpeercert()
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber"),
                    "version": cert.get("version"),
                }
                logger.info(f"TLS 1.3 connection successful: {cipher[0]}")
    except ssl.SSLError as e:
        results["issues"].append(f"TLS 1.3 not supported: {e}")
        logger.warning(f"TLS 1.3 not supported on {host}:{port}")
    except Exception as e:
        results["issues"].append(f"Connection error: {e}")

    # Test TLS 1.2
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                results["tls_12_supported"] = True
                if not results["tls_13_supported"]:
                    results["protocol_version"] = ssock.version()
                    cipher = ssock.cipher()
                    results["cipher_suite"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2],
                    }
    except (ssl.SSLError, Exception):
        pass

    # Test deprecated protocols
    for version_name, version_enum in [
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = version_enum
            ctx.maximum_version = version_enum
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results["issues"].append(
                        f"VULNERABLE: {version_name} is still enabled (should be disabled)"
                    )
                    logger.warning(f"{version_name} is enabled on {host}:{port}")
        except (ssl.SSLError, OSError):
            pass

    return results


def check_cipher_suites(host: str, port: int = 443, timeout: int = 10) -> Dict:
    """Check which cipher suites a server supports."""
    results = {"host": host, "port": port, "supported_ciphers": [], "weak_ciphers": []}

    weak_patterns = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                results["negotiated_cipher"] = {
                    "name": cipher[0],
                    "protocol": cipher[1],
                    "bits": cipher[2],
                }
                shared = ssock.shared_ciphers()
                if shared:
                    for c in shared:
                        cipher_info = {"name": c[0], "protocol": c[1], "bits": c[2]}
                        results["supported_ciphers"].append(cipher_info)
                        if any(weak in c[0] for weak in weak_patterns):
                            results["weak_ciphers"].append(cipher_info)
    except Exception as e:
        results["error"] = str(e)

    return results


def generate_self_signed_cert(
    domain: str, output_dir: str, key_type: str = "ecdsa"
) -> Dict:
    """Generate a self-signed TLS certificate for testing."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if key_type == "ecdsa":
        private_key = ec.generate_private_key(ec.SECP256R1())
        key_filename = "server-ecdsa.key"
        cert_filename = "server-ecdsa.crt"
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_filename = "server-rsa.key"
        cert_filename = "server-rsa.crt"

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(domain),
                x509.DNSName(f"*.{domain}"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_path = output_path / key_filename
    cert_path = output_path / cert_filename

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    logger.info(f"Generated {key_type.upper()} certificate for {domain}")
    logger.info(f"  Key:  {key_path}")
    logger.info(f"  Cert: {cert_path}")

    return {
        "domain": domain,
        "key_type": key_type,
        "key_path": str(key_path),
        "cert_path": str(cert_path),
        "valid_days": 365,
    }


def generate_nginx_config(
    domain: str, cert_path: str, key_path: str, enable_tls12: bool = True
) -> str:
    """Generate nginx TLS 1.3 configuration."""
    tls_protocols = "TLSv1.3"
    if enable_tls12:
        tls_protocols = "TLSv1.2 TLSv1.3"

    tls12_ciphers = ":".join(RECOMMENDED_TLS_12_CIPHERS)

    config = f"""# TLS 1.3 Optimized nginx Configuration
# Generated for: {domain}
# Mozilla SSL Configuration Generator: Modern profile

server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain};

    # Certificate paths
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};

    # Protocol versions
    ssl_protocols {tls_protocols};

    # TLS 1.2 cipher suites (TLS 1.3 ciphers are configured automatically)
    ssl_ciphers '{tls12_ciphers}';
    ssl_prefer_server_ciphers off;

    # ECDH curve
    ssl_ecdh_curve X25519:secp256r1:secp384r1;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # Session configuration
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Root and index
    root /var/www/{domain}/html;
    index index.html;

    location / {{
        try_files $uri $uri/ =404;
    }}
}}

# HTTP to HTTPS redirect
server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}
"""
    return config


def generate_apache_config(
    domain: str, cert_path: str, key_path: str, enable_tls12: bool = True
) -> str:
    """Generate Apache TLS 1.3 configuration."""
    tls_protocols = "TLSv1.3"
    if enable_tls12:
        tls_protocols = "TLSv1.2 TLSv1.3"

    tls12_ciphers = ":".join(RECOMMENDED_TLS_12_CIPHERS)

    config = f"""# TLS 1.3 Optimized Apache Configuration
# Generated for: {domain}

<VirtualHost *:443>
    ServerName {domain}
    DocumentRoot /var/www/{domain}/html

    SSLEngine on
    SSLCertificateFile {cert_path}
    SSLCertificateKeyFile {key_path}

    # Protocol versions
    SSLProtocol all -{" -".join(["SSLv3", "TLSv1", "TLSv1.1"])}
    {"" if enable_tls12 else "SSLProtocol TLSv1.3"}

    # Cipher suites
    SSLCipherSuite {tls12_ciphers}
    SSLHonorCipherOrder off

    # OCSP Stapling
    SSLUseStapling on
    SSLStaplingCache shmcb:/var/run/ocsp(128000)

    # Security headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
</VirtualHost>

# HTTP to HTTPS redirect
<VirtualHost *:80>
    ServerName {domain}
    Redirect permanent / https://{domain}/
</VirtualHost>
"""
    return config


def main():
    parser = argparse.ArgumentParser(description="TLS 1.3 Configuration Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Test server
    test = subparsers.add_parser("test-server", help="Test TLS configuration of a server")
    test.add_argument("--host", required=True, help="Server hostname")
    test.add_argument("--port", type=int, default=443, help="Server port")

    # Check ciphers
    ciphers = subparsers.add_parser("check-ciphers", help="Check supported cipher suites")
    ciphers.add_argument("--host", required=True, help="Server hostname")
    ciphers.add_argument("--port", type=int, default=443, help="Server port")

    # Generate certificate
    cert = subparsers.add_parser("generate-cert", help="Generate self-signed certificate")
    cert.add_argument("--domain", required=True, help="Domain name")
    cert.add_argument("--output", default="./certs", help="Output directory")
    cert.add_argument("--key-type", choices=["ecdsa", "rsa"], default="ecdsa")

    # Generate nginx config
    nginx = subparsers.add_parser("generate-nginx", help="Generate nginx TLS config")
    nginx.add_argument("--domain", required=True, help="Domain name")
    nginx.add_argument("--cert-path", required=True, help="Certificate file path")
    nginx.add_argument("--key-path", required=True, help="Private key file path")
    nginx.add_argument("--tls12", action="store_true", default=True, help="Enable TLS 1.2")

    # Generate Apache config
    apache = subparsers.add_parser("generate-apache", help="Generate Apache TLS config")
    apache.add_argument("--domain", required=True, help="Domain name")
    apache.add_argument("--cert-path", required=True, help="Certificate file path")
    apache.add_argument("--key-path", required=True, help="Private key file path")

    args = parser.parse_args()

    if args.command == "test-server":
        result = test_tls_connection(args.host, args.port)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "check-ciphers":
        result = check_cipher_suites(args.host, args.port)
        print(json.dumps(result, indent=2))
    elif args.command == "generate-cert":
        result = generate_self_signed_cert(args.domain, args.output, args.key_type)
        print(json.dumps(result, indent=2))
    elif args.command == "generate-nginx":
        config = generate_nginx_config(args.domain, args.cert_path, args.key_path, args.tls12)
        print(config)
    elif args.command == "generate-apache":
        config = generate_apache_config(args.domain, args.cert_path, args.key_path)
        print(config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
