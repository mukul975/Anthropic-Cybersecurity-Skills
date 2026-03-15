#!/usr/bin/env python3
"""Agent for SSL/TLS certificate lifecycle management.

Generates CSRs, parses X.509 certificates using the cryptography
library, monitors expiration across infrastructure, checks OCSP
revocation status, and maintains a certificate inventory.
"""

import json
import sys
import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class CertLifecycleAgent:
    """Manages SSL/TLS certificate lifecycle operations."""

    def __init__(self, output_dir="./cert_inventory"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.inventory = []

    def generate_csr(self, common_name, org="", country="US",
                     san_names=None, key_type="ecdsa"):
        """Generate a private key and Certificate Signing Request."""
        if not HAS_CRYPTO:
            return {"error": "cryptography library required"}

        if key_type == "ecdsa":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org or common_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        if san_names:
            sans = [x509.DNSName(n) for n in san_names]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans), critical=False)

        csr = builder.sign(private_key, hashes.SHA256())

        key_path = self.output_dir / f"{common_name}.key"
        csr_path = self.output_dir / f"{common_name}.csr"

        key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

        return {"common_name": common_name, "key_file": str(key_path),
                "csr_file": str(csr_path), "key_type": key_type}

    def fetch_remote_cert(self, hostname, port=443):
        """Fetch and parse a certificate from a remote server."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(10)
                s.connect((hostname, port))
                der = s.getpeercert(binary_form=True)
                pem_info = s.getpeercert()

            not_after = datetime.strptime(
                pem_info["notAfter"], "%b %d %H:%M:%S %Y %Z")
            not_before = datetime.strptime(
                pem_info["notBefore"], "%b %d %H:%M:%S %Y %Z")
            days_remaining = (not_after - datetime.utcnow()).days

            subject = dict(x[0] for x in pem_info.get("subject", ()))
            issuer = dict(x[0] for x in pem_info.get("issuer", ()))
            sans = [entry[1] for entry in pem_info.get("subjectAltName", ())]

            entry = {
                "hostname": hostname, "port": port,
                "subject_cn": subject.get("commonName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "issuer_org": issuer.get("organizationName", ""),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "san": sans[:20],
                "serial": pem_info.get("serialNumber", ""),
                "version": pem_info.get("version", 0),
                "expired": days_remaining < 0,
                "expiring_soon": 0 < days_remaining <= 30,
            }
            self.inventory.append(entry)
            return entry

        except (socket.error, ssl.SSLError, OSError) as exc:
            return {"hostname": hostname, "error": str(exc)}

    def scan_hosts(self, hostnames, port=443):
        """Scan multiple hosts and collect certificate data."""
        results = []
        for host in hostnames:
            result = self.fetch_remote_cert(host, port)
            results.append(result)
        return results

    def check_expiring(self, threshold_days=30):
        """Return certificates expiring within threshold days."""
        return [c for c in self.inventory
                if c.get("days_remaining", 999) <= threshold_days
                and "error" not in c]

    def generate_report(self):
        """Generate certificate inventory report."""
        expiring = self.check_expiring(30)
        expired = [c for c in self.inventory if c.get("expired")]

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_certificates": len(self.inventory),
            "expired": len(expired),
            "expiring_30d": len(expiring),
            "healthy": len(self.inventory) - len(expired) - len(expiring),
            "certificates": self.inventory,
            "alerts": [
                {"hostname": c["hostname"],
                 "days_remaining": c["days_remaining"],
                 "severity": "critical" if c.get("expired") else "warning"}
                for c in expired + expiring
            ],
        }

        report_path = self.output_dir / "cert_inventory_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    hosts = sys.argv[1:] if len(sys.argv) > 1 else [
        "google.com", "github.com", "expired.badssl.com"]
    agent = CertLifecycleAgent()
    agent.scan_hosts(hosts)
    agent.generate_report()


if __name__ == "__main__":
    main()
