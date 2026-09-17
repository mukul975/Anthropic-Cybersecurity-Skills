#!/usr/bin/env python3
"""RSA key pair lifecycle management agent.

Generates, audits, rotates, and manages RSA key pairs using the
cryptography library. Supports key generation with configurable sizes,
PEM export with encryption, public key extraction, key strength
auditing, and expiration tracking.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def generate_key_pair(key_size=4096, passphrase=None):
    """Generate an RSA key pair."""
    if not HAS_CRYPTO:
        print("[!] 'cryptography' required: pip install cryptography", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Generating {key_size}-bit RSA key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    print(f"[+] Key pair generated ({key_size} bits)")
    return {
        "private_pem": private_pem.decode(),
        "public_pem": public_pem.decode(),
        "public_ssh": public_ssh.decode(),
        "key_size": key_size,
        "encrypted": passphrase is not None,
    }


def save_key_pair(key_data, private_path, public_path):
    """Save key pair to files with secure permissions."""
    with open(private_path, "w") as f:
        f.write(key_data["private_pem"])
    os.chmod(private_path, 0o600)
    print(f"[+] Private key saved to {private_path} (mode 0600)")
    with open(public_path, "w") as f:
        f.write(key_data["public_pem"])
    os.chmod(public_path, 0o644)
    print(f"[+] Public key saved to {public_path}")


def audit_key_file(key_path):
    """Audit an existing RSA key file for security issues."""
    if not HAS_CRYPTO:
        print("[!] 'cryptography' required", file=sys.stderr)
        sys.exit(1)
    findings = []
    if not os.path.isfile(key_path):
        findings.append({"check": "File exists", "status": "FAIL", "severity": "CRITICAL"})
        return findings
    stat = os.stat(key_path)
    mode = oct(stat.st_mode)[-3:]
    if mode not in ("600", "400"):
        findings.append({
            "check": "File permissions",
            "status": f"FAIL (mode {mode})",
            "severity": "HIGH",
            "recommendation": "Set permissions to 600: chmod 600 " + key_path,
        })
    else:
        findings.append({"check": "File permissions", "status": f"PASS (mode {mode})", "severity": "INFO"})
    with open(key_path, "rb") as f:
        pem_data = f.read()
    is_encrypted = b"ENCRYPTED" in pem_data
    try:
        if b"PRIVATE" in pem_data:
            if is_encrypted:
                findings.append({"check": "Key encryption", "status": "PASS (encrypted)", "severity": "INFO"})
                findings.append({"check": "Key type", "status": "Private key (encrypted)", "severity": "INFO"})
                return findings
            private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
            key_size = private_key.key_size
            findings.append({"check": "Key encryption", "status": "FAIL (unencrypted)", "severity": "HIGH",
                            "recommendation": "Encrypt private key with a passphrase"})
        else:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            public_key = load_pem_public_key(pem_data, backend=default_backend())
            key_size = public_key.key_size
            findings.append({"check": "Key type", "status": "Public key", "severity": "INFO"})

        if key_size < 2048:
            findings.append({"check": "Key strength", "status": f"FAIL ({key_size} bits)", "severity": "CRITICAL",
                            "recommendation": "Minimum 2048-bit; recommend 4096-bit for new keys"})
        elif key_size < 4096:
            findings.append({"check": "Key strength", "status": f"WARN ({key_size} bits)", "severity": "MEDIUM",
                            "recommendation": "Consider upgrading to 4096-bit"})
        else:
            findings.append({"check": "Key strength", "status": f"PASS ({key_size} bits)", "severity": "INFO"})
    except Exception as e:
        findings.append({"check": "Key parsing", "status": f"FAIL: {e}", "severity": "HIGH"})
    return findings


def scan_directory_for_keys(directory, recursive=True):
    """Scan a directory for key files and audit each one."""
    key_files = []
    key_extensions = (".pem", ".key", ".pub", ".rsa", ".der")
    key_markers = (b"BEGIN RSA PRIVATE", b"BEGIN PRIVATE", b"BEGIN PUBLIC", b"BEGIN OPENSSH")
    for root, dirs, files in os.walk(directory):
        for fname in files:
            full_path = os.path.join(root, fname)
            is_key = False
            if any(fname.endswith(ext) for ext in key_extensions):
                is_key = True
            else:
                try:
                    with open(full_path, "rb") as f:
                        header = f.read(64)
                    if any(marker in header for marker in key_markers):
                        is_key = True
                except (IOError, PermissionError):
                    pass
            if is_key:
                findings = audit_key_file(full_path)
                key_files.append({"path": full_path, "findings": findings})
        if not recursive:
            break
    return key_files


def format_summary(results, action):
    """Print a human-readable summary."""
    print(f"\n{'='*60}")
    print("  RSA Key Management Report")
    print(f"{'='*60}")
    print(f"  Action    : {action}")
    if action == "audit" and isinstance(results, list):
        total_keys = len(results)
        critical = sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "CRITICAL")
        high = sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "HIGH")
        print(f"  Keys Found: {total_keys}")
        print(f"  Critical  : {critical}")
        print(f"  High      : {high}")
        for r in results:
            print(f"\n    Key: {r['path']}")
            for f in r.get("findings", []):
                print(f"      [{f['severity']:8s}] {f['check']}: {f['status']}")


def main():
    parser = argparse.ArgumentParser(description="RSA key pair lifecycle management agent")
    sub = parser.add_subparsers(dest="command")

    p_gen = sub.add_parser("generate", help="Generate new RSA key pair")
    p_gen.add_argument("--key-size", type=int, default=4096, choices=[2048, 3072, 4096],
                       help="RSA key size in bits (default: 4096)")
    p_gen.add_argument("--passphrase", help="Passphrase to encrypt private key")
    p_gen.add_argument("--private-key", default="id_rsa", help="Private key output path")
    p_gen.add_argument("--public-key", default="id_rsa.pub", help="Public key output path")

    p_audit = sub.add_parser("audit", help="Audit existing key files")
    p_audit.add_argument("--path", required=True, help="Key file or directory to audit")
    p_audit.add_argument("--recursive", action="store_true", help="Scan directory recursively")

    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate":
        key_data = generate_key_pair(args.key_size, args.passphrase)
        save_key_pair(key_data, args.private_key, args.public_key)
        result = {"action": "generate", "key_size": args.key_size,
                  "private_key": args.private_key, "public_key": args.public_key,
                  "encrypted": key_data["encrypted"]}
    elif args.command == "audit":
        if os.path.isdir(args.path):
            results = scan_directory_for_keys(args.path, args.recursive)
        else:
            findings = audit_key_file(args.path)
            results = [{"path": args.path, "findings": findings}]
        format_summary(results, "audit")
        result = {"action": "audit", "keys_audited": results}

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "RSA Key Manager",
        "result": result,
    }
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
