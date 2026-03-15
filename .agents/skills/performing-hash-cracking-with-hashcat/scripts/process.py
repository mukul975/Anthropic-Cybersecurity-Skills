#!/usr/bin/env python3
"""
Hash Cracking Analysis and Hashcat Automation Tool

Provides hash identification, hashcat command generation, result analysis,
and password strength reporting for authorized security assessments.

Requirements:
    pip install passlib argon2-cffi

Usage:
    python process.py identify --hash "5f4dcc3b5aa765d61d8327deb882cf99"
    python process.py generate-cmd --hash-file hashes.txt --mode 0 --attack dictionary
    python process.py analyze-results --potfile hashcat.potfile --hash-file hashes.txt
    python process.py create-test-hashes --output test_hashes.txt
"""

import os
import re
import sys
import json
import hashlib
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

HASH_PATTERNS = {
    r"^[a-f0-9]{32}$": [("MD5", 0), ("NTLM", 1000)],
    r"^[a-f0-9]{40}$": [("SHA-1", 100)],
    r"^[a-f0-9]{64}$": [("SHA-256", 1400)],
    r"^[a-f0-9]{128}$": [("SHA-512", 1700)],
    r"^\$2[aby]\$\d{2}\$.{53}$": [("bcrypt", 3200)],
    r"^\$6\$": [("sha512crypt", 1800)],
    r"^\$5\$": [("sha256crypt", 7400)],
    r"^\$argon2(i|d|id)\$": [("Argon2", 32600)],
    r"^\$1\$": [("md5crypt", 500)],
    r"^\$apr1\$": [("Apache APR1", 1600)],
    r"^[a-f0-9]{32}:[a-f0-9]+$": [("MD5 salted", 10)],
    r"^\$krb5tgs\$": [("Kerberos TGS-REP", 13100)],
    r"^[a-f0-9]{32}:[a-f0-9]{32}$": [("NetNTLMv1", 5500)],
}


def identify_hash(hash_value: str) -> List[Dict]:
    """Identify the type of a hash value."""
    hash_value = hash_value.strip()
    matches = []

    for pattern, hash_types in HASH_PATTERNS.items():
        if re.match(pattern, hash_value, re.IGNORECASE):
            for name, mode in hash_types:
                matches.append({
                    "hash_type": name,
                    "hashcat_mode": mode,
                    "confidence": "high" if len(hash_types) == 1 else "medium",
                })

    if not matches:
        matches.append({
            "hash_type": "Unknown",
            "hashcat_mode": None,
            "confidence": "none",
        })

    return matches


def generate_hashcat_command(
    hash_file: str,
    mode: int,
    attack: str = "dictionary",
    wordlist: str = "rockyou.txt",
    rules: Optional[str] = None,
    mask: Optional[str] = None,
    output_file: Optional[str] = None,
) -> str:
    """Generate a hashcat command string."""
    cmd_parts = ["hashcat"]
    cmd_parts.extend(["-m", str(mode)])

    if attack == "dictionary":
        cmd_parts.extend(["-a", "0"])
        cmd_parts.append(hash_file)
        cmd_parts.append(wordlist)
        if rules:
            cmd_parts.extend(["-r", rules])
    elif attack == "bruteforce":
        cmd_parts.extend(["-a", "3"])
        cmd_parts.append(hash_file)
        cmd_parts.append(mask or "?a?a?a?a?a?a?a?a")
    elif attack == "hybrid_wm":
        cmd_parts.extend(["-a", "6"])
        cmd_parts.append(hash_file)
        cmd_parts.append(wordlist)
        cmd_parts.append(mask or "?d?d?d?d")
    elif attack == "hybrid_mw":
        cmd_parts.extend(["-a", "7"])
        cmd_parts.append(hash_file)
        cmd_parts.append(mask or "?d?d?d?d")
        cmd_parts.append(wordlist)

    if output_file:
        cmd_parts.extend(["-o", output_file])

    cmd_parts.extend(["--force", "--status", "--status-timer=10"])
    return " ".join(cmd_parts)


def create_test_hashes(output_path: str) -> Dict:
    """Create a set of test password hashes for practice."""
    test_passwords = [
        "password", "123456", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "qwerty", "login",
        "P@ssw0rd", "Summer2024!", "company123", "test1234",
        "hunter2", "trustno1", "batman", "shadow", "sunshine",
        "iloveyou",
    ]

    hashes = {"md5": [], "sha1": [], "sha256": []}
    for pwd in test_passwords:
        pwd_bytes = pwd.encode("utf-8")
        hashes["md5"].append(hashlib.md5(pwd_bytes).hexdigest())
        hashes["sha1"].append(hashlib.sha1(pwd_bytes).hexdigest())
        hashes["sha256"].append(hashlib.sha256(pwd_bytes).hexdigest())

    output = Path(output_path)
    for hash_type, hash_list in hashes.items():
        path = output.parent / f"{output.stem}_{hash_type}{output.suffix}"
        path.write_text("\n".join(hash_list) + "\n")
        logger.info(f"Created {path} with {len(hash_list)} hashes")

    return {
        "test_passwords_count": len(test_passwords),
        "hash_types": list(hashes.keys()),
        "output_directory": str(output.parent),
        "note": "These are intentionally weak passwords for authorized testing only",
    }


def analyze_cracked_results(potfile_path: str, hash_file_path: str) -> Dict:
    """Analyze hashcat results from potfile."""
    potfile = Path(potfile_path)
    hash_file = Path(hash_file_path)

    if not potfile.exists():
        return {"error": f"Potfile not found: {potfile_path}"}

    total_hashes = 0
    if hash_file.exists():
        total_hashes = sum(1 for line in hash_file.read_text().strip().split("\n") if line.strip())

    cracked_passwords = []
    for line in potfile.read_text().strip().split("\n"):
        if ":" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                cracked_passwords.append(parts[1])

    cracked_count = len(cracked_passwords)
    crack_rate = (cracked_count / total_hashes * 100) if total_hashes > 0 else 0

    # Password analysis
    lengths = [len(p) for p in cracked_passwords]
    charset_analysis = {"lowercase_only": 0, "with_uppercase": 0, "with_digits": 0, "with_special": 0}

    for pwd in cracked_passwords:
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)
        if has_special:
            charset_analysis["with_special"] += 1
        elif has_digit and has_upper:
            charset_analysis["with_digits"] += 1
        elif has_upper:
            charset_analysis["with_uppercase"] += 1
        else:
            charset_analysis["lowercase_only"] += 1

    # Strength categories
    strength = {"critical": 0, "weak": 0, "moderate": 0}
    for pwd in cracked_passwords:
        if len(pwd) < 8:
            strength["critical"] += 1
        elif len(pwd) < 12 or not any(not c.isalnum() for c in pwd):
            strength["weak"] += 1
        else:
            strength["moderate"] += 1

    common_words = Counter()
    for pwd in cracked_passwords:
        base = re.sub(r"[^a-zA-Z]", "", pwd).lower()
        if len(base) >= 3:
            common_words[base] += 1

    return {
        "total_hashes": total_hashes,
        "cracked_count": cracked_count,
        "crack_rate_percent": round(crack_rate, 1),
        "uncracked_count": total_hashes - cracked_count,
        "password_length": {
            "min": min(lengths) if lengths else 0,
            "max": max(lengths) if lengths else 0,
            "avg": round(sum(lengths) / len(lengths), 1) if lengths else 0,
        },
        "charset_distribution": charset_analysis,
        "strength_distribution": strength,
        "top_base_words": dict(common_words.most_common(10)),
        "recommendations": [
            "Enforce minimum 12-character passwords",
            "Require mixed character sets (upper, lower, digit, special)",
            "Block common dictionary words and patterns",
            "Implement password breach checking (Have I Been Pwned API)",
            "Use Argon2id or bcrypt for password hashing (not MD5/SHA)",
            "Consider passphrase-based policies over complexity rules",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Hash Cracking Analysis Tool")
    subparsers = parser.add_subparsers(dest="command")

    ident = subparsers.add_parser("identify", help="Identify hash type")
    ident.add_argument("--hash", required=True, help="Hash value to identify")

    gen = subparsers.add_parser("generate-cmd", help="Generate hashcat command")
    gen.add_argument("--hash-file", required=True, help="Hash file path")
    gen.add_argument("--mode", type=int, required=True, help="Hashcat hash mode")
    gen.add_argument("--attack", choices=["dictionary", "bruteforce", "hybrid_wm", "hybrid_mw"], default="dictionary")
    gen.add_argument("--wordlist", default="rockyou.txt")
    gen.add_argument("--rules", help="Rules file")
    gen.add_argument("--mask", help="Mask pattern")

    create = subparsers.add_parser("create-test-hashes", help="Create test hashes")
    create.add_argument("--output", "-o", default="test_hashes.txt")

    analyze = subparsers.add_parser("analyze-results", help="Analyze cracking results")
    analyze.add_argument("--potfile", required=True, help="Hashcat potfile")
    analyze.add_argument("--hash-file", required=True, help="Original hash file")

    args = parser.parse_args()

    if args.command == "identify":
        result = identify_hash(args.hash)
        print(json.dumps(result, indent=2))
    elif args.command == "generate-cmd":
        cmd = generate_hashcat_command(args.hash_file, args.mode, args.attack, args.wordlist, args.rules, args.mask)
        print(cmd)
    elif args.command == "create-test-hashes":
        result = create_test_hashes(args.output)
        print(json.dumps(result, indent=2))
    elif args.command == "analyze-results":
        result = analyze_cracked_results(args.potfile, args.hash_file)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
