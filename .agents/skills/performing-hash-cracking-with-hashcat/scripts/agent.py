#!/usr/bin/env python3
"""Agent for performing hash cracking with hashcat — hash identification, attack management, and result analysis."""

import json
import argparse
import subprocess
import hashlib
import re
from pathlib import Path
from datetime import datetime


HASH_PATTERNS = {
    "MD5": (r"^[a-f0-9]{32}$", 0),
    "SHA1": (r"^[a-f0-9]{40}$", 100),
    "SHA256": (r"^[a-f0-9]{64}$", 1400),
    "SHA512": (r"^[a-f0-9]{128}$", 1700),
    "NTLM": (r"^[a-f0-9]{32}$", 1000),
    "bcrypt": (r"^\$2[aby]?\$\d+\$.{53}$", 3200),
    "sha512crypt": (r"^\$6\$[^\$]+\$[a-zA-Z0-9./]{86}$", 1800),
    "sha256crypt": (r"^\$5\$[^\$]+\$[a-zA-Z0-9./]{43}$", 7400),
    "md5crypt": (r"^\$1\$[^\$]+\$[a-zA-Z0-9./]{22}$", 500),
    "NetNTLMv2": (r"^[^:]+::\S+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", 5600),
    "Kerberos_TGS": (r"^\$krb5tgs\$", 13100),
    "Kerberos_AS": (r"^\$krb5asrep\$", 18200),
}


def identify_hash(hash_string):
    """Identify hash type and return hashcat mode."""
    candidates = []
    for name, (pattern, mode) in HASH_PATTERNS.items():
        if re.match(pattern, hash_string.strip(), re.IGNORECASE):
            candidates.append({"type": name, "hashcat_mode": mode})
    return {"hash": hash_string[:40] + "..." if len(hash_string) > 40 else hash_string, "candidates": candidates}


def identify_hashes_file(hash_file):
    """Identify hash types from a file of hashes."""
    hashes = Path(hash_file).read_text(encoding="utf-8", errors="replace").strip().splitlines()
    results = []
    for h in hashes[:100]:
        h = h.strip()
        if h:
            results.append(identify_hash(h))
    types = {}
    for r in results:
        for c in r["candidates"]:
            types[c["type"]] = types.get(c["type"], 0) + 1
    return {"total_hashes": len(results), "type_distribution": types, "samples": results[:5]}


def run_hashcat(hash_file, mode, attack="dictionary", wordlist=None, rules=None, mask=None):
    """Execute hashcat with specified attack mode."""
    cmd = ["hashcat", "-m", str(mode), "--quiet", "--potfile-disable", "-o", "/tmp/hashcat_out.txt"]
    if attack == "dictionary":
        if not wordlist:
            return {"error": "wordlist required for dictionary attack"}
        cmd += ["-a", "0", hash_file, wordlist]
        if rules:
            cmd += ["-r", rules]
    elif attack == "brute":
        m = mask or "?a?a?a?a?a?a?a?a"
        cmd += ["-a", "3", hash_file, m]
    elif attack == "combinator":
        if not wordlist:
            return {"error": "two wordlists required (comma-separated)"}
        wl = wordlist.split(",")
        if len(wl) != 2:
            return {"error": "combinator needs two wordlists: list1.txt,list2.txt"}
        cmd += ["-a", "1", hash_file, wl[0], wl[1]]
    else:
        return {"error": f"Unknown attack type: {attack}"}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        cracked = []
        out_file = Path("/tmp/hashcat_out.txt")
        if out_file.exists():
            for line in out_file.read_text().strip().splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    cracked.append({"hash": parts[0][:30] + "...", "plain": parts[1]})
        return {
            "attack": attack, "mode": mode, "cracked_count": len(cracked),
            "cracked": cracked[:50], "return_code": result.returncode,
            "stderr_snippet": result.stderr[:300] if result.stderr else "",
        }
    except FileNotFoundError:
        return {"error": "hashcat not found in PATH"}
    except subprocess.TimeoutExpired:
        return {"error": "hashcat timed out after 3600s"}


def parse_hashcat_status(potfile):
    """Parse hashcat potfile for cracked results."""
    cracked = []
    try:
        for line in Path(potfile).read_text(encoding="utf-8", errors="replace").strip().splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2:
                cracked.append({"hash": parts[0], "plain": parts[1]})
    except FileNotFoundError:
        return {"error": f"Potfile not found: {potfile}"}
    passwords = [c["plain"] for c in cracked]
    length_dist = {}
    for p in passwords:
        l = len(p)
        bucket = f"{l}" if l <= 8 else "9-12" if l <= 12 else "13+"
        length_dist[bucket] = length_dist.get(bucket, 0) + 1
    charset = {"lowercase_only": 0, "uppercase_mixed": 0, "with_digits": 0, "with_special": 0}
    for p in passwords:
        if re.match(r"^[a-z]+$", p):
            charset["lowercase_only"] += 1
        elif re.search(r"\d", p):
            charset["with_digits"] += 1
        elif re.search(r"[!@#$%^&*()_+=\-\[\]{};:'\",.<>?/\\|`~]", p):
            charset["with_special"] += 1
        else:
            charset["uppercase_mixed"] += 1
    return {
        "total_cracked": len(cracked),
        "length_distribution": length_dist,
        "charset_analysis": charset,
        "top_passwords": [p for p, _ in __import__("collections").Counter(passwords).most_common(10)],
    }


def generate_hash(plaintext, algorithm="sha256"):
    """Generate hash of a plaintext string for testing."""
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
    if algorithm not in algos:
        return {"error": f"Unsupported: {algorithm}. Use: {list(algos.keys())}"}
    h = algos[algorithm](plaintext.encode()).hexdigest()
    return {"plaintext": plaintext, "algorithm": algorithm, "hash": h}


def main():
    parser = argparse.ArgumentParser(description="Hashcat Hash Cracking Agent")
    sub = parser.add_subparsers(dest="command")
    i = sub.add_parser("identify", help="Identify hash type")
    i.add_argument("--hash", help="Single hash string")
    i.add_argument("--file", help="File containing hashes")
    c = sub.add_parser("crack", help="Run hashcat")
    c.add_argument("--hash-file", required=True)
    c.add_argument("--mode", type=int, required=True, help="Hashcat mode number")
    c.add_argument("--attack", default="dictionary", choices=["dictionary", "brute", "combinator"])
    c.add_argument("--wordlist", help="Wordlist path (or two comma-separated for combinator)")
    c.add_argument("--rules", help="Hashcat rules file")
    c.add_argument("--mask", help="Brute force mask")
    p = sub.add_parser("parse", help="Parse potfile results")
    p.add_argument("--potfile", required=True)
    g = sub.add_parser("gen", help="Generate test hash")
    g.add_argument("--text", required=True)
    g.add_argument("--algo", default="sha256")
    args = parser.parse_args()
    if args.command == "identify":
        result = identify_hashes_file(args.file) if args.file else identify_hash(args.hash) if args.hash else {"error": "provide --hash or --file"}
    elif args.command == "crack":
        result = run_hashcat(args.hash_file, args.mode, args.attack, args.wordlist, args.rules, args.mask)
    elif args.command == "parse":
        result = parse_hashcat_status(args.potfile)
    elif args.command == "gen":
        result = generate_hash(args.text, args.algo)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
