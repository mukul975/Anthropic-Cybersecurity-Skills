# API Reference — Performing Hash Cracking with Hashcat

## Libraries Used
- **subprocess**: Execute hashcat with various attack modes
- **hashlib**: Generate test hashes (MD5, SHA1, SHA256, SHA512)
- **re**: Pattern matching for hash type identification
- **pathlib**: Read hash files and potfiles

## CLI Interface
```
python agent.py identify --hash <hash_string>
python agent.py identify --file hashes.txt
python agent.py crack --hash-file hashes.txt --mode 0 --attack dictionary --wordlist rockyou.txt [--rules best64.rule]
python agent.py crack --hash-file hashes.txt --mode 1000 --attack brute --mask "?u?l?l?l?d?d?d?s"
python agent.py parse --potfile hashcat.potfile
python agent.py gen --text "password123" --algo sha256
```

## Core Functions

### `identify_hash(hash_string)` — Detect hash type and hashcat mode
Matches against 12 patterns: MD5 (0), SHA1 (100), SHA256 (1400), SHA512 (1700),
NTLM (1000), bcrypt (3200), sha512crypt (1800), md5crypt (500), NetNTLMv2 (5600),
Kerberos TGS (13100), Kerberos AS-REP (18200).

### `run_hashcat(hash_file, mode, attack, wordlist, rules, mask)` — Execute hashcat
Attack modes: `dictionary` (-a 0), `brute` (-a 3), `combinator` (-a 1).

### `parse_hashcat_status(potfile)` — Analyze cracked passwords
Returns length distribution, charset analysis, top passwords from potfile.

### `generate_hash(plaintext, algorithm)` — Create test hashes
Supported: md5, sha1, sha256, sha512.

## Hashcat Mask Charsets
- `?l` lowercase, `?u` uppercase, `?d` digits, `?s` special, `?a` all

## Dependencies
System: hashcat (GPU-accelerated hash cracking)
No Python packages required — standard library only.
