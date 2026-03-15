#!/usr/bin/env python3
"""Agent for reverse engineering ransomware encryption routines.

Identifies encryption algorithms, extracts key material from
memory dumps or binary analysis, detects IV/nonce patterns,
and documents the cryptographic implementation for decryptor
development.
"""

import json
import sys
import re
import struct
import hashlib
from pathlib import Path
from datetime import datetime


CRYPTO_CONSTANTS = {
    "AES S-Box": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
    "AES Inv S-Box": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38]),
    "RSA Marker": b"\x30\x82",
    "ChaCha20 Constant": b"expand 32-byte k",
    "Salsa20 Constant": b"expand 32-byte k",
    "RC4 State Init": bytes(range(8)),
    "SHA256 Init H0": struct.pack(">I", 0x6a09e667),
}

RANSOMWARE_PATTERNS = {
    "file_extension_change": re.compile(rb'\.\w{3,10}(?=\x00)'),
    "ransom_note_name": re.compile(rb'(?:README|RECOVER|DECRYPT|HOW.TO)[\w.-]*\.(?:txt|html|hta)', re.I),
    "bitcoin_address": re.compile(rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'),
    "onion_url": re.compile(rb'[\w]{16,56}\.onion'),
    "email_address": re.compile(rb'[\w.+-]+@[\w-]+\.[\w.]{2,}'),
}


class RansomwareREAgent:
    """Analyzes ransomware encryption implementation."""

    def __init__(self, sample_path, output_dir="./ransomware_re"):
        self.sample_path = Path(sample_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def identify_crypto_algorithms(self):
        """Scan binary for cryptographic algorithm constants."""
        data = self.sample_path.read_bytes()
        detected = []

        for name, constant in CRYPTO_CONSTANTS.items():
            offset = data.find(constant)
            if offset != -1:
                detected.append({
                    "algorithm": name,
                    "offset": hex(offset),
                    "context": data[max(0, offset - 16):offset + len(constant) + 16].hex(),
                })
                self.findings.append({
                    "type": "Crypto Algorithm Detected",
                    "algorithm": name, "offset": hex(offset),
                })
        return detected

    def extract_encryption_indicators(self):
        """Extract ransomware-specific indicators from the binary."""
        data = self.sample_path.read_bytes()
        indicators = {}

        for name, pattern in RANSOMWARE_PATTERNS.items():
            matches = pattern.findall(data)
            if matches:
                decoded = []
                for m in matches[:10]:
                    try:
                        decoded.append(m.decode("utf-8", errors="ignore"))
                    except (UnicodeDecodeError, AttributeError):
                        decoded.append(m.hex())
                indicators[name] = decoded

        return indicators

    def analyze_encrypted_file(self, encrypted_path, original_path=None):
        """Analyze an encrypted file to determine encryption characteristics."""
        enc_data = Path(encrypted_path).read_bytes()
        analysis = {
            "file_size": len(enc_data),
            "entropy": self._calculate_entropy(enc_data),
            "header_bytes": enc_data[:64].hex(),
            "footer_bytes": enc_data[-64:].hex() if len(enc_data) > 64 else "",
        }

        if analysis["entropy"] > 7.9:
            analysis["encryption_type"] = "Full file encryption"
        elif analysis["entropy"] > 6.0:
            analysis["encryption_type"] = "Partial/intermittent encryption"
        else:
            analysis["encryption_type"] = "Possibly not encrypted or header-only"

        if original_path and Path(original_path).exists():
            orig_data = Path(original_path).read_bytes()
            analysis["size_difference"] = len(enc_data) - len(orig_data)
            if analysis["size_difference"] > 0:
                analysis["appended_bytes"] = analysis["size_difference"]
                analysis["footer_metadata"] = enc_data[len(orig_data):len(orig_data) + 128].hex()

        return analysis

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        import math
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_key_material(self, memory_dump_path=None):
        """Search for potential encryption key material."""
        search_data = (Path(memory_dump_path).read_bytes()
                       if memory_dump_path else self.sample_path.read_bytes())
        potential_keys = []

        for offset in range(0, min(len(search_data), 10_000_000), 16):
            block = search_data[offset:offset + 32]
            if len(block) < 16:
                break
            entropy = self._calculate_entropy(block)
            if entropy > 4.5 and all(b != 0 for b in block[:16]):
                if not all(b == block[0] for b in block[:16]):
                    potential_keys.append({
                        "offset": hex(offset),
                        "length": len(block),
                        "entropy": entropy,
                        "sha256": hashlib.sha256(block).hexdigest()[:16],
                    })
            if len(potential_keys) >= 50:
                break

        return potential_keys[:20]

    def generate_report(self):
        crypto = self.identify_crypto_algorithms()
        indicators = self.extract_encryption_indicators()
        sha256 = hashlib.sha256(self.sample_path.read_bytes()).hexdigest()

        report = {
            "sample": str(self.sample_path),
            "sha256": sha256,
            "report_date": datetime.utcnow().isoformat(),
            "crypto_algorithms": crypto,
            "ransomware_indicators": indicators,
            "findings": self.findings,
        }
        report_path = self.output_dir / "ransomware_re_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <sample_path> [encrypted_file] [original_file]")
        sys.exit(1)
    agent = RansomwareREAgent(sys.argv[1])
    agent.generate_report()
    if len(sys.argv) > 2:
        orig = sys.argv[3] if len(sys.argv) > 3 else None
        analysis = agent.analyze_encrypted_file(sys.argv[2], orig)
        print(json.dumps(analysis, indent=2))


if __name__ == "__main__":
    main()
