#!/usr/bin/env python3
"""Agent for reverse engineering Rust-compiled malware.

Identifies Rust binaries, extracts crate dependencies, locates
crypto/network/persistence patterns, and maps suspicious capabilities
for malware analysis reporting.
"""

import json
import re
import struct
import sys
import hashlib
from pathlib import Path
from datetime import datetime


SUSPICIOUS_CRATES = {
    "reqwest": "HTTP client (C2 communication)",
    "hyper": "HTTP library (C2/exfiltration)",
    "tokio": "Async runtime (concurrent operations)",
    "aes": "AES encryption (ransomware/data theft)",
    "chacha20": "ChaCha20 cipher (ransomware)",
    "rsa": "RSA encryption (key exchange)",
    "ring": "Crypto library (encryption)",
    "base64": "Base64 encoding (data encoding)",
    "winapi": "Windows API (system interaction)",
    "winreg": "Registry access (persistence)",
    "sysinfo": "System enumeration",
    "screenshots": "Screen capture (spyware)",
    "clipboard": "Clipboard access (data theft)",
    "rusqlite": "SQLite access (credential theft)",
    "native-tls": "TLS connections (encrypted C2)",
}


class RustMalwareREAgent:
    """Reverse engineers Rust-compiled malware binaries."""

    def __init__(self, sample_path, output_dir="./rust_re"):
        self.sample_path = Path(sample_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.data = b""

    def load_sample(self):
        self.data = self.sample_path.read_bytes()
        return len(self.data)

    def identify_rust_binary(self):
        """Check if binary is Rust-compiled and extract version info."""
        indicators = {
            "panicked_at": bool(re.search(rb"panicked at", self.data)),
            "unwrap_none": bool(re.search(rb"called.*unwrap.*on.*None", self.data)),
            "core_panic": bool(re.search(rb"core::panicking", self.data)),
            "std_rt": bool(re.search(rb"std::rt::lang_start", self.data)),
            "cargo_registry": bool(re.search(rb"\.cargo[/\\]registry", self.data)),
            "rustc_version": None,
        }
        ver = re.search(rb"rustc\s+(\d+\.\d+\.\d+)", self.data)
        if ver:
            indicators["rustc_version"] = ver.group(1).decode()
        is_rust = sum(1 for v in indicators.values() if v) >= 2
        if is_rust:
            self.findings.append({
                "type": "Binary Identification",
                "detail": "Rust-compiled binary confirmed",
                "rustc_version": indicators["rustc_version"],
            })
        return is_rust, indicators

    def extract_crates(self):
        """Extract crate dependencies from binary strings."""
        pattern = re.compile(
            rb"(?:crates\.io-[a-f0-9]+/|\.cargo/registry/src/[^/]+/)"
            rb"([\w-]+)-(\d+\.\d+\.\d+)"
        )
        crates = {}
        for m in pattern.finditer(self.data):
            crates[m.group(1).decode()] = m.group(2).decode()

        capabilities = []
        for name, desc in SUSPICIOUS_CRATES.items():
            if name in crates:
                capabilities.append({
                    "crate": name,
                    "version": crates[name],
                    "capability": desc,
                })
                self.findings.append({
                    "type": "Suspicious Crate",
                    "crate": name,
                    "capability": desc,
                })
        return crates, capabilities

    def extract_suspicious_strings(self):
        """Extract malware-relevant strings from the binary."""
        keywords = [
            "http", "socket", "encrypt", "decrypt", "shell", "exec",
            "cmd", "upload", "download", "persist", "registry", "mutex",
            "pipe", "inject", "ransom", "bitcoin", "wallet", "onion",
            "tor", "password", "credential", "keylog",
        ]
        strings = []
        for m in re.finditer(rb"[\x20-\x7e]{8,500}", self.data):
            s = m.group().decode("ascii")
            if any(kw in s.lower() for kw in keywords):
                strings.append(s)
        return strings[:50]

    def detect_pe_sections(self):
        """Parse PE sections if Windows binary."""
        if self.data[:2] != b"MZ":
            return []
        try:
            pe_offset = struct.unpack_from("<I", self.data, 0x3C)[0]
            if self.data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return []
            num_sections = struct.unpack_from("<H", self.data, pe_offset + 6)[0]
            sections = []
            sec_start = pe_offset + 24 + struct.unpack_from("<H", self.data, pe_offset + 20)[0]
            for i in range(min(num_sections, 20)):
                off = sec_start + i * 40
                name = self.data[off:off + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
                vsize = struct.unpack_from("<I", self.data, off + 8)[0]
                rsize = struct.unpack_from("<I", self.data, off + 16)[0]
                sections.append({"name": name, "virtual_size": vsize, "raw_size": rsize})
            return sections
        except (struct.error, IndexError):
            return []

    def generate_report(self):
        size = self.load_sample()
        sha256 = hashlib.sha256(self.data).hexdigest()
        is_rust, rust_indicators = self.identify_rust_binary()
        crates, capabilities = self.extract_crates()
        strings = self.extract_suspicious_strings()
        sections = self.detect_pe_sections()

        report = {
            "sample": str(self.sample_path),
            "sha256": sha256,
            "file_size": size,
            "report_date": datetime.utcnow().isoformat(),
            "is_rust_binary": is_rust,
            "rust_indicators": rust_indicators,
            "crates_found": len(crates),
            "crates": crates,
            "suspicious_capabilities": capabilities,
            "suspicious_strings_count": len(strings),
            "suspicious_strings": strings[:20],
            "pe_sections": sections,
            "findings": self.findings,
        }
        out = self.output_dir / "rust_re_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <rust_binary_path>")
        sys.exit(1)
    agent = RustMalwareREAgent(sys.argv[1])
    agent.generate_report()


if __name__ == "__main__":
    main()
