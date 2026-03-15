#!/usr/bin/env python3
"""
PowerShell Malware Deobfuscation Script

Identifies and removes multiple layers of PowerShell obfuscation
to reveal the underlying malicious payload and extract IOCs.

Requirements:
    pip install regex

Usage:
    python process.py --file obfuscated.ps1 --output deobfuscated.ps1
    python process.py --file obfuscated.ps1 --extract-iocs
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path


class PowerShellDeobfuscator:
    """Multi-layer PowerShell deobfuscation engine."""

    def __init__(self):
        self.layers = []
        self.iocs = {
            "urls": set(),
            "ips": set(),
            "domains": set(),
            "file_paths": set(),
            "registry_keys": set(),
            "suspicious_commands": set(),
        }

    def analyze(self, content):
        """Identify obfuscation techniques present."""
        techniques = []

        checks = [
            (r'-[Ee]nc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}',
             "Base64 EncodedCommand"),
            (r'\[Convert\]::FromBase64String', "FromBase64String"),
            (r"'\s*\+\s*'", "String Concatenation (single-quote)"),
            (r'"\s*\+\s*"', "String Concatenation (double-quote)"),
            (r'\[char\]\s*\d+', "Character Code Casting"),
            (r'\[char\[\]\]\s*\([\d,\s]+\)', "Character Array"),
            (r'`[a-zA-Z]', "Tick-Mark Insertion"),
            (r'Invoke-Expression', "Invoke-Expression"),
            (r'\bIEX\b', "IEX Alias"),
            (r'\|\s*IEX', "Pipeline IEX"),
            (r'IO\.Compression', "Compression Stream"),
            (r'-bxor\s+\d+', "XOR Encoding"),
            (r'\.Replace\(', "Replace Chain"),
            (r'ConvertTo-SecureString', "SecureString"),
            (r'\$env:', "Environment Variable"),
            (r'-f\s+[\'"]', "Format String Operator"),
            (r'New-Object\s+IO\.MemoryStream', "MemoryStream"),
        ]

        for pattern, name in checks:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                techniques.append({"technique": name, "count": len(matches)})

        return techniques

    def deobfuscate(self, content):
        """Apply all deobfuscation layers iteratively."""
        current = content
        iteration = 0

        while iteration < 20:
            previous = current

            # Layer: Remove tick marks
            current = self._remove_ticks(current)

            # Layer: Resolve string concatenation
            current = self._resolve_concat(current)

            # Layer: Decode Base64 EncodedCommand
            current = self._decode_base64_command(current)

            # Layer: Decode FromBase64String calls
            current = self._decode_frombase64(current)

            # Layer: Resolve character arrays
            current = self._resolve_char_arrays(current)

            # Layer: Resolve format strings
            current = self._resolve_format_strings(current)

            # Layer: Decompress streams
            current = self._decompress_streams(current)

            if current == previous:
                break

            self.layers.append({
                "iteration": iteration + 1,
                "length_before": len(previous),
                "length_after": len(current),
            })
            iteration += 1

        # Extract IOCs from final result
        self._extract_iocs(current)

        return current

    def _remove_ticks(self, content):
        """Remove backtick obfuscation."""
        escape_sequences = {'`n', '`r', '`t', '`a', '`b', '`f', '`v', '`0', '``'}
        result = []
        i = 0
        while i < len(content):
            if content[i] == '`' and i + 1 < len(content):
                pair = content[i:i+2]
                if pair in escape_sequences:
                    result.append(pair)
                    i += 2
                else:
                    result.append(content[i+1])
                    i += 2
            else:
                result.append(content[i])
                i += 1
        return ''.join(result)

    def _resolve_concat(self, content):
        """Resolve string concatenation."""
        # Single-quoted concatenation
        pattern = re.compile(r"'([^']*)'\s*\+\s*'([^']*)'")
        while pattern.search(content):
            content = pattern.sub(r"'\1\2'", content)

        # Double-quoted concatenation
        pattern = re.compile(r'"([^"]*)"\s*\+\s*"([^"]*)"')
        while pattern.search(content):
            content = pattern.sub(r'"\1\2"', content)

        return content

    def _decode_base64_command(self, content):
        """Decode -EncodedCommand Base64 arguments."""
        pattern = re.compile(
            r'-[Ee]nc(?:odedcommand)?\s+([A-Za-z0-9+/=]{20,})',
            re.IGNORECASE
        )
        match = pattern.search(content)
        if match:
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-16-le')
                content = pattern.sub(decoded, content)
            except Exception:
                pass
        return content

    def _decode_frombase64(self, content):
        """Decode [Convert]::FromBase64String calls."""
        pattern = re.compile(
            r"\[Convert\]::FromBase64String\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)",
            re.IGNORECASE
        )
        for match in pattern.finditer(content):
            try:
                decoded = base64.b64decode(match.group(1))
                decoded_str = decoded.decode('utf-8', errors='replace')
                content = content.replace(match.group(0), f"'{decoded_str}'")
            except Exception:
                pass
        return content

    def _resolve_char_arrays(self, content):
        """Resolve [char] and [char[]] expressions."""
        # [char]NN patterns
        pattern = re.compile(r'\[char\]\s*(\d+)', re.IGNORECASE)
        for match in pattern.finditer(content):
            try:
                char_val = chr(int(match.group(1)))
                content = content.replace(match.group(0), f"'{char_val}'")
            except (ValueError, OverflowError):
                pass

        return content

    def _resolve_format_strings(self, content):
        """Resolve PowerShell format string operator."""
        pattern = re.compile(
            r"\(?\s*['\"](\{[\d\}{\s]+[^'\"]*)['\"]"
            r"\s*-f\s*([^)]+)\)?",
            re.IGNORECASE
        )
        for match in pattern.finditer(content):
            try:
                fmt_str = match.group(1)
                args_str = match.group(2)
                args = [a.strip().strip("'\"") for a in args_str.split(",")]
                resolved = fmt_str
                for i, arg in enumerate(args):
                    resolved = resolved.replace(f"{{{i}}}", arg)
                content = content.replace(match.group(0), f"'{resolved}'")
            except Exception:
                pass
        return content

    def _decompress_streams(self, content):
        """Attempt to decode compressed Base64 payloads."""
        import zlib
        import io

        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{100,}')
        for match in b64_pattern.finditer(content):
            try:
                raw = base64.b64decode(match.group(0))
                # Try deflate
                decompressed = zlib.decompress(raw, -zlib.MAX_WBITS)
                decoded = decompressed.decode('utf-8', errors='replace')
                if len(decoded) > 50:
                    content = content.replace(match.group(0), decoded)
            except Exception:
                try:
                    # Try gzip
                    raw = base64.b64decode(match.group(0))
                    decompressed = zlib.decompress(raw, zlib.MAX_WBITS | 16)
                    decoded = decompressed.decode('utf-8', errors='replace')
                    if len(decoded) > 50:
                        content = content.replace(match.group(0), decoded)
                except Exception:
                    pass
        return content

    def _extract_iocs(self, content):
        """Extract IOCs from deobfuscated content."""
        # URLs
        for url in re.findall(r'https?://[^\s\'"<>)\]]+', content, re.I):
            self.iocs["urls"].add(url)

        # IPs
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content):
            self.iocs["ips"].add(ip)

        # File paths
        for path in re.findall(
            r'[A-Za-z]:\\[^\s\'"<>|]+', content, re.I
        ):
            self.iocs["file_paths"].add(path)

        # Registry keys
        for key in re.findall(
            r'(?:HKLM|HKCU|HKCR)(?:\\[^\s\'"<>|]+)+', content, re.I
        ):
            self.iocs["registry_keys"].add(key)

        # Suspicious commands
        for cmd in ['DownloadString', 'DownloadFile', 'Invoke-WebRequest',
                     'Start-Process', 'New-ScheduledTask', 'Add-MpPreference',
                     'Reflection.Assembly']:
            if cmd.lower() in content.lower():
                self.iocs["suspicious_commands"].add(cmd)

    def get_report(self):
        """Generate analysis report."""
        return {
            "layers_processed": len(self.layers),
            "layer_details": self.layers,
            "iocs": {k: sorted(v) for k, v in self.iocs.items()},
        }


def main():
    parser = argparse.ArgumentParser(
        description="PowerShell Malware Deobfuscator"
    )
    parser.add_argument("--file", required=True, help="Input PS1 file")
    parser.add_argument("--output", help="Output deobfuscated file")
    parser.add_argument("--extract-iocs", action="store_true",
                        help="Extract IOCs from result")
    parser.add_argument("--report", help="Save JSON report")

    args = parser.parse_args()

    with open(args.file, 'r', errors='replace') as f:
        content = f.read()

    deob = PowerShellDeobfuscator()

    print("[+] Analyzing obfuscation techniques...")
    techniques = deob.analyze(content)
    for t in techniques:
        print(f"  - {t['technique']} ({t['count']} occurrences)")

    print(f"\n[+] Deobfuscating ({len(content)} chars)...")
    result = deob.deobfuscate(content)
    print(f"[+] Result: {len(result)} chars")

    if args.output:
        with open(args.output, 'w') as f:
            f.write(result)
        print(f"[+] Saved to {args.output}")

    report = deob.get_report()
    if args.extract_iocs or args.report:
        print(f"\n[+] Extracted IOCs:")
        for category, values in report["iocs"].items():
            if values:
                print(f"  {category}:")
                for v in values:
                    print(f"    - {v}")

    if args.report:
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.report}")


if __name__ == "__main__":
    main()
