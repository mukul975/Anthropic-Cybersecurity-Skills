#!/usr/bin/env python3
"""
Malware IOC Extraction Script

Performs static analysis on PE files to extract IOCs:
- File hash generation (MD5, SHA-1, SHA-256, imphash)
- PE header parsing and section analysis
- String extraction with IOC pattern matching
- YARA rule scanning
- STIX 2.1 bundle generation

Requirements:
    pip install pefile yara-python stix2 requests

Usage:
    python process.py --file malware.exe --output iocs.json
    python process.py --file malware.exe --yara-rules rules/ --stix-output bundle.json
    python process.py --file malware.exe --vt-check --vt-key YOUR_KEY
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime
from typing import Optional

try:
    import pefile
except ImportError:
    pefile = None

try:
    import yara
except ImportError:
    yara = None


class MalwareIOCExtractor:
    """Extract IOCs from malware samples via static analysis."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)

        with open(filepath, "rb") as f:
            self.data = f.read()

        self.hashes = self._calculate_hashes()
        self.iocs = {
            "file": {"name": self.filename, "size": len(self.data)},
            "hashes": self.hashes,
            "pe_info": {},
            "network_iocs": {},
            "host_iocs": {},
            "yara_matches": [],
            "suspicious_strings": [],
        }

    def _calculate_hashes(self) -> dict:
        return {
            "md5": hashlib.md5(self.data).hexdigest(),
            "sha1": hashlib.sha1(self.data).hexdigest(),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }

    def analyze_pe(self):
        """Parse PE file structure and extract metadata IOCs."""
        if pefile is None:
            print("[-] pefile not installed, skipping PE analysis")
            return

        try:
            pe = pefile.PE(data=self.data)
        except pefile.PEFormatError:
            print("[-] Not a valid PE file")
            return

        self.iocs["hashes"]["imphash"] = pe.get_imphash()

        # Compilation timestamp
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.utcfromtimestamp(timestamp).isoformat()
        except (OSError, ValueError):
            compile_time = f"invalid ({timestamp})"

        self.iocs["pe_info"] = {
            "compile_time": compile_time,
            "machine": hex(pe.FILE_HEADER.Machine),
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [],
            "imports": [],
            "exports": [],
        }

        # Section analysis
        for section in pe.sections:
            name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            entropy = section.get_entropy()
            self.iocs["pe_info"]["sections"].append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "suspicious": entropy > 7.0,
                "md5": hashlib.md5(section.get_data()).hexdigest(),
            })

        # Import table
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="ignore"))
                self.iocs["pe_info"]["imports"].append({
                    "dll": dll,
                    "functions": funcs,
                })

        # Suspicious API imports
        suspicious_apis = {
            "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
            "WriteProcessMemory", "NtUnmapViewOfSection", "IsDebuggerPresent",
            "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
            "URLDownloadToFileA", "InternetOpenA", "HttpSendRequestA",
            "WinExec", "ShellExecuteA", "CreateProcessA",
            "RegSetValueExA", "CryptEncrypt", "CryptDecrypt",
        }

        found_suspicious = set()
        for imp_entry in self.iocs["pe_info"]["imports"]:
            for func in imp_entry["functions"]:
                if func in suspicious_apis:
                    found_suspicious.add(func)

        self.iocs["pe_info"]["suspicious_apis"] = sorted(found_suspicious)

        # Export table
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    self.iocs["pe_info"]["exports"].append(
                        exp.name.decode("utf-8", errors="ignore")
                    )

        pe.close()

    def extract_strings(self, min_length: int = 4):
        """Extract and classify strings from the binary."""
        patterns = {
            "ipv4": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            "domain": re.compile(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                r"(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|ws|pw|"
                r"onion|bit|me|co|uk|de|fr|jp|kr|br)\b"
            ),
            "url": re.compile(r"https?://[^\s\"'<>\x00]{5,200}"),
            "email": re.compile(
                r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
            ),
            "registry": re.compile(
                r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)"
                r"\\[\\a-zA-Z0-9_ .{}\-]+"
            ),
            "filepath": re.compile(
                r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n\x00]+\\)*[^\\/:*?\"<>|\r\n\x00]+"
            ),
            "mutex": re.compile(r"(?:Global\\|Local\\)[a-zA-Z0-9_\-{}.]{4,}"),
            "useragent": re.compile(r"Mozilla/[45]\.0[^\"'\x00]{10,200}"),
            "pdb_path": re.compile(r"[A-Z]:\\[^\x00\"]{5,200}\.pdb"),
            "bitcoin_wallet": re.compile(
                r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
            ),
        }

        # Extract ASCII strings
        ascii_regex = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        ascii_strings = [
            s.decode("ascii", errors="ignore")
            for s in ascii_regex.findall(self.data)
        ]

        # Extract Unicode strings
        unicode_regex = re.compile(
            rb"(?:[\x20-\x7e]\x00){%d,}" % min_length
        )
        unicode_strings = [
            s.decode("utf-16-le", errors="ignore")
            for s in unicode_regex.findall(self.data)
        ]

        all_strings = ascii_strings + unicode_strings

        network_iocs = {"ipv4": set(), "domain": set(), "url": set(), "email": set()}
        host_iocs = {"registry": set(), "filepath": set(), "mutex": set()}
        other = {"useragent": set(), "pdb_path": set(), "bitcoin_wallet": set()}

        for string in all_strings:
            for category, pattern in patterns.items():
                for match in pattern.findall(string):
                    if category in network_iocs:
                        network_iocs[category].add(match)
                    elif category in host_iocs:
                        host_iocs[category].add(match)
                    else:
                        other[category].add(match)

        # Filter private IPs
        private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.", "127.", "0.", "255.")
        network_iocs["ipv4"] = {
            ip for ip in network_iocs["ipv4"]
            if not ip.startswith(private_prefixes)
        }

        # Filter common benign domains
        benign_domains = {
            "microsoft.com", "windows.com", "google.com", "w3.org",
            "xmlsoap.org", "openxmlformats.org", "schemas.microsoft.com",
        }
        network_iocs["domain"] = {
            d for d in network_iocs["domain"]
            if not any(d.endswith(b) for b in benign_domains)
        }

        self.iocs["network_iocs"] = {k: sorted(v) for k, v in network_iocs.items() if v}
        self.iocs["host_iocs"] = {k: sorted(v) for k, v in host_iocs.items() if v}
        self.iocs["suspicious_strings"] = {k: sorted(v) for k, v in other.items() if v}

    def scan_yara(self, rules_path: str):
        """Scan with YARA rules."""
        if yara is None:
            print("[-] yara-python not installed, skipping YARA scan")
            return

        try:
            if os.path.isdir(rules_path):
                rule_files = {}
                for f in os.listdir(rules_path):
                    if f.endswith((".yar", ".yara")):
                        rule_files[f] = os.path.join(rules_path, f)
                rules = yara.compile(filepaths=rule_files)
            else:
                rules = yara.compile(filepath=rules_path)

            matches = rules.match(data=self.data)

            for match in matches:
                self.iocs["yara_matches"].append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "string_count": len(match.strings),
                })
                print(f"[+] YARA match: {match.rule} (tags: {match.tags})")

        except yara.Error as e:
            print(f"[-] YARA error: {e}")

    def check_virustotal(self, api_key: str) -> Optional[dict]:
        """Check file hash against VirusTotal."""
        import requests

        sha256 = self.hashes["sha256"]
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            vt_result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "popular_threat_name": data.get(
                    "popular_threat_classification", {}
                ).get("suggested_threat_label", ""),
                "tags": data.get("tags", []),
                "type_description": data.get("type_description", ""),
                "names": data.get("names", [])[:5],
            }
            self.iocs["virustotal"] = vt_result
            print(
                f"[+] VT: {vt_result['malicious']}/{vt_result['total']} "
                f"detections - {vt_result['popular_threat_name']}"
            )
            return vt_result
        elif resp.status_code == 404:
            print(f"[!] Hash not found on VirusTotal: {sha256}")
        else:
            print(f"[-] VT API error: {resp.status_code}")
        return None

    def generate_stix_bundle(self) -> dict:
        """Generate STIX 2.1 bundle from extracted IOCs."""
        from stix2 import Bundle, Indicator, Malware, Relationship

        objects = []

        malware_obj = Malware(
            name=self.filename,
            is_family=False,
            malware_types=["unknown"],
            description=(
                f"SHA256: {self.hashes['sha256']}\n"
                f"MD5: {self.hashes['md5']}"
            ),
            allow_custom=True,
        )
        objects.append(malware_obj)

        # Hash indicator
        hash_ind = Indicator(
            name=f"File hash: {self.hashes['sha256'][:16]}...",
            pattern=f"[file:hashes.'SHA-256' = '{self.hashes['sha256']}']",
            pattern_type="stix",
            valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            indicator_types=["malicious-activity"],
            allow_custom=True,
        )
        objects.append(hash_ind)
        objects.append(Relationship(
            relationship_type="indicates",
            source_ref=hash_ind.id,
            target_ref=malware_obj.id,
        ))

        # Network indicators
        for ip in self.iocs.get("network_iocs", {}).get("ipv4", []):
            ind = Indicator(
                name=f"C2 IP: {ip}",
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                indicator_types=["malicious-activity"],
                allow_custom=True,
            )
            objects.append(ind)
            objects.append(Relationship(
                relationship_type="indicates",
                source_ref=ind.id,
                target_ref=malware_obj.id,
            ))

        for domain in self.iocs.get("network_iocs", {}).get("domain", []):
            ind = Indicator(
                name=f"C2 Domain: {domain}",
                pattern=f"[domain-name:value = '{domain}']",
                pattern_type="stix",
                valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                indicator_types=["malicious-activity"],
                allow_custom=True,
            )
            objects.append(ind)
            objects.append(Relationship(
                relationship_type="indicates",
                source_ref=ind.id,
                target_ref=malware_obj.id,
            ))

        bundle = Bundle(objects=objects, allow_custom=True)
        return json.loads(bundle.serialize())

    def get_report(self) -> dict:
        """Get complete IOC extraction report."""
        return self.iocs


def main():
    parser = argparse.ArgumentParser(description="Malware IOC Extraction Tool")
    parser.add_argument("--file", required=True, help="Path to malware sample")
    parser.add_argument("--output", default="iocs.json", help="Output IOC file")
    parser.add_argument("--yara-rules", help="YARA rules file or directory")
    parser.add_argument("--vt-check", action="store_true", help="Check VirusTotal")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    parser.add_argument("--stix-output", help="Output STIX 2.1 bundle file")
    parser.add_argument(
        "--min-string-length", type=int, default=4,
        help="Minimum string length for extraction",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}")
        sys.exit(1)

    print(f"[*] Analyzing: {args.file}")
    extractor = MalwareIOCExtractor(args.file)

    print("[*] Calculating hashes...")
    print(f"  MD5:    {extractor.hashes['md5']}")
    print(f"  SHA1:   {extractor.hashes['sha1']}")
    print(f"  SHA256: {extractor.hashes['sha256']}")

    print("[*] Parsing PE structure...")
    extractor.analyze_pe()

    print("[*] Extracting strings and IOC patterns...")
    extractor.extract_strings(min_length=args.min_string_length)

    if args.yara_rules:
        print(f"[*] Scanning with YARA rules: {args.yara_rules}")
        extractor.scan_yara(args.yara_rules)

    if args.vt_check and args.vt_key:
        print("[*] Checking VirusTotal...")
        extractor.check_virustotal(args.vt_key)

    report = extractor.get_report()
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] IOC report saved to {args.output}")

    if args.stix_output:
        print("[*] Generating STIX 2.1 bundle...")
        bundle = extractor.generate_stix_bundle()
        with open(args.stix_output, "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"[+] STIX bundle saved to {args.stix_output}")

    # Print summary
    net = report.get("network_iocs", {})
    host = report.get("host_iocs", {})
    print(f"\n=== IOC Summary ===")
    print(f"  IPs: {len(net.get('ipv4', []))}")
    print(f"  Domains: {len(net.get('domain', []))}")
    print(f"  URLs: {len(net.get('url', []))}")
    print(f"  Registry keys: {len(host.get('registry', []))}")
    print(f"  File paths: {len(host.get('filepath', []))}")
    print(f"  YARA matches: {len(report.get('yara_matches', []))}")


if __name__ == "__main__":
    main()
