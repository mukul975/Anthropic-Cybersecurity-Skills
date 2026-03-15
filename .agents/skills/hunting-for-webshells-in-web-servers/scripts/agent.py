#!/usr/bin/env python3
"""Webshell Detection Agent - Scans web server directories for webshell indicators."""

import json
import math
import os
import re
import logging
import argparse
from datetime import datetime, timedelta
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

WEB_EXTENSIONS = {".php", ".phtml", ".php5", ".php7", ".jsp", ".jspx", ".asp", ".aspx", ".cgi", ".py", ".pl", ".cfm"}

PHP_PATTERNS = [
    (r"\beval\s*\(", "eval() execution", "critical"),
    (r"\bbase64_decode\s*\(", "base64_decode() obfuscation", "high"),
    (r"\bsystem\s*\(", "system() command execution", "critical"),
    (r"\bpassthru\s*\(", "passthru() command execution", "critical"),
    (r"\bshell_exec\s*\(", "shell_exec() command execution", "critical"),
    (r"\bexec\s*\(", "exec() command execution", "high"),
    (r"\bproc_open\s*\(", "proc_open() process spawn", "critical"),
    (r"\bpopen\s*\(", "popen() pipe execution", "high"),
    (r"\bstr_rot13\s*\(", "str_rot13() obfuscation", "medium"),
    (r"\bgzinflate\s*\(", "gzinflate() decompression obfuscation", "high"),
    (r"\bpreg_replace\s*\(.*/e", "preg_replace /e code execution", "critical"),
    (r"\bassert\s*\(", "assert() code execution", "high"),
    (r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[", "direct superglobal access", "medium"),
    (r"\bcreate_function\s*\(", "create_function() dynamic code", "high"),
    (r"\bReflectionFunction\b", "ReflectionFunction dynamic invocation", "high"),
]

JSP_PATTERNS = [
    (r"Runtime\.getRuntime\(\)\.exec\(", "Runtime.exec() command execution", "critical"),
    (r"ProcessBuilder\b", "ProcessBuilder command execution", "critical"),
    (r"Class\.forName\s*\(", "Class.forName() dynamic loading", "high"),
]

ASP_PATTERNS = [
    (r"Server\.CreateObject\s*\(", "CreateObject instantiation", "high"),
    (r"WScript\.Shell", "WScript.Shell execution", "critical"),
    (r"Scripting\.FileSystemObject", "FileSystemObject access", "high"),
    (r"Execute\s*\(", "Execute() dynamic code", "critical"),
]


def calculate_entropy(data):
    """Calculate Shannon entropy of file content."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def get_patterns_for_ext(ext):
    """Return relevant patterns based on file extension."""
    ext = ext.lower()
    patterns = []
    if ext in (".php", ".phtml", ".php5", ".php7"):
        patterns.extend(PHP_PATTERNS)
    elif ext in (".jsp", ".jspx"):
        patterns.extend(JSP_PATTERNS)
    elif ext in (".asp", ".aspx"):
        patterns.extend(ASP_PATTERNS)
    return patterns


def scan_file(filepath, entropy_threshold=5.5):
    """Scan a single file for webshell indicators."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError) as e:
        return {"file": filepath, "error": str(e)}

    stat = os.stat(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    entropy = calculate_entropy(content)
    matched_patterns = []

    for pattern, description, severity in get_patterns_for_ext(ext):
        if re.search(pattern, content, re.IGNORECASE):
            matched_patterns.append({"pattern": description, "severity": severity})

    long_strings = len(re.findall(r'["\'][^"\']{500,}["\']', content))
    has_hex_encoding = bool(re.search(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}", content))
    line_count = content.count("\n") + 1
    avg_line_length = len(content) / max(line_count, 1)

    risk_score = 0
    if entropy > entropy_threshold:
        risk_score += 30
    if matched_patterns:
        risk_score += min(len(matched_patterns) * 15, 50)
    if long_strings > 0:
        risk_score += 10
    if has_hex_encoding:
        risk_score += 15
    if avg_line_length > 500:
        risk_score += 10

    if risk_score >= 50:
        verdict = "MALICIOUS"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "file": filepath,
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "entropy": round(entropy, 3),
        "patterns_matched": matched_patterns,
        "long_strings": long_strings,
        "hex_encoding": has_hex_encoding,
        "avg_line_length": round(avg_line_length, 1),
        "risk_score": risk_score,
        "verdict": verdict,
    }


def scan_directory(webroot, entropy_threshold=5.5, max_age_days=30):
    """Scan a web directory for webshell files."""
    results = []
    cutoff = datetime.now() - timedelta(days=max_age_days)

    for root, _dirs, files in os.walk(webroot):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in WEB_EXTENSIONS:
                continue
            filepath = os.path.join(root, fname)
            result = scan_file(filepath, entropy_threshold)
            if "error" not in result:
                results.append(result)

    recently_modified = [
        r for r in results
        if datetime.fromisoformat(r["modified"]) > cutoff
    ]
    logger.info(
        "Scanned %d files, %d recently modified (<%d days)",
        len(results), len(recently_modified), max_age_days,
    )
    return results


def generate_report(scan_results):
    """Generate webshell detection report."""
    malicious = [r for r in scan_results if r["verdict"] == "MALICIOUS"]
    suspicious = [r for r in scan_results if r["verdict"] == "SUSPICIOUS"]
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_files_scanned": len(scan_results),
        "malicious_count": len(malicious),
        "suspicious_count": len(suspicious),
        "clean_count": len(scan_results) - len(malicious) - len(suspicious),
        "malicious_files": malicious,
        "suspicious_files": suspicious,
    }
    print(f"WEBSHELL REPORT: {len(malicious)} malicious, {len(suspicious)} suspicious out of {len(scan_results)} files")
    return report


def main():
    parser = argparse.ArgumentParser(description="Webshell Detection Agent")
    parser.add_argument("--webroot", required=True, help="Web server document root to scan")
    parser.add_argument("--entropy-threshold", type=float, default=5.5)
    parser.add_argument("--max-age-days", type=int, default=30)
    parser.add_argument("--output", default="webshell_report.json")
    args = parser.parse_args()

    results = scan_directory(args.webroot, args.entropy_threshold, args.max_age_days)
    report = generate_report(results)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
