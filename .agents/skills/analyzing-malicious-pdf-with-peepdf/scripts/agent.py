#!/usr/bin/env python3
"""Malicious PDF Analysis Agent - static analysis using peepdf, pdfid, and pdf-parser for threat detection."""

import json
import argparse
import logging
import subprocess
import hashlib
import os
import re
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
    "/RichMedia", "/XFA", "/AcroForm", "/JBIG2Decode", "/URI", "/SubmitForm",
    "/ImportData", "/Names", "/ObjStm",
]

HIGH_RISK_KEYWORDS = ["/JS", "/JavaScript", "/OpenAction", "/Launch", "/EmbeddedFile", "/XFA"]


def compute_hashes(filepath):
    """Compute MD5 and SHA-256 hashes of the PDF file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def run_pdfid(filepath):
    """Run pdfid.py to triage PDF for suspicious keywords."""
    cmd = ["python3", "-m", "pdfid", filepath]
    alt_cmd = ["pdfid.py", filepath]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        result = subprocess.run(alt_cmd, capture_output=True, text=True)
    keywords = {}
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in line.lower():
                parts = line.rsplit(None, 1)
                if len(parts) == 2:
                    try:
                        count = int(parts[1])
                        keywords[kw] = count
                    except ValueError:
                        pass
    return keywords


def run_peepdf_analysis(filepath):
    """Run peepdf for detailed PDF object analysis."""
    cmd = ["peepdf", "-f", "-l", filepath]
    alt_cmd = ["python3", "-m", "peepdf", "-f", "-l", filepath]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        result = subprocess.run(alt_cmd, capture_output=True, text=True)
    analysis = {
        "versions": 0,
        "objects": 0,
        "streams": 0,
        "encoded_streams": 0,
        "suspicious_objects": [],
        "js_objects": [],
        "vulns": [],
        "urls": [],
        "raw_output": result.stdout[:2000],
    }
    for line in result.stdout.split("\n"):
        line = line.strip()
        if "Version" in line and "Objects" in line:
            nums = re.findall(r"\d+", line)
            if nums:
                analysis["objects"] = int(nums[-1]) if nums else 0
        if "Suspicious" in line or "suspicious" in line:
            analysis["suspicious_objects"].append(line)
        if "/JS" in line or "/JavaScript" in line:
            obj_ids = re.findall(r"(\d+)", line)
            analysis["js_objects"].extend(obj_ids)
        if "CVE" in line.upper():
            cves = re.findall(r"CVE-\d{4}-\d{4,}", line, re.IGNORECASE)
            analysis["vulns"].extend(cves)
        urls = re.findall(r"https?://[^\s\"'<>]+", line)
        analysis["urls"].extend(urls)
    return analysis


def run_pdf_parser(filepath, object_id=None):
    """Run pdf-parser.py to extract specific objects."""
    if object_id:
        cmd = ["pdf-parser.py", "-o", str(object_id), "-f", "-d", filepath]
    else:
        cmd = ["pdf-parser.py", "--stats", filepath]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout[:3000]


def extract_javascript(filepath, peepdf_analysis):
    """Extract JavaScript content from identified objects."""
    js_content = []
    for obj_id in peepdf_analysis.get("js_objects", []):
        cmd = ["pdf-parser.py", "-o", str(obj_id), "-f", "-w", filepath]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            js_content.append({
                "object_id": obj_id,
                "content_preview": result.stdout[:1000],
                "length": len(result.stdout),
            })
    return js_content


def detect_shellcode_patterns(content):
    """Detect common shellcode patterns in extracted content."""
    patterns = {
        "heap_spray": r"(%u[0-9a-fA-F]{4}){4,}",
        "nop_sled": r"(\\x90){8,}|(%u9090){4,}",
        "unescape_chain": r"unescape\s*\(",
        "shellcode_var": r"shellcode|payload|sc\s*=\s*[\"']",
        "fromcharcode": r"String\.fromCharCode",
        "eval_call": r"eval\s*\(",
        "activex": r"new\s+ActiveXObject",
    }
    detected = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            detected[name] = len(matches)
    return detected


def calculate_risk_score(pdfid_results, peepdf_analysis, shellcode_patterns):
    """Calculate overall risk score for the PDF."""
    score = 0
    for kw, count in pdfid_results.items():
        if count > 0:
            if kw in HIGH_RISK_KEYWORDS:
                score += count * 20
            else:
                score += count * 5
    score += len(peepdf_analysis.get("vulns", [])) * 30
    score += len(peepdf_analysis.get("js_objects", [])) * 15
    score += sum(shellcode_patterns.values()) * 10
    risk_level = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 20 else "low"
    return {"score": min(score, 100), "risk_level": risk_level}


def generate_report(filepath, hashes, pdfid_results, peepdf_analysis, js_content, shellcode, risk):
    """Generate comprehensive PDF malware analysis report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "file": os.path.basename(filepath),
        "file_size": os.path.getsize(filepath),
        "hashes": hashes,
        "risk_assessment": risk,
        "pdfid_keywords": pdfid_results,
        "suspicious_keyword_count": sum(1 for v in pdfid_results.values() if v > 0),
        "peepdf_analysis": {
            "objects": peepdf_analysis.get("objects", 0),
            "js_objects": peepdf_analysis.get("js_objects", []),
            "cve_references": peepdf_analysis.get("vulns", []),
            "extracted_urls": list(set(peepdf_analysis.get("urls", []))),
        },
        "javascript_content": js_content[:5],
        "shellcode_indicators": shellcode,
        "iocs": {
            "sha256": hashes["sha256"],
            "urls": list(set(peepdf_analysis.get("urls", []))),
            "cves": peepdf_analysis.get("vulns", []),
        },
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Malicious PDF Analysis Agent")
    parser.add_argument("file", help="Path to PDF file to analyze")
    parser.add_argument("--extract-js", action="store_true", help="Extract JavaScript objects")
    parser.add_argument("--output", default="pdf_analysis_report.json")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        logger.error("File not found: %s", args.file)
        return

    logger.info("Analyzing: %s (%d bytes)", args.file, os.path.getsize(args.file))
    hashes = compute_hashes(args.file)
    logger.info("SHA-256: %s", hashes["sha256"])

    pdfid_results = run_pdfid(args.file)
    peepdf_analysis = run_peepdf_analysis(args.file)

    js_content = []
    shellcode = {}
    if args.extract_js or peepdf_analysis.get("js_objects"):
        js_content = extract_javascript(args.file, peepdf_analysis)
        all_js = " ".join(j["content_preview"] for j in js_content)
        shellcode = detect_shellcode_patterns(all_js)

    risk = calculate_risk_score(pdfid_results, peepdf_analysis, shellcode)
    report = generate_report(args.file, hashes, pdfid_results, peepdf_analysis, js_content, shellcode, risk)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Risk: %s (score %d), %d suspicious keywords, %d JS objects, %d CVEs",
                risk["risk_level"], risk["score"], report["suspicious_keyword_count"],
                len(peepdf_analysis.get("js_objects", [])), len(peepdf_analysis.get("vulns", [])))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
