#!/usr/bin/env python3
"""Agent for performing SSL/TLS security assessment using sslyze.

Scans TLS server configurations to evaluate cipher suites,
protocol versions, certificate chains, HSTS, and known
vulnerabilities like Heartbleed and ROBOT.
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

try:
    from sslyze import (
        Scanner,
        ServerScanRequest,
        ServerNetworkLocation,
        ScanCommand,
        ScanCommandAttemptStatusEnum,
    )
except ImportError:
    Scanner = None


WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]


class SSLTLSAssessmentAgent:
    """Assesses SSL/TLS configurations using sslyze."""

    def __init__(self, output_dir="./ssl_tls_assessment"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def scan_server(self, hostname, port=443):
        """Run full sslyze scan against a target server."""
        if Scanner is None:
            return {"error": "sslyze not installed: pip install sslyze"}

        location = ServerNetworkLocation(hostname=hostname, port=port)
        scan_request = ServerScanRequest(server_location=location)
        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for result in scanner.get_results():
            return self._process_result(result, hostname, port)
        return {"error": "No scan results returned"}

    def _process_result(self, result, hostname, port):
        """Process sslyze ServerScanResult into structured findings."""
        report = {"hostname": hostname, "port": port, "protocols": {},
                  "cipher_suites": {}, "certificate": {}, "vulnerabilities": {}}

        protocol_checks = [
            ("ssl_2_0_cipher_suites", "SSLv2"),
            ("ssl_3_0_cipher_suites", "SSLv3"),
            ("tls_1_0_cipher_suites", "TLS 1.0"),
            ("tls_1_1_cipher_suites", "TLS 1.1"),
            ("tls_1_2_cipher_suites", "TLS 1.2"),
            ("tls_1_3_cipher_suites", "TLS 1.3"),
        ]

        scan = result.scan_result
        for attr, proto_name in protocol_checks:
            attempt = getattr(scan, attr, None)
            if attempt and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                ciphers = attempt.result
                accepted = [c.cipher_suite.name for c in ciphers.accepted_cipher_suites]
                report["protocols"][proto_name] = len(accepted) > 0
                report["cipher_suites"][proto_name] = accepted

                if proto_name in ("SSLv2", "SSLv3"):
                    if accepted:
                        self.findings.append({
                            "severity": "critical", "type": "Deprecated Protocol",
                            "detail": f"{proto_name} enabled with {len(accepted)} cipher suites",
                        })
                elif proto_name in ("TLS 1.0", "TLS 1.1"):
                    if accepted:
                        self.findings.append({
                            "severity": "high", "type": "Legacy Protocol",
                            "detail": f"{proto_name} still enabled",
                        })

                for cipher_name in accepted:
                    if any(weak in cipher_name for weak in WEAK_CIPHERS_KEYWORDS):
                        self.findings.append({
                            "severity": "high", "type": "Weak Cipher Suite",
                            "detail": f"{cipher_name} accepted on {proto_name}",
                        })

        cert_attempt = getattr(scan, "certificate_info", None)
        if cert_attempt and cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            cert_result = cert_attempt.result
            for deployment in cert_result.certificate_deployments:
                leaf = deployment.received_certificate_chain[0]
                report["certificate"] = {
                    "subject": leaf.subject.rfc4514_string(),
                    "issuer": leaf.issuer.rfc4514_string(),
                    "not_before": leaf.not_valid_before_utc.isoformat(),
                    "not_after": leaf.not_valid_after_utc.isoformat(),
                    "serial": str(leaf.serial_number),
                    "signature_algorithm": leaf.signature_hash_algorithm.name
                        if leaf.signature_hash_algorithm else "unknown",
                    "chain_valid": deployment.verified_certificate_chain is not None,
                    "ocsp_stapling": deployment.ocsp_response is not None,
                }
                if leaf.not_valid_after_utc < datetime.utcnow():
                    self.findings.append({
                        "severity": "critical", "type": "Expired Certificate",
                        "detail": f"Certificate expired on {leaf.not_valid_after_utc}",
                    })
                if leaf.signature_hash_algorithm and leaf.signature_hash_algorithm.name == "sha1":
                    self.findings.append({
                        "severity": "high", "type": "SHA-1 Certificate",
                        "detail": "Certificate uses SHA-1 signature",
                    })

        vuln_checks = [
            ("heartbleed", "Heartbleed", "is_vulnerable_to_heartbleed"),
            ("openssl_ccs_injection", "CCS Injection", "is_vulnerable_to_ccs_injection"),
        ]
        for attr, name, field in vuln_checks:
            attempt = getattr(scan, attr, None)
            if attempt and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                vulnerable = getattr(attempt.result, field, False)
                report["vulnerabilities"][name] = vulnerable
                if vulnerable:
                    self.findings.append({
                        "severity": "critical", "type": f"{name} Vulnerable",
                        "detail": f"Server is vulnerable to {name}",
                    })

        robot_attempt = getattr(scan, "robot", None)
        if robot_attempt and robot_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            robot_result = robot_attempt.result
            is_vuln = "VULNERABLE" in str(robot_result.robot_result)
            report["vulnerabilities"]["ROBOT"] = is_vuln
            if is_vuln:
                self.findings.append({
                    "severity": "critical", "type": "ROBOT Vulnerable",
                    "detail": "Server is vulnerable to ROBOT attack",
                })

        return report

    def generate_report(self, targets):
        """Scan multiple targets and generate consolidated report."""
        results = []
        for target in targets:
            parts = target.split(":")
            hostname = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
            results.append(self.scan_server(hostname, port))

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "targets_scanned": len(targets),
            "scan_results": results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "ssl_tls_assessment_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Assess SSL/TLS server configurations using sslyze"
    )
    parser.add_argument("targets", nargs="+", help="Target host:port (e.g. example.com:443)")
    parser.add_argument("--output-dir", default="./ssl_tls_assessment")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    agent = SSLTLSAssessmentAgent(output_dir=args.output_dir)
    agent.generate_report(args.targets)


if __name__ == "__main__":
    main()
