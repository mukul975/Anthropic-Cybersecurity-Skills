#!/usr/bin/env python3
"""
Agent for performing post-quantum cryptography migration assessment.

Scans TLS endpoints for quantum-vulnerable algorithms, assesses crypto-agility
readiness, tests hybrid TLS (X25519MLKEM768) support, validates ML-KEM and
ML-DSA algorithm functionality, and generates prioritized migration roadmaps
per NIST FIPS 203/204/205 standards.
"""

import os
import sys
import json
import ssl
import socket
import argparse
import logging
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("pqc-migration-agent")

# ---------------------------------------------------------------------------
# Constants: Quantum-vulnerable algorithm classification
# ---------------------------------------------------------------------------

QUANTUM_VULNERABLE_KEY_EXCHANGE = {
    "RSA",
    "DH",
    "DHE",
    "ECDH",
    "ECDHE",
}

QUANTUM_VULNERABLE_SIGNATURE = {
    "RSA",
    "ECDSA",
    "DSA",
    "Ed25519",
    "Ed448",
}

QUANTUM_SAFE_KEY_EXCHANGE = {
    "X25519MLKEM768",
    "X25519_MLKEM768",
    "SecP256r1MLKEM768",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "X448MLKEM1024",
}

PQC_SIGNATURE_ALGORITHMS = {
    "MLDSA44",
    "MLDSA65",
    "MLDSA87",
    "SLHDSA_SHA2_128S",
    "SLHDSA_SHA2_128F",
    "SLHDSA_SHA2_192S",
    "SLHDSA_SHA2_192F",
    "SLHDSA_SHA2_256S",
    "SLHDSA_SHA2_256F",
    "SLHDSA_SHAKE_128S",
    "SLHDSA_SHAKE_128F",
    "SLHDSA_SHAKE_192S",
    "SLHDSA_SHAKE_192F",
    "SLHDSA_SHAKE_256S",
    "SLHDSA_SHAKE_256F",
}

# Minimum key sizes that provide adequate classical security
MIN_SECURE_KEY_SIZES = {
    "RSA": 2048,
    "EC": 256,
    "AES": 256,  # For post-quantum, AES-256 recommended (Grover's halves effective strength)
}

NIST_MIGRATION_DEADLINES = {
    "deprecation": "2030",
    "disallowed": "2035",
    "description": "NIST IR 8547: quantum-vulnerable algorithms deprecated by 2030, "
                   "disallowed by 2035 for federal systems",
}

# ML-KEM parameters per FIPS 203
MLKEM_PARAMS = {
    "ML-KEM-512": {
        "security_level": 1,
        "pk_bytes": 800,
        "sk_bytes": 1632,
        "ct_bytes": 768,
        "ss_bytes": 32,
        "comparable_to": "AES-128",
    },
    "ML-KEM-768": {
        "security_level": 3,
        "pk_bytes": 1184,
        "sk_bytes": 2400,
        "ct_bytes": 1088,
        "ss_bytes": 32,
        "comparable_to": "AES-192",
    },
    "ML-KEM-1024": {
        "security_level": 5,
        "pk_bytes": 1568,
        "sk_bytes": 3168,
        "ct_bytes": 1568,
        "ss_bytes": 32,
        "comparable_to": "AES-256",
    },
}

# ML-DSA parameters per FIPS 204
MLDSA_PARAMS = {
    "ML-DSA-44": {
        "security_level": 2,
        "pk_bytes": 1312,
        "sk_bytes": 2560,
        "sig_bytes": 2420,
        "comparable_to": "NIST Level 2 (~AES-128+)",
    },
    "ML-DSA-65": {
        "security_level": 3,
        "pk_bytes": 1952,
        "sk_bytes": 4032,
        "sig_bytes": 3293,
        "comparable_to": "NIST Level 3 (~AES-192)",
    },
    "ML-DSA-87": {
        "security_level": 5,
        "pk_bytes": 2592,
        "sk_bytes": 4896,
        "sig_bytes": 4595,
        "comparable_to": "NIST Level 5 (~AES-256)",
    },
}

# SLH-DSA parameters per FIPS 205
SLHDSA_PARAMS = {
    "SLH-DSA-SHA2-128s": {"security_level": 1, "pk_bytes": 32, "sig_bytes": 7856},
    "SLH-DSA-SHA2-128f": {"security_level": 1, "pk_bytes": 32, "sig_bytes": 17088},
    "SLH-DSA-SHA2-192s": {"security_level": 3, "pk_bytes": 48, "sig_bytes": 16224},
    "SLH-DSA-SHA2-192f": {"security_level": 3, "pk_bytes": 48, "sig_bytes": 35664},
    "SLH-DSA-SHA2-256s": {"security_level": 5, "pk_bytes": 64, "sig_bytes": 29792},
    "SLH-DSA-SHA2-256f": {"security_level": 5, "pk_bytes": 64, "sig_bytes": 49856},
    "SLH-DSA-SHAKE-128s": {"security_level": 1, "pk_bytes": 32, "sig_bytes": 7856},
    "SLH-DSA-SHAKE-128f": {"security_level": 1, "pk_bytes": 32, "sig_bytes": 17088},
    "SLH-DSA-SHAKE-192s": {"security_level": 3, "pk_bytes": 48, "sig_bytes": 16224},
    "SLH-DSA-SHAKE-192f": {"security_level": 3, "pk_bytes": 48, "sig_bytes": 35664},
    "SLH-DSA-SHAKE-256s": {"security_level": 5, "pk_bytes": 64, "sig_bytes": 29792},
    "SLH-DSA-SHAKE-256f": {"security_level": 5, "pk_bytes": 64, "sig_bytes": 49856},
}


# ---------------------------------------------------------------------------
# TLS Endpoint Scanning
# ---------------------------------------------------------------------------

def scan_tls_endpoint(host, port=443, timeout=10):
    """
    Scan a TLS endpoint to extract cryptographic algorithm details.

    Connects to the target, performs TLS handshake, and extracts:
    - Protocol version
    - Cipher suite (key exchange, encryption, MAC)
    - Certificate details (algorithm, key size, validity)
    - Supported groups / curves

    Args:
        host: Target hostname or IP
        port: Target port (default 443)
        timeout: Connection timeout in seconds

    Returns:
        Dict with comprehensive TLS cryptographic inventory
    """
    result = {
        "host": host,
        "port": port,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "tls_version": None,
        "cipher_suite": None,
        "key_exchange": None,
        "certificate": {},
        "quantum_vulnerable": True,
        "vulnerabilities": [],
        "recommendations": [],
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                # Extract TLS session details
                cipher = tls_sock.cipher()
                result["tls_version"] = tls_sock.version()
                result["cipher_suite"] = cipher[0] if cipher else None
                result["cipher_protocol"] = cipher[1] if cipher and len(cipher) > 1 else None
                result["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else None

                # Parse key exchange from cipher suite name
                cipher_name = cipher[0] if cipher else ""
                result["key_exchange"] = _extract_key_exchange(cipher_name)

                # Extract certificate details
                cert = tls_sock.getpeercert()
                cert_der = tls_sock.getpeercert(binary_form=True)
                result["certificate"] = _parse_certificate(cert, cert_der)

                # Assess quantum vulnerability
                _assess_quantum_vulnerability(result)

        logger.info("Scanned %s:%d -- %s [%s]", host, port,
                     result["cipher_suite"], result["tls_version"])

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
        logger.warning("SSL error scanning %s:%d: %s", host, port, e)
    except socket.timeout:
        result["error"] = "Connection timed out"
        logger.warning("Timeout scanning %s:%d", host, port)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"
        logger.warning("DNS error for %s: %s", host, e)
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
        logger.warning("Connection refused: %s:%d", host, port)
    except Exception as e:
        result["error"] = f"Unexpected error: {e}"
        logger.error("Error scanning %s:%d: %s", host, port, e)

    return result


def _extract_key_exchange(cipher_name):
    """Extract key exchange algorithm from cipher suite name."""
    cipher_upper = cipher_name.upper()
    if "ECDHE" in cipher_upper:
        return "ECDHE"
    elif "DHE" in cipher_upper or "EDH" in cipher_upper:
        return "DHE"
    elif "ECDH" in cipher_upper:
        return "ECDH"
    elif "DH" in cipher_upper:
        return "DH"
    elif "RSA" in cipher_upper:
        return "RSA"
    return "Unknown"


def _parse_certificate(cert, cert_der=None):
    """Parse certificate details from Python ssl cert dict."""
    cert_info = {
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "serial_number": "",
        "signature_algorithm": "Unknown",
        "public_key_algorithm": "Unknown",
        "public_key_bits": 0,
        "san": [],
    }

    if not cert:
        return cert_info

    # Extract subject
    subject = cert.get("subject", ())
    for rdn in subject:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                cert_info["subject"] = attr_value

    # Extract issuer
    issuer = cert.get("issuer", ())
    for rdn in issuer:
        for attr_type, attr_value in rdn:
            if attr_type == "organizationName":
                cert_info["issuer"] = attr_value

    cert_info["not_before"] = cert.get("notBefore", "")
    cert_info["not_after"] = cert.get("notAfter", "")
    cert_info["serial_number"] = cert.get("serialNumber", "")

    # Extract SANs
    sans = cert.get("subjectAltName", ())
    cert_info["san"] = [value for san_type, value in sans if san_type == "DNS"]

    # Try to get detailed cert info via openssl
    if cert_der:
        try:
            cert_details = _openssl_parse_cert_der(cert_der)
            cert_info.update(cert_details)
        except Exception:
            pass

    return cert_info


def _openssl_parse_cert_der(cert_der):
    """Use openssl CLI to parse DER certificate for algorithm details."""
    details = {}
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-text"],
            input=cert_der,
            capture_output=True,
            timeout=10,
        )
        output = proc.stdout.decode("utf-8", errors="replace")

        # Extract signature algorithm
        sig_match = re.search(r"Signature Algorithm:\s+(.+)", output)
        if sig_match:
            details["signature_algorithm"] = sig_match.group(1).strip()

        # Extract public key algorithm and size
        pk_match = re.search(r"Public Key Algorithm:\s+(.+)", output)
        if pk_match:
            details["public_key_algorithm"] = pk_match.group(1).strip()

        bits_match = re.search(r"(?:RSA Public-Key|Public-Key):\s+\((\d+) bit\)", output)
        if bits_match:
            details["public_key_bits"] = int(bits_match.group(1))

        ec_match = re.search(r"ASN1 OID:\s+(.+)", output)
        if ec_match:
            details["ec_curve"] = ec_match.group(1).strip()

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return details


def _assess_quantum_vulnerability(result):
    """Assess whether the TLS connection uses quantum-vulnerable cryptography."""
    vulnerabilities = []
    recommendations = []
    is_vulnerable = False

    # Check key exchange
    kx = result.get("key_exchange", "").upper()
    kx_base = kx.replace("_", "")
    if any(v in kx_base for v in ["RSA", "ECDH", "ECDHE", "DHE", "DH"]):
        if not any(pq in kx_base for pq in ["MLKEM", "KYBER"]):
            is_vulnerable = True
            vulnerabilities.append({
                "component": "key_exchange",
                "algorithm": kx,
                "threat": "Shor's algorithm can break this key exchange",
                "severity": "critical",
            })
            recommendations.append(
                "Migrate to hybrid key exchange X25519MLKEM768 for TLS 1.3"
            )

    # Check certificate signature algorithm
    sig_algo = result.get("certificate", {}).get("signature_algorithm", "").lower()
    if any(v in sig_algo for v in ["rsa", "ecdsa", "dsa"]):
        if not any(pq in sig_algo for pq in ["mldsa", "dilithium", "slhdsa", "sphincs"]):
            is_vulnerable = True
            vulnerabilities.append({
                "component": "certificate_signature",
                "algorithm": sig_algo,
                "threat": "Shor's algorithm can forge signatures",
                "severity": "high",
            })
            recommendations.append(
                "Plan migration to ML-DSA (FIPS 204) for certificate signatures"
            )

    # Check public key algorithm
    pk_algo = result.get("certificate", {}).get("public_key_algorithm", "").lower()
    pk_bits = result.get("certificate", {}).get("public_key_bits", 0)

    if "rsa" in pk_algo:
        is_vulnerable = True
        if pk_bits < 2048:
            vulnerabilities.append({
                "component": "certificate_public_key",
                "algorithm": f"RSA-{pk_bits}",
                "threat": "Below minimum key size AND quantum-vulnerable",
                "severity": "critical",
            })
        else:
            vulnerabilities.append({
                "component": "certificate_public_key",
                "algorithm": f"RSA-{pk_bits}",
                "threat": "Quantum-vulnerable (adequate classically)",
                "severity": "high",
            })

    if "ec" in pk_algo or "ecdsa" in pk_algo:
        is_vulnerable = True
        vulnerabilities.append({
            "component": "certificate_public_key",
            "algorithm": pk_algo,
            "threat": "Shor's algorithm breaks elliptic curve discrete log",
            "severity": "high",
        })

    # Check TLS version
    tls_version = result.get("tls_version", "")
    if tls_version and "1.3" not in tls_version:
        recommendations.append(
            f"Upgrade from {tls_version} to TLS 1.3 (required for hybrid PQC key exchange)"
        )

    result["quantum_vulnerable"] = is_vulnerable
    result["vulnerabilities"] = vulnerabilities
    result["recommendations"] = recommendations


def scan_multiple_endpoints(targets_file, port=443):
    """
    Scan multiple TLS endpoints from a targets file.

    Args:
        targets_file: Path to file with one host[:port] per line
        port: Default port if not specified per target

    Returns:
        List of scan results for all targets
    """
    targets_path = Path(targets_file)
    if not targets_path.exists():
        logger.error("Targets file not found: %s", targets_file)
        return []

    results = []
    with open(targets_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" in line:
                host, target_port = line.rsplit(":", 1)
                try:
                    target_port = int(target_port)
                except ValueError:
                    target_port = port
            else:
                host = line
                target_port = port

            result = scan_tls_endpoint(host, target_port)
            results.append(result)

    return results


# ---------------------------------------------------------------------------
# Crypto-Agility Assessment
# ---------------------------------------------------------------------------

def assess_crypto_agility(scan_results):
    """
    Assess organizational crypto-agility based on TLS scan results.

    Evaluates the ability to migrate from quantum-vulnerable algorithms
    to post-quantum alternatives without major infrastructure changes.

    Args:
        scan_results: List of TLS scan result dicts

    Returns:
        Crypto-agility assessment report
    """
    assessment = {
        "assessment_time": datetime.now(timezone.utc).isoformat(),
        "total_endpoints": len(scan_results),
        "quantum_vulnerable_endpoints": 0,
        "tls13_ready": 0,
        "algorithm_inventory": defaultdict(int),
        "certificate_algorithms": defaultdict(int),
        "key_exchange_algorithms": defaultdict(int),
        "risk_summary": {},
        "agility_score": 0,
        "findings": [],
        "recommendations": [],
    }

    for result in scan_results:
        if result.get("error"):
            continue

        if result.get("quantum_vulnerable"):
            assessment["quantum_vulnerable_endpoints"] += 1

        tls_ver = result.get("tls_version", "")
        if "1.3" in tls_ver:
            assessment["tls13_ready"] += 1

        cipher = result.get("cipher_suite", "Unknown")
        assessment["algorithm_inventory"][cipher] += 1

        kx = result.get("key_exchange", "Unknown")
        assessment["key_exchange_algorithms"][kx] += 1

        sig_algo = result.get("certificate", {}).get("signature_algorithm", "Unknown")
        assessment["certificate_algorithms"][sig_algo] += 1

    total = assessment["total_endpoints"]
    if total == 0:
        return assessment

    vuln_pct = (assessment["quantum_vulnerable_endpoints"] / total) * 100
    tls13_pct = (assessment["tls13_ready"] / total) * 100

    # Calculate agility score (0-100)
    score = 0
    score += min(40, tls13_pct * 0.4)  # TLS 1.3 readiness (up to 40 points)
    score += max(0, 30 - (vuln_pct * 0.3))  # Fewer vulnerabilities (up to 30 points)

    # Bonus for algorithm diversity (indicates flexibility)
    unique_ciphers = len(assessment["algorithm_inventory"])
    score += min(15, unique_ciphers * 3)  # Up to 15 points for diversity

    # Bonus for modern configurations
    modern_kx = sum(
        v for k, v in assessment["key_exchange_algorithms"].items()
        if k in ("ECDHE", "DHE")
    )
    if total > 0:
        score += min(15, (modern_kx / total) * 15)  # Up to 15 points for PFS

    assessment["agility_score"] = round(score, 1)

    # Risk summary
    assessment["risk_summary"] = {
        "quantum_vulnerable_percentage": round(vuln_pct, 1),
        "tls13_percentage": round(tls13_pct, 1),
        "unique_cipher_suites": unique_ciphers,
        "risk_level": (
            "critical" if vuln_pct > 90 else
            "high" if vuln_pct > 70 else
            "medium" if vuln_pct > 40 else
            "low"
        ),
    }

    # Findings
    if vuln_pct > 0:
        assessment["findings"].append({
            "finding": f"{assessment['quantum_vulnerable_endpoints']}/{total} "
                       f"endpoints ({vuln_pct:.0f}%) use quantum-vulnerable algorithms",
            "severity": "critical" if vuln_pct > 70 else "high",
            "category": "quantum_vulnerability",
        })

    if tls13_pct < 100:
        not_tls13 = total - assessment["tls13_ready"]
        assessment["findings"].append({
            "finding": f"{not_tls13} endpoints do not support TLS 1.3 "
                       f"(required for hybrid PQC key exchange)",
            "severity": "high",
            "category": "protocol_version",
        })

    # Recommendations
    if tls13_pct < 100:
        assessment["recommendations"].append({
            "priority": 1,
            "action": "Upgrade all TLS endpoints to TLS 1.3",
            "rationale": "Hybrid PQC key exchange (X25519MLKEM768) requires TLS 1.3",
            "effort": "medium",
        })

    assessment["recommendations"].append({
        "priority": 2,
        "action": "Deploy hybrid key exchange X25519MLKEM768 on TLS 1.3 endpoints",
        "rationale": "Provides quantum-resistant key exchange while maintaining "
                     "classical security as fallback",
        "effort": "low" if tls13_pct > 80 else "medium",
    })

    assessment["recommendations"].append({
        "priority": 3,
        "action": "Update OpenSSL to 3.5+ or install oqs-provider for PQC support",
        "rationale": "OpenSSL 3.5 provides native ML-KEM/ML-DSA support; "
                     "oqs-provider adds PQC to OpenSSL 3.0-3.4",
        "effort": "medium",
    })

    assessment["recommendations"].append({
        "priority": 4,
        "action": "Plan certificate migration to ML-DSA (FIPS 204) signatures",
        "rationale": "Certificate signatures need PQC before the NIST 2030 "
                     "deprecation deadline",
        "effort": "high",
    })

    # Convert defaultdicts to regular dicts for JSON serialization
    assessment["algorithm_inventory"] = dict(assessment["algorithm_inventory"])
    assessment["certificate_algorithms"] = dict(assessment["certificate_algorithms"])
    assessment["key_exchange_algorithms"] = dict(assessment["key_exchange_algorithms"])

    return assessment


# ---------------------------------------------------------------------------
# Hybrid TLS Testing
# ---------------------------------------------------------------------------

def test_hybrid_tls_support(host, port=443):
    """
    Test whether a server supports hybrid post-quantum TLS key exchange.

    Attempts connection using X25519MLKEM768 and other hybrid groups.
    Requires OpenSSL 3.5+ or oqs-provider.

    Args:
        host: Target hostname
        port: Target port

    Returns:
        Dict with hybrid TLS support test results
    """
    result = {
        "host": host,
        "port": port,
        "test_time": datetime.now(timezone.utc).isoformat(),
        "openssl_version": "",
        "hybrid_groups_tested": [],
        "pqc_supported": False,
        "details": {},
    }

    # Check OpenSSL version
    try:
        proc = subprocess.run(
            ["openssl", "version"],
            capture_output=True, timeout=5,
        )
        result["openssl_version"] = proc.stdout.decode().strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["openssl_version"] = "openssl not found"

    # Test hybrid key exchange groups
    hybrid_groups = [
        "X25519MLKEM768",
        "x25519_mlkem768",  # oqs-provider naming
    ]

    for group in hybrid_groups:
        test_result = _test_tls_group(host, port, group)
        result["hybrid_groups_tested"].append(test_result)
        if test_result.get("supported"):
            result["pqc_supported"] = True

    # Also test classical groups for comparison
    classical_groups = ["X25519", "P-256", "P-384"]
    for group in classical_groups:
        test_result = _test_tls_group(host, port, group)
        result["hybrid_groups_tested"].append(test_result)

    return result


def _test_tls_group(host, port, group):
    """Test a specific TLS key exchange group against a server."""
    test = {
        "group": group,
        "supported": False,
        "error": None,
    }

    try:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-groups", group,
            "-brief",
        ]
        proc = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=15,
        )
        output = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")

        # Check if connection succeeded with the specified group
        if "Protocol" in output or "Verification" in output:
            test["supported"] = True
            # Extract negotiated protocol and cipher
            proto_match = re.search(r"Protocol version:\s+(\S+)", output)
            cipher_match = re.search(r"Ciphersuite:\s+(\S+)", output)
            if proto_match:
                test["protocol"] = proto_match.group(1)
            if cipher_match:
                test["cipher"] = cipher_match.group(1)
        elif "no protocols available" in stderr.lower():
            test["error"] = "Group not supported by server"
        elif "unknown group" in stderr.lower():
            test["error"] = "Group not supported by local OpenSSL"
        else:
            test["error"] = "Connection failed"
            if stderr:
                # Take first line of error
                test["error_detail"] = stderr.split("\n")[0][:200]

    except subprocess.TimeoutExpired:
        test["error"] = "Connection timed out"
    except FileNotFoundError:
        test["error"] = "openssl binary not found"

    return test


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203) Validation
# ---------------------------------------------------------------------------

def test_mlkem_support():
    """
    Test ML-KEM (CRYSTALS-Kyber / FIPS 203) key encapsulation support.

    Tests keygen, encapsulation, and decapsulation at all three security levels
    using either the mlkem Python library or OpenSSL with oqs-provider.

    Returns:
        Dict with ML-KEM validation results for each security level
    """
    results = {
        "test_time": datetime.now(timezone.utc).isoformat(),
        "library": None,
        "levels": {},
    }

    # Try Python mlkem library first
    try:
        from mlkem.ml_kem import ML_KEM

        results["library"] = "mlkem (Python)"

        for level_name, params in MLKEM_PARAMS.items():
            level_result = _test_mlkem_python(level_name, params)
            results["levels"][level_name] = level_result

        logger.info("ML-KEM tested via Python mlkem library")
        return results

    except ImportError:
        logger.info("mlkem Python library not available, trying OpenSSL")

    # Fallback to OpenSSL CLI
    try:
        for level_name, params in MLKEM_PARAMS.items():
            level_result = _test_mlkem_openssl(level_name, params)
            results["levels"][level_name] = level_result

        results["library"] = "OpenSSL"
        logger.info("ML-KEM tested via OpenSSL")
        return results

    except Exception as e:
        logger.warning("ML-KEM testing failed: %s", e)
        results["error"] = str(e)

    return results


def _test_mlkem_python(level_name, params):
    """Test ML-KEM at a specific level using the Python mlkem library."""
    result = {
        "level": level_name,
        "security_level": params["security_level"],
        "supported": False,
        "keygen": False,
        "encaps": False,
        "decaps": False,
        "shared_secret_match": False,
        "performance": {},
    }

    try:
        from mlkem.ml_kem import ML_KEM
        import time

        # Map level name to ML_KEM parameter
        param_map = {
            "ML-KEM-512": 512,
            "ML-KEM-768": 768,
            "ML-KEM-1024": 1024,
        }
        k = param_map.get(level_name)
        if k is None:
            result["error"] = f"Unknown level: {level_name}"
            return result

        ml_kem = ML_KEM(k)

        # Key generation
        t0 = time.perf_counter()
        ek, dk = ml_kem.key_gen()
        keygen_ms = (time.perf_counter() - t0) * 1000
        result["keygen"] = True
        result["performance"]["keygen_ms"] = round(keygen_ms, 2)

        # Verify key sizes
        result["pk_bytes"] = len(ek)
        result["sk_bytes"] = len(dk)

        # Encapsulation
        t0 = time.perf_counter()
        shared_secret, ciphertext = ml_kem.encaps(ek)
        encaps_ms = (time.perf_counter() - t0) * 1000
        result["encaps"] = True
        result["performance"]["encaps_ms"] = round(encaps_ms, 2)
        result["ct_bytes"] = len(ciphertext)

        # Decapsulation
        t0 = time.perf_counter()
        shared_secret_dec = ml_kem.decaps(dk, ciphertext)
        decaps_ms = (time.perf_counter() - t0) * 1000
        result["decaps"] = True
        result["performance"]["decaps_ms"] = round(decaps_ms, 2)

        # Verify shared secrets match
        result["shared_secret_match"] = (shared_secret == shared_secret_dec)
        result["ss_bytes"] = len(shared_secret)
        result["supported"] = result["shared_secret_match"]

    except Exception as e:
        result["error"] = str(e)

    return result


def _test_mlkem_openssl(level_name, params):
    """Test ML-KEM support via OpenSSL CLI (requires OpenSSL 3.5+ or oqs-provider)."""
    result = {
        "level": level_name,
        "security_level": params["security_level"],
        "supported": False,
        "error": None,
    }

    algo_map = {
        "ML-KEM-512": "mlkem512",
        "ML-KEM-768": "mlkem768",
        "ML-KEM-1024": "mlkem1024",
    }
    algo = algo_map.get(level_name, "mlkem768")

    try:
        # Test key generation with openssl
        proc = subprocess.run(
            ["openssl", "pkey", "-algorithm", algo, "-text", "-noout"],
            input=b"",
            capture_output=True,
            timeout=15,
        )

        # Also try via genpkey
        proc2 = subprocess.run(
            ["openssl", "genpkey", "-algorithm", algo, "-outform", "PEM"],
            capture_output=True,
            timeout=15,
        )

        if proc2.returncode == 0:
            result["supported"] = True
            result["keygen"] = True
            logger.info("OpenSSL supports %s (%s)", level_name, algo)
        else:
            stderr = proc2.stderr.decode("utf-8", errors="replace")
            result["error"] = stderr.split("\n")[0][:200] if stderr else "keygen failed"

    except subprocess.TimeoutExpired:
        result["error"] = "OpenSSL command timed out"
    except FileNotFoundError:
        result["error"] = "openssl binary not found"

    return result


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204) Validation
# ---------------------------------------------------------------------------

def test_mldsa_support():
    """
    Test ML-DSA (CRYSTALS-Dilithium / FIPS 204) digital signature support.

    Tests key generation, signing, and verification at all three security levels
    using OpenSSL with native support or oqs-provider.

    Returns:
        Dict with ML-DSA validation results
    """
    results = {
        "test_time": datetime.now(timezone.utc).isoformat(),
        "library": None,
        "levels": {},
    }

    algo_map = {
        "ML-DSA-44": "mldsa44",
        "ML-DSA-65": "mldsa65",
        "ML-DSA-87": "mldsa87",
    }

    for level_name, params in MLDSA_PARAMS.items():
        algo = algo_map.get(level_name, "mldsa65")
        level_result = _test_mldsa_openssl(level_name, algo, params)
        results["levels"][level_name] = level_result

    results["library"] = "OpenSSL"
    return results


def _test_mldsa_openssl(level_name, algo, params):
    """Test ML-DSA at a specific level via OpenSSL CLI."""
    result = {
        "level": level_name,
        "security_level": params["security_level"],
        "supported": False,
        "keygen": False,
        "sign": False,
        "verify": False,
        "error": None,
    }

    import tempfile

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "key.pem")
            pub_path = os.path.join(tmpdir, "pub.pem")
            msg_path = os.path.join(tmpdir, "message.txt")
            sig_path = os.path.join(tmpdir, "signature.bin")

            # Generate key pair
            proc = subprocess.run(
                ["openssl", "genpkey", "-algorithm", algo, "-out", key_path],
                capture_output=True, timeout=30,
            )
            if proc.returncode != 0:
                stderr = proc.stderr.decode("utf-8", errors="replace")
                result["error"] = f"keygen failed: {stderr.split(chr(10))[0][:200]}"
                return result
            result["keygen"] = True

            # Extract public key
            proc = subprocess.run(
                ["openssl", "pkey", "-in", key_path, "-pubout", "-out", pub_path],
                capture_output=True, timeout=15,
            )
            if proc.returncode != 0:
                result["error"] = "public key extraction failed"
                return result

            # Create test message
            with open(msg_path, "w") as f:
                f.write("Post-quantum cryptography migration test message")

            # Sign
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-sign",
                 "-inkey", key_path,
                 "-in", msg_path,
                 "-out", sig_path],
                capture_output=True, timeout=30,
            )
            if proc.returncode != 0:
                # Try dgst approach
                proc = subprocess.run(
                    ["openssl", "dgst", "-sign", key_path,
                     "-out", sig_path, msg_path],
                    capture_output=True, timeout=30,
                )
            if proc.returncode == 0:
                result["sign"] = True
            else:
                result["error"] = "signing failed"
                return result

            # Verify
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-verify",
                 "-pubin", "-inkey", pub_path,
                 "-in", msg_path,
                 "-sigfile", sig_path],
                capture_output=True, timeout=30,
            )
            if proc.returncode != 0:
                proc = subprocess.run(
                    ["openssl", "dgst", "-verify", pub_path,
                     "-signature", sig_path, msg_path],
                    capture_output=True, timeout=30,
                )
            if proc.returncode == 0:
                result["verify"] = True
                result["supported"] = True
            else:
                result["error"] = "verification failed"

    except subprocess.TimeoutExpired:
        result["error"] = "OpenSSL command timed out"
    except FileNotFoundError:
        result["error"] = "openssl binary not found"

    return result


# ---------------------------------------------------------------------------
# Migration Roadmap Generation
# ---------------------------------------------------------------------------

def generate_migration_roadmap(scan_results, agility_assessment=None):
    """
    Generate a prioritized PQC migration roadmap.

    Prioritizes systems based on data sensitivity, exposure, crypto-agility,
    compliance requirements, and dependency chains.

    Args:
        scan_results: List of TLS scan results
        agility_assessment: Optional crypto-agility assessment

    Returns:
        Migration roadmap with phased recommendations
    """
    roadmap = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nist_timeline": NIST_MIGRATION_DEADLINES,
        "executive_summary": "",
        "phases": [],
        "risk_register": [],
        "quick_wins": [],
    }

    total = len(scan_results)
    vuln_count = sum(1 for r in scan_results if r.get("quantum_vulnerable"))
    tls13_count = sum(1 for r in scan_results
                      if "1.3" in r.get("tls_version", ""))

    roadmap["executive_summary"] = (
        f"Scanned {total} TLS endpoints: {vuln_count} ({vuln_count/total*100:.0f}%) "
        f"use quantum-vulnerable algorithms. {tls13_count} ({tls13_count/total*100:.0f}%) "
        f"support TLS 1.3 (prerequisite for hybrid PQC). "
        f"NIST mandates deprecation of quantum-vulnerable algorithms by 2030 and "
        f"complete removal by 2035."
    ) if total > 0 else "No endpoints scanned."

    # Phase 1: Immediate (0-6 months)
    phase1_actions = [
        {
            "action": "Complete cryptographic inventory across all systems",
            "priority": "P0",
            "effort": "medium",
            "description": "Extend scanning beyond TLS to include code libraries, "
                           "key stores, HSMs, certificates, VPN configurations, "
                           "and embedded systems.",
        },
        {
            "action": "Upgrade OpenSSL to 3.5+ on development and staging systems",
            "priority": "P0",
            "effort": "low",
            "description": "OpenSSL 3.5 provides native ML-KEM, ML-DSA, SLH-DSA support. "
                           "For OpenSSL 3.0-3.4, install oqs-provider as interim solution.",
        },
        {
            "action": "Enable X25519MLKEM768 hybrid key exchange on TLS 1.3 endpoints",
            "priority": "P1",
            "effort": "low",
            "description": "Add X25519MLKEM768 to supported_groups in TLS configuration. "
                           "This is a drop-in change for servers already on TLS 1.3 with "
                           "OpenSSL 3.5+ or oqs-provider.",
        },
    ]

    # Phase 2: Short-term (6-18 months)
    phase2_actions = [
        {
            "action": "Upgrade all endpoints to TLS 1.3",
            "priority": "P1",
            "effort": "medium",
            "description": f"{total - tls13_count} endpoints need TLS 1.3 upgrade. "
                           "Hybrid PQC key exchange is only available in TLS 1.3.",
        },
        {
            "action": "Deploy hybrid key exchange across production infrastructure",
            "priority": "P1",
            "effort": "medium",
            "description": "Configure X25519MLKEM768 as preferred key exchange group "
                           "on all production TLS endpoints.",
        },
        {
            "action": "Test ML-DSA certificate chains in staging environments",
            "priority": "P2",
            "effort": "high",
            "description": "Issue test certificates with ML-DSA signatures from internal CA. "
                           "Validate certificate chain verification across all clients.",
        },
        {
            "action": "Assess HSM and KMS PQC compatibility",
            "priority": "P2",
            "effort": "medium",
            "description": "Verify that hardware security modules and key management "
                           "systems support PQC key sizes and algorithms.",
        },
    ]

    # Phase 3: Medium-term (18-36 months)
    phase3_actions = [
        {
            "action": "Migrate certificate infrastructure to hybrid or PQC signatures",
            "priority": "P2",
            "effort": "high",
            "description": "Deploy hybrid certificates (classical + ML-DSA) for backward "
                           "compatibility, then transition to pure ML-DSA.",
        },
        {
            "action": "Update code signing and software supply chain to PQC",
            "priority": "P2",
            "effort": "high",
            "description": "Migrate code signing certificates, package signatures, "
                           "and firmware signing to ML-DSA or SLH-DSA.",
        },
        {
            "action": "Replace quantum-vulnerable VPN and IPsec configurations",
            "priority": "P2",
            "effort": "medium",
            "description": "Upgrade VPN concentrators and IPsec configurations to "
                           "support PQC key exchange.",
        },
    ]

    # Phase 4: Long-term (36-60 months, by 2030)
    phase4_actions = [
        {
            "action": "Complete deprecation of all quantum-vulnerable algorithms",
            "priority": "P3",
            "effort": "high",
            "description": "Remove RSA, ECDH, ECDSA, DH, DSA from all systems. "
                           "Ensure 100% PQC coverage before NIST 2030 deadline.",
        },
        {
            "action": "Validate SLH-DSA (FIPS 205) as backup signature standard",
            "priority": "P3",
            "effort": "low",
            "description": "Maintain tested SLH-DSA deployment capability as fallback "
                           "in case ML-DSA is found vulnerable.",
        },
    ]

    roadmap["phases"] = [
        {"name": "Phase 1: Discovery and Quick Wins", "timeline": "0-6 months",
         "actions": phase1_actions},
        {"name": "Phase 2: Hybrid Deployment", "timeline": "6-18 months",
         "actions": phase2_actions},
        {"name": "Phase 3: Full PQC Migration", "timeline": "18-36 months",
         "actions": phase3_actions},
        {"name": "Phase 4: Algorithm Deprecation", "timeline": "36-60 months",
         "actions": phase4_actions},
    ]

    # Quick wins (can be done immediately with minimal effort)
    if tls13_count > 0:
        roadmap["quick_wins"].append({
            "action": f"Enable X25519MLKEM768 on {tls13_count} TLS 1.3 endpoints",
            "effort": "configuration change only",
            "impact": "Immediate quantum-resistant key exchange for existing TLS 1.3 servers",
        })

    roadmap["quick_wins"].append({
        "action": "Increase AES key sizes to 256-bit where currently using 128-bit",
        "effort": "configuration change",
        "impact": "Grover's algorithm halves effective symmetric key strength; "
                  "AES-256 provides 128-bit post-quantum security",
    })

    # Risk register
    roadmap["risk_register"] = [
        {
            "risk": "Harvest Now, Decrypt Later (HNDL) attacks",
            "description": "Adversaries record encrypted traffic today to decrypt when "
                           "quantum computers become available",
            "likelihood": "high",
            "impact": "critical for long-lived secrets (government, healthcare, finance)",
            "mitigation": "Priority migration of systems handling data with >10yr confidentiality",
        },
        {
            "risk": "Algorithm implementation vulnerabilities",
            "description": "Side-channel attacks or implementation bugs in new PQC libraries",
            "likelihood": "medium",
            "impact": "high",
            "mitigation": "Use NIST-validated implementations, conduct security audits, "
                          "deploy hybrid schemes for defense-in-depth",
        },
        {
            "risk": "Performance degradation",
            "description": "PQC algorithms have larger key/signature sizes and may be slower",
            "likelihood": "medium",
            "impact": "medium",
            "mitigation": "Benchmark PQC under production load, optimize TLS handshake "
                          "configurations, consider ML-KEM-768 (balanced performance)",
        },
        {
            "risk": "Compatibility issues",
            "description": "Older clients/devices may not support PQC algorithms",
            "likelihood": "high",
            "impact": "medium",
            "mitigation": "Hybrid schemes ensure backward compatibility; maintain classical "
                          "fallback during transition",
        },
    ]

    return roadmap


# ---------------------------------------------------------------------------
# OpenSSL and oqs-provider Configuration
# ---------------------------------------------------------------------------

def check_openssl_pqc_support():
    """
    Check the local OpenSSL installation for PQC algorithm support.

    Returns:
        Dict with OpenSSL version, provider status, and PQC algorithm availability
    """
    result = {
        "check_time": datetime.now(timezone.utc).isoformat(),
        "openssl_version": "",
        "providers": [],
        "pqc_kem_algorithms": [],
        "pqc_signature_algorithms": [],
        "hybrid_groups": [],
        "pqc_ready": False,
    }

    # Get OpenSSL version
    try:
        proc = subprocess.run(["openssl", "version", "-a"],
                              capture_output=True, timeout=5)
        result["openssl_version"] = proc.stdout.decode().strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        result["error"] = "openssl not found"
        return result

    # List providers
    try:
        proc = subprocess.run(["openssl", "list", "-providers"],
                              capture_output=True, timeout=5)
        output = proc.stdout.decode()
        result["providers"] = [
            line.strip() for line in output.split("\n")
            if line.strip() and "name:" in line.lower()
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check for PQC KEM algorithms
    try:
        proc = subprocess.run(["openssl", "list", "-kem-algorithms"],
                              capture_output=True, timeout=5)
        output = proc.stdout.decode()
        for line in output.split("\n"):
            line = line.strip().lower()
            if any(pqc in line for pqc in ["mlkem", "kyber", "bike", "hqc", "frodo"]):
                result["pqc_kem_algorithms"].append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check for PQC signature algorithms
    try:
        proc = subprocess.run(["openssl", "list", "-signature-algorithms"],
                              capture_output=True, timeout=5)
        output = proc.stdout.decode()
        for line in output.split("\n"):
            line = line.strip().lower()
            if any(pqc in line for pqc in ["mldsa", "dilithium", "slhdsa", "sphincs", "falcon"]):
                result["pqc_signature_algorithms"].append(line)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check for hybrid groups
    try:
        proc = subprocess.run(["openssl", "list", "-tls1-3-groups"],
                              capture_output=True, timeout=5)
        output = proc.stdout.decode()
        for line in output.split("\n"):
            line_stripped = line.strip()
            if any(pqc in line_stripped.lower() for pqc in ["mlkem", "kyber"]):
                result["hybrid_groups"].append(line_stripped)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    result["pqc_ready"] = bool(
        result["pqc_kem_algorithms"] or result["pqc_signature_algorithms"]
    )

    return result


def generate_oqs_provider_config():
    """
    Generate an OpenSSL configuration file for oqs-provider.

    Returns the configuration text for enabling PQC algorithms via
    the Open Quantum Safe provider in OpenSSL 3.x.
    """
    config = """# OpenSSL configuration for oqs-provider (Post-Quantum Cryptography)
# Place at /etc/ssl/openssl-oqs.cnf
# Set OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf before running OpenSSL/nginx/Apache

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
# Adjust path to match your oqs-provider installation
module = /usr/lib/oqs-provider/oqsprovider.so

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
# Hybrid PQC groups: prefer X25519MLKEM768 with classical fallbacks
Groups = x25519_mlkem768:X25519:P-256:P-384

# Minimum TLS version (1.3 required for PQC key exchange)
MinProtocol = TLSv1.2
"""
    return config


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Post-Quantum Cryptography Migration Assessment Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Actions:
  scan_tls        Scan TLS endpoints for quantum-vulnerable algorithms
  assess_agility  Assess crypto-agility from scan results
  test_hybrid_tls Test hybrid PQC TLS key exchange support
  test_mlkem      Test ML-KEM (FIPS 203) key encapsulation
  test_mldsa      Test ML-DSA (FIPS 204) digital signatures
  check_openssl   Check local OpenSSL PQC algorithm support
  roadmap         Generate prioritized PQC migration roadmap
  full_assessment Run complete assessment pipeline

Examples:
  python agent.py --action scan_tls --targets hosts.txt --output scan.json
  python agent.py --action scan_tls --target server.example.com:443
  python agent.py --action test_hybrid_tls --target server.example.com:443
  python agent.py --action test_mlkem --output mlkem.json
  python agent.py --action check_openssl
  python agent.py --action roadmap --scan-results scan.json --output roadmap.json
  python agent.py --action full_assessment --targets hosts.txt --output full_report.json
        """,
    )
    parser.add_argument("--action", required=True, choices=[
        "scan_tls", "assess_agility", "test_hybrid_tls",
        "test_mlkem", "test_mldsa", "check_openssl",
        "roadmap", "full_assessment",
    ])
    parser.add_argument("--target", default=None,
                        help="Single target host[:port] for scanning")
    parser.add_argument("--targets", default=None,
                        help="File with one host[:port] per line")
    parser.add_argument("--port", type=int, default=443,
                        help="Default port for TLS scanning")
    parser.add_argument("--scan-results", default=None,
                        help="Path to previous scan results JSON (for assess/roadmap)")
    parser.add_argument("--agility-results", default=None,
                        help="Path to agility assessment JSON (for roadmap)")
    parser.add_argument("--output", default="pqc_report.json",
                        help="Output file for results")
    args = parser.parse_args()

    report = {
        "agent": "pqc-migration-assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "action": args.action,
        "nist_standards": {
            "FIPS_203": "ML-KEM (CRYSTALS-Kyber) -- Key Encapsulation",
            "FIPS_204": "ML-DSA (CRYSTALS-Dilithium) -- Digital Signatures",
            "FIPS_205": "SLH-DSA (SPHINCS+) -- Digital Signatures (backup)",
        },
    }

    # --- TLS Scanning ---
    scan_results = []
    if args.action in ("scan_tls", "full_assessment"):
        if args.targets:
            scan_results = scan_multiple_endpoints(args.targets, args.port)
        elif args.target:
            host_port = args.target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else args.port
            scan_results = [scan_tls_endpoint(host, port)]
        else:
            print("[!] Provide --target or --targets for TLS scanning")
            sys.exit(1)

        report["tls_scan"] = scan_results
        vuln = sum(1 for r in scan_results if r.get("quantum_vulnerable"))
        print(f"[+] Scanned {len(scan_results)} endpoints: "
              f"{vuln} quantum-vulnerable")
        for r in scan_results:
            status = "VULNERABLE" if r.get("quantum_vulnerable") else "OK"
            err = r.get("error", "")
            if err:
                print(f"    {r['host']}:{r['port']} -- ERROR: {err}")
            else:
                print(f"    {r['host']}:{r['port']} -- [{status}] "
                      f"{r.get('cipher_suite', 'N/A')} ({r.get('tls_version', 'N/A')})")

    # --- Crypto-Agility Assessment ---
    if args.action in ("assess_agility", "full_assessment"):
        if not scan_results and args.scan_results:
            with open(args.scan_results, encoding="utf-8") as f:
                data = json.load(f)
                scan_results = data.get("tls_scan", data) if isinstance(data, dict) else data

        if scan_results:
            agility = assess_crypto_agility(scan_results)
            report["agility_assessment"] = agility
            print(f"[+] Crypto-agility score: {agility['agility_score']}/100")
            print(f"    Risk level: {agility['risk_summary'].get('risk_level', 'unknown')}")
            print(f"    TLS 1.3 ready: {agility['risk_summary'].get('tls13_percentage', 0)}%")
        else:
            print("[!] No scan results available for agility assessment")

    # --- Hybrid TLS Testing ---
    if args.action in ("test_hybrid_tls", "full_assessment"):
        target = args.target
        if not target and scan_results:
            target = f"{scan_results[0]['host']}:{scan_results[0]['port']}"
        if target:
            host_port = target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443
            hybrid_result = test_hybrid_tls_support(host, port)
            report["hybrid_tls"] = hybrid_result
            pqc_status = "SUPPORTED" if hybrid_result["pqc_supported"] else "NOT SUPPORTED"
            print(f"[+] Hybrid TLS (X25519MLKEM768): {pqc_status}")
            print(f"    OpenSSL: {hybrid_result.get('openssl_version', 'unknown')}")
            for group_test in hybrid_result.get("hybrid_groups_tested", []):
                status = "OK" if group_test.get("supported") else "FAIL"
                print(f"    {group_test['group']}: [{status}] "
                      f"{group_test.get('error', '')}")

    # --- ML-KEM Testing ---
    if args.action in ("test_mlkem", "full_assessment"):
        mlkem_result = test_mlkem_support()
        report["mlkem_validation"] = mlkem_result
        print(f"[+] ML-KEM (FIPS 203) validation via {mlkem_result.get('library', 'N/A')}:")
        for level, result in mlkem_result.get("levels", {}).items():
            status = "PASS" if result.get("supported") else "FAIL"
            perf = result.get("performance", {})
            perf_str = ""
            if perf:
                perf_str = (f" (keygen={perf.get('keygen_ms', '?')}ms, "
                            f"encaps={perf.get('encaps_ms', '?')}ms, "
                            f"decaps={perf.get('decaps_ms', '?')}ms)")
            print(f"    {level}: [{status}]{perf_str}")

    # --- ML-DSA Testing ---
    if args.action in ("test_mldsa", "full_assessment"):
        mldsa_result = test_mldsa_support()
        report["mldsa_validation"] = mldsa_result
        print("[+] ML-DSA (FIPS 204) validation:")
        for level, result in mldsa_result.get("levels", {}).items():
            status = "PASS" if result.get("supported") else "FAIL"
            err = result.get("error", "")
            print(f"    {level}: [{status}] {err}")

    # --- OpenSSL PQC Check ---
    if args.action in ("check_openssl", "full_assessment"):
        ossl = check_openssl_pqc_support()
        report["openssl_pqc"] = ossl
        print("[+] OpenSSL PQC support check:")
        print(f"    Version: {ossl.get('openssl_version', 'unknown')}")
        print(f"    PQC ready: {ossl.get('pqc_ready', False)}")
        if ossl.get("pqc_kem_algorithms"):
            print(f"    KEM algorithms: {', '.join(ossl['pqc_kem_algorithms'][:5])}")
        if ossl.get("pqc_signature_algorithms"):
            print(f"    Signature algorithms: {', '.join(ossl['pqc_signature_algorithms'][:5])}")
        if ossl.get("hybrid_groups"):
            print(f"    Hybrid groups: {', '.join(ossl['hybrid_groups'][:5])}")

        if not ossl.get("pqc_ready"):
            print("\n[*] To enable PQC, either:")
            print("    1. Upgrade to OpenSSL 3.5+ (native ML-KEM/ML-DSA)")
            print("    2. Install oqs-provider for OpenSSL 3.0+:")
            print("       https://github.com/open-quantum-safe/oqs-provider")
            config = generate_oqs_provider_config()
            report["oqs_provider_config"] = config

    # --- Migration Roadmap ---
    if args.action in ("roadmap", "full_assessment"):
        if not scan_results and args.scan_results:
            with open(args.scan_results, encoding="utf-8") as f:
                data = json.load(f)
                scan_results = data.get("tls_scan", data) if isinstance(data, dict) else data

        agility = None
        if args.agility_results:
            with open(args.agility_results, encoding="utf-8") as f:
                agility = json.load(f)

        if scan_results:
            roadmap = generate_migration_roadmap(scan_results, agility)
            report["migration_roadmap"] = roadmap
            print("\n[+] Migration Roadmap")
            print(f"    {roadmap['executive_summary']}")
            print(f"\n    NIST Timeline: deprecation by {NIST_MIGRATION_DEADLINES['deprecation']}, "
                  f"removal by {NIST_MIGRATION_DEADLINES['disallowed']}")
            for phase in roadmap["phases"]:
                print(f"\n    {phase['name']} ({phase['timeline']}):")
                for action in phase["actions"]:
                    print(f"      [{action['priority']}] {action['action']}")
            if roadmap["quick_wins"]:
                print("\n    Quick Wins:")
                for qw in roadmap["quick_wins"]:
                    print(f"      - {qw['action']}")
        else:
            print("[!] No scan results available for roadmap generation")

    # --- Write report ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
