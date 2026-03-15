---
name: performing-supply-chain-attack-simulation
description: Simulate and detect software supply chain attacks including typosquatting detection via Levenshtein distance, dependency confusion testing against private registries, package hash verification with pip, and known vulnerability scanning with pip-audit.
domain: cybersecurity
subdomain: application-security
tags: [supply-chain, typosquatting, dependency-confusion, package-verification, pip-audit, PyPI, software-composition-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Supply Chain Attack Simulation

## Overview

Software supply chain attacks exploit trust in package registries through typosquatting (registering names similar to popular packages), dependency confusion (publishing higher-version public packages matching private names), and compromised package distribution. This skill detects these attack vectors by computing Levenshtein distance between package names and popular PyPI packages, verifying package integrity via SHA-256 hash comparison, scanning for known CVEs with pip-audit, and testing dependency resolution order for confusion vulnerabilities.

## Prerequisites

- Python 3.9+ with `pip-audit`, `Levenshtein`, `requests`
- Access to PyPI JSON API (https://pypi.org/pypi/{package}/json)
- Network access for package metadata retrieval

## Key Detection Areas

1. **Typosquatting** — compare package names against top PyPI packages using edit distance thresholds
2. **Dependency confusion** — check if internal package names exist on public PyPI with higher version numbers
3. **Hash verification** — download packages and verify SHA-256 digests match published hashes
4. **Vulnerability scanning** — audit installed packages against OSV and PyPA advisory databases
5. **Metadata anomalies** — flag packages with suspicious author emails, missing homepages, or very recent first upload dates

## Output

JSON report with risk scores per package, detected attack vectors, hash verification results, and CVE findings.
