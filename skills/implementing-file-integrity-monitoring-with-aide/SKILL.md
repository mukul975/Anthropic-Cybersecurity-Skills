---
name: implementing-file-integrity-monitoring-with-aide
description: "Configures AIDE (Advanced Intrusion Detection Environment) for file integrity monitoring on Linux, covering baseline database creation, scheduled integrity checks via cron, change detection, and alerting on unauthorized modifications. Use when setting up host-based file integrity monitoring, detecting unauthorized file changes, or meeting compliance requirements for FIM on Linux systems. Keywords: AIDE, file integrity monitoring, FIM, baseline database, cron integrity check, Linux, change detection. Do not use for multi-tool HIDS with OSSEC or Wazuh - use configuring-host-based-intrusion-detection; for Linux CIS hardening - use hardening-linux-endpoint-with-cis-benchmark."
domain: cybersecurity
subdomain: endpoint-security
tags:
- aide
- file-integrity
- hids
- baseline
- intrusion-detection
- compliance
- linux-security
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
mitre_attack:
- T1055
- T1547
- T1059
- T1036
---

# Implementing File Integrity Monitoring with AIDE

## Overview

AIDE (Advanced Intrusion Detection Environment) is a host-based intrusion detection system that monitors file and directory integrity using cryptographic checksums. This skill covers generating AIDE configuration files, initializing baseline databases, running integrity checks, parsing change reports, and setting up automated cron-based monitoring with alerting.


## When to Use

- When deploying or configuring implementing file integrity monitoring with aide capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- AIDE installed on target Linux system (apt install aide / yum install aide)
- Root or sudo access for file system scanning
- Python 3.8+ with standard library

## Steps

1. **Generate AIDE Configuration** — Create aide.conf with monitoring rules for critical directories (/etc, /bin, /sbin, /usr/bin, /boot)
2. **Initialize Baseline Database** — Run aide --init to create the initial file integrity baseline
3. **Run Integrity Check** — Execute aide --check to compare current state against baseline
4. **Parse Change Report** — Extract added, removed, and changed files from AIDE output
5. **Configure Automated Monitoring** — Generate cron job for scheduled integrity checks
6. **Generate Compliance Report** — Produce structured report of all file changes with severity classification

## Expected Output

- AIDE configuration file (aide.conf)
- Baseline database creation status
- JSON report of file changes (added/removed/changed) with severity
- Cron job configuration for automated monitoring
