---
name: detecting-malicious-npm-packages
description: Triage npm packages and lockfiles for install-script malware, credential exfiltration, and worming behavior using GuardDog, manual tarball inspection, and dynamic detonation with network/filesystem monitoring. Use when vetting a new dependency, reviewing a package.json/package-lock.json during code review, checking lockfiles against a supply-chain advisory's known-bad versions, or investigating a host suspected of installing a trojanized package. Do not use for name-similarity typosquatting detection - use detecting-typosquatting-packages-in-npm-pypi.
domain: cybersecurity
subdomain: supply-chain-security
tags:
- supply-chain-security
- npm
- malware-analysis
- guarddog
- install-scripts
- exfiltration
- static-analysis
- threat-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-09
mitre_attack:
- T1195.002
---
# Detecting Malicious npm Packages

> **Legal Notice:** Analyze packages in an isolated, disposable environment. Some malicious packages execute on install (`npm install` runs lifecycle scripts automatically) or on import. Never analyze a suspect package on a workstation with credentials, SSH keys, cloud tokens, or network access to production. This skill is for defensive analysis and authorized incident response only.

## Overview

The npm registry is the largest software package ecosystem in the world and the most heavily targeted by supply-chain attackers. Malicious packages reach victims through typosquatting (`expresss`, `crossenv`), dependency confusion, account/maintainer takeover (the 2025 Shai-Hulud worm and the `event-stream` compromise are canonical examples), and starjacking. The defining danger of npm is that `npm install` automatically runs `preinstall`, `install`, and `postinstall` lifecycle scripts with the developer's full privileges **before any application code is invoked** — so simply installing a package is enough to be compromised. Roughly 2% of npm packages use install scripts, which makes them both common and a powerful malware delivery vehicle.

Typical malicious behaviors are: exfiltrating environment variables, `~/.npmrc` tokens, SSH keys, and cloud credentials to an attacker-controlled URL; opening reverse shells; dropping cryptominers; reading and posting `process.env`; obfuscating payloads with base64/eval; and self-propagating (worming) by stealing the maintainer's npm token and republishing trojanized versions of other packages they own.

This skill provides a repeatable triage workflow centered on **GuardDog** (Datadog's open-source heuristic scanner built on Semgrep + metadata rules), supplemented by manual tarball inspection, lockfile-based compromise checks against known-bad version lists, and dynamic detonation with network and filesystem monitoring. The goal is to decide, quickly and safely, whether a given package or a project's dependency tree contains malicious code.

## When to Use

- Triaging a specific npm package before adding it as a dependency.
- Vetting a full `package.json` / `package-lock.json` during code review or onboarding a third-party library.
- Responding to a supply-chain advisory (e.g., a worm campaign) and needing to check whether your lockfiles pulled a known-bad version.
- Investigating an endpoint or CI runner suspected of having installed a trojanized package.
- Building a pre-install gate in CI/CD that blocks packages exhibiting malicious indicators.

## Prerequisites

- An isolated VM or disposable container with **no production credentials** and snapshot/rollback capability.
- GuardDog:
  ```bash
  pip install guarddog
  # or run via Docker without local install:
  docker pull ghcr.io/datadog/guarddog
  alias guarddog='docker run --rm ghcr.io/datadog/guarddog'
  ```
- Node.js + npm (use `--ignore-scripts` when downloading for analysis).
- `jq`, `tar`, and optionally OSV-Scanner for known-vulnerability/known-malicious cross-checks:
  ```bash
  go install github.com/google/osv-scanner/cmd/osv-scanner@v1
  ```
- For dynamic analysis: a sandbox with egress logging (e.g., `tcpdump`, a DNS sink, or a network namespace).

## Objectives

- Statically scan an npm package (or a whole dependency tree) for malicious heuristics without executing it.
- Identify install-script abuse, environment/credential exfiltration, obfuscation, and silent process execution.
- Cross-check lockfile-pinned versions against known-malicious version lists / OSV.
- Safely detonate a suspect package and observe network and filesystem behavior.
- Extract indicators of compromise (URLs, IPs, hashes) for blocking and threat intel.
- Produce a defensible verdict (benign / suspicious / malicious) with evidence.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Core technique — trojanized npm package delivered through the registry. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious install scripts / module code execute attacker JavaScript. |
| T1552.001 | Unsecured Credentials: Credentials In Files | Packages steal `~/.npmrc`, `.env`, SSH keys, and cloud credential files. |
| T1041 | Exfiltration Over C2 Channel | Stolen secrets posted to attacker HTTP(S) endpoints. |
| T1027 | Obfuscated Files or Information | base64/eval/hex obfuscation hides the payload from review. |

## Workflow

### 1. Download the package without executing it
Fetch the tarball with scripts disabled so nothing runs during acquisition.
```bash
mkdir triage && cd triage
# Resolve the tarball URL and download it (no install, no scripts)
npm pack express@4.18.2            # produces express-4.18.2.tgz
# or for an arbitrary version:
npm view some-pkg@1.2.3 dist.tarball
curl -sL "$(npm view some-pkg@1.2.3 dist.tarball)" -o some-pkg.tgz
tar -xzf some-pkg.tgz              # extracts into ./package
```

### 2. Scan a single package with GuardDog
GuardDog applies metadata + source heuristics and prints which rules matched.
```bash
# Scan the latest published version from the registry
guarddog npm scan express

# Scan a specific version
guarddog npm scan some-pkg --version 1.2.3

# Scan the local tarball / extracted directory you downloaded above
guarddog npm scan ./some-pkg.tgz
guarddog npm scan ./package/
```

### 3. Verify an entire dependency tree
`verify` scans every dependency declared in a manifest — ideal for code review.
```bash
guarddog npm verify /path/to/repo/package.json
```

### 4. Focus on the highest-signal heuristics
Filter to the npm rules most indicative of malware to cut noise during triage.
```bash
guarddog npm scan some-pkg \
  --rules npm-install-script \
  --rules npm-serialize-environment \
  --rules npm-exec-base64 \
  --rules npm-silent-process-execution \
  --rules npm-obfuscation \
  --rules shady-links \
  --rules typosquatting
```

### 5. Emit machine-readable output for pipelines
JSON for tooling, SARIF for GitHub code scanning.
```bash
guarddog npm scan some-pkg --output-format=json   > guarddog.json
guarddog npm verify package.json --output-format=sarif > guarddog.sarif
```

### 6. Manually inspect lifecycle scripts and source
Lifecycle scripts are the first thing to read; obfuscation and outbound URLs are red flags.
```bash
# Show all lifecycle hooks
jq '.scripts' package/package.json

# Hunt for exfiltration / execution primitives in the source
grep -rEn "child_process|exec\(|spawn|eval\(|Buffer\.from\(.*base64|process\.env|https?://" package/ \
  --include='*.js' --include='*.ts' | head -50
```

### 7. Cross-check lockfiles against known-malicious versions
During an active campaign, compare pinned versions to the advisory's bad-version list, and run OSV.
```bash
# Extract resolved name@version pairs from a v3 lockfile
jq -r '.packages | to_entries[] | select(.key|startswith("node_modules/")) | "\(.key|ltrimstr("node_modules/"))@\(.value.version)"' package-lock.json

# OSV-Scanner flags known-vulnerable AND known-malicious (MAL-) advisories
osv-scanner --lockfile=package-lock.json
```

### 8. Detonate safely with monitoring (only if static is inconclusive)
Run the install inside a disposable, network-monitored sandbox.
```bash
# In a throwaway container / VM with egress capture running (tcpdump -w capture.pcap):
npm install ./some-pkg.tgz            # scripts WILL run — sandbox only
# Baseline-diff the filesystem afterwards for writes outside node_modules,
# and inspect capture.pcap for unexpected DNS / HTTP beacons.
```

### 9. Extract and operationalize IOCs
Pull URLs, IPs, and hashes for blocking and intel sharing.
```bash
grep -rhoE "https?://[a-zA-Z0-9./?=_%:-]+" package/ | sort -u > urls.txt
sha256sum some-pkg.tgz package/*.js > hashes.txt
```

### 10. Run the bundled triage helper
`agent.py` orchestrates GuardDog, lifecycle-script inspection, and IOC extraction into one report.
```bash
python scripts/agent.py --package some-pkg --version 1.2.3 --output verdict.json
# or against a local tarball:
python scripts/agent.py --tarball ./some-pkg.tgz --output verdict.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| GuardDog | Heuristic npm/PyPI/Go malware scanner | https://github.com/DataDog/guarddog |
| OSV-Scanner | Known-vulnerable & known-malicious (MAL-) advisory matching | https://github.com/google/osv-scanner |
| OSV malicious DB | Open-source malicious package advisories | https://github.com/ossf/malicious-packages |
| npm lifecycle docs | preinstall/install/postinstall semantics | https://docs.npmjs.com/cli/v10/using-npm/scripts |
| Datadog Security Labs | npm campaign writeups & rules | https://securitylabs.datadoghq.com/ |
| Semgrep | Rule engine GuardDog uses for source heuristics | https://semgrep.dev/ |

## Validation Criteria

- [ ] Package acquired with scripts disabled in an isolated environment.
- [ ] GuardDog `scan` run on the target version with results captured.
- [ ] Full dependency tree run through GuardDog `verify` where applicable.
- [ ] Lifecycle scripts (`preinstall`/`install`/`postinstall`) read and assessed.
- [ ] Lockfile versions cross-checked against OSV / known-bad lists.
- [ ] Dynamic detonation performed in a sandbox if static analysis was inconclusive.
- [ ] IOCs (URLs, IPs, hashes) extracted and recorded.
- [ ] Documented verdict (benign / suspicious / malicious) with supporting evidence.
- [ ] Malicious findings reported to the registry and shared as threat intel.
