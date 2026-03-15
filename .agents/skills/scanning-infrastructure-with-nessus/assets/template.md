# Nessus Infrastructure Scan Report Template

## Scan Information
| Field | Value |
|-------|-------|
| Scan Name | [SCAN_NAME] |
| Scan Date | [YYYY-MM-DD HH:MM] |
| Scanner | Tenable Nessus Professional [VERSION] |
| Policy | [POLICY_NAME] |
| Target Range | [TARGET_CIDR] |
| Scan Type | Authenticated / Unauthenticated |
| Duration | [HH:MM:SS] |

## Executive Summary

This vulnerability assessment identified **[TOTAL]** findings across **[HOST_COUNT]** hosts in the **[ENVIRONMENT]** environment. The scan was conducted on [DATE] using [AUTHENTICATED/UNAUTHENTICATED] scanning with the [POLICY] scan policy.

### Severity Distribution
| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | [N] | [%] |
| High | [N] | [%] |
| Medium | [N] | [%] |
| Low | [N] | [%] |
| Informational | [N] | [%] |
| **Total** | **[N]** | **100%** |

### Key Metrics
- **Unique CVEs Identified**: [N]
- **Exploitable Vulnerabilities**: [N]
- **Hosts with Critical Findings**: [N]
- **Average CVSS Score**: [N.N]

## Critical and High Findings

### Finding 1: [PLUGIN_NAME]
- **Plugin ID**: [NESSUS_PLUGIN_ID]
- **Severity**: Critical / High
- **CVSS Score**: [N.N]
- **CVE**: [CVE-YYYY-NNNNN]
- **Affected Hosts**: [COUNT]
- **Synopsis**: [Brief description of the vulnerability]
- **Impact**: [Description of potential impact if exploited]
- **Solution**: [Recommended remediation steps]
- **Affected Systems**:
  | Host | IP Address | Port | Service |
  |------|-----------|------|---------|
  | [hostname] | [IP] | [port] | [service] |

### Finding 2: [PLUGIN_NAME]
[Repeat structure for each critical/high finding]

## Remediation Priorities

### Immediate (0-48 hours)
1. [Critical finding requiring immediate patching]
2. [Exploitable vulnerability with public PoC]

### Short-term (1-2 weeks)
1. [High severity findings with available patches]
2. [Configuration weaknesses with easy remediation]

### Medium-term (30 days)
1. [Medium severity findings]
2. [Hardening recommendations]

### Long-term (90 days)
1. [Architecture improvements]
2. [Legacy system migration plans]

## Host Risk Rankings

| Rank | Hostname | IP Address | OS | Risk Score | Critical | High | Medium |
|------|----------|-----------|-----|------------|----------|------|--------|
| 1 | [host] | [IP] | [OS] | [score] | [N] | [N] | [N] |
| 2 | [host] | [IP] | [OS] | [score] | [N] | [N] | [N] |

## Scan Coverage

### Successfully Scanned
- Total targets: [N]
- Successfully scanned: [N]
- Credentialed checks successful: [N]

### Scan Gaps
- Unreachable hosts: [N] - [list IPs]
- Authentication failures: [N] - [list IPs]
- Scan timeouts: [N] - [list IPs]

## Trending (if applicable)

| Metric | Previous Scan | Current Scan | Change |
|--------|--------------|--------------|--------|
| Critical | [N] | [N] | [+/-N] |
| High | [N] | [N] | [+/-N] |
| Medium | [N] | [N] | [+/-N] |
| Total Findings | [N] | [N] | [+/-N] |
| Mean Time to Remediate | [N days] | [N days] | [+/-N] |

## Appendices

### A. Scan Configuration
- Port Range: [1-65535 / Common Ports]
- Plugin Families Enabled: [List families]
- Credentials Used: [SSH / WinRM / SNMP / Database]
- Excluded Hosts: [List if applicable]

### B. Methodology
This assessment follows NIST SP 800-115 guidelines for vulnerability scanning. Scans were performed with [authenticated/unauthenticated] access using Nessus Professional with current plugin feed.

### C. Disclaimers
- This scan represents a point-in-time assessment
- New vulnerabilities may be discovered after this scan
- False positives may exist; manual verification is recommended for critical findings
- Scan coverage may be affected by network segmentation and firewall rules
