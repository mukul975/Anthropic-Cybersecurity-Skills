---
name: detecting-anomalous-authentication-patterns
description: Detects anomalous authentication patterns using UEBA analytics, statistical baselines, and machine learning models to identify impossible travel, credential stuffing, brute force, password spraying, and compromised account behaviors across authentication logs. Use when detecting authentication anomalies, analyzing login behavior, implementing UEBA for sign-ins, or investigating suspicious authentication events. Do not use for broad user behavior analytics beyond authentication - use performing-user-behavior-analytics.
domain: cybersecurity
subdomain: identity-access-management
tags:
- UEBA
- authentication-anomaly
- impossible-travel
- brute-force
- credential-stuffing
- behavioral-analytics
version: '1.0'
author: mahipal
license: Apache-2.0
atlas_techniques:
- AML.T0043
- AML.T0018
nist_ai_rmf:
- MEASURE-2.7
- MEASURE-2.5
- MAP-5.1
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
mitre_attack:
- T1110
- T1110.003
- T1110.004
- T1078
- T1021
mitre_f3:
  version: '1.1'
  tactics:
  - initial-access
  - positioning
  techniques:
  - id: T1110.004
    name: 'Brute Force:  Credential Stuffing'
    tactic: initial-access
    source: attack
  - id: T1110.003
    name: 'Brute Force: Password Spraying'
    tactic: initial-access
    source: attack
  - id: F1006
    name: Account Takeover
    tactic: initial-access
    source: f3
  - id: F1006.002
    name: 'Account Takeover: Exposed Login Credential'
    tactic: initial-access
    source: f3
  - id: T1539
    name: Steal Web Session Cookie
    tactic: positioning
    source: attack
---

# Detecting Anomalous Authentication Patterns

## When to Use

- Security operations needs to identify compromised accounts from authentication log analysis
- Implementing impossible travel detection to flag geographically inconsistent logins
- Detecting brute force, password spraying, and credential stuffing attacks in real time
- Building behavioral baselines for users to identify deviations indicating account compromise
- Correlating authentication anomalies with threat intelligence for lateral movement detection
- Investigating alerts from SIEM or IdP for suspicious sign-in activity

**Do not use** for static rule-based alerting on single failed logins; anomaly detection requires statistical baselines across time and entity dimensions to reduce false positives.

## Prerequisites

- Authentication log sources (Azure AD/Entra ID sign-in logs, Okta system logs, Active Directory event logs 4624/4625/4648/4768/4771)
- SIEM platform (Splunk, Microsoft Sentinel, Elastic SIEM) with at least 90 days of baseline data
- GeoIP database for location-based anomaly detection (MaxMind GeoLite2 or IP2Location)
- Python 3.9+ with pandas, scikit-learn, and scipy for custom analytics
- User identity context (department, role, typical work hours, location)

## Workflow

### Step 1: Collect and Normalize Authentication Logs

Aggregate authentication events from all identity sources. Normalize Azure AD/Entra ID, Okta, and Windows AD events to a common schema (timestamp, user, source_ip, location, result, app, device), then enrich Windows AD events that lack location with GeoIP lookups.

See `references/detection-code.md` (Step 1) for the `normalize_auth_logs()` and `enrich_geoip()` implementations.

### Step 2: Detect Impossible Travel Anomalies

Identify logins from geographically impossible locations. Compute the great-circle (haversine) distance between consecutive successful logins for each user, divide by the time delta, and flag any pair whose required travel speed exceeds ~900 km/h over a distance greater than 100 km.

See `references/detection-code.md` (Step 2) for the `haversine_distance()` and `detect_impossible_travel()` implementations.

### Step 3: Detect Brute Force and Password Spraying

Identify credential attack patterns across authentication logs. Brute force detection uses a sliding window to flag many failed attempts against a single account; password spray detection groups failures by source IP to flag many targeted users with few attempts each, then checks for successful logins after the spray window (compromised accounts).

See `references/detection-code.md` (Step 3) for the `detect_brute_force()` and `detect_password_spray()` implementations.

### Step 4: Build Behavioral Baselines and Detect Deviations

Create user behavioral profiles and flag statistical anomalies. `build_user_baseline()` profiles typical hours (with z-score bounds), days, IPs, countries, apps, and devices over a 90-day lookback. `detect_behavioral_anomalies()` compares a new event against that baseline (off-hours, new IP, new country, new app, new device, weekend logins). `isolation_forest_anomaly_detection()` adds unsupervised multivariate detection over engineered features.

See `references/detection-code.md` (Step 4) for the `build_user_baseline()`, `detect_behavioral_anomalies()`, and `isolation_forest_anomaly_detection()` implementations.

### Step 5: Implement SIEM Detection Rules

Deploy detection rules for common authentication attack patterns (brute force, password spray, impossible travel, credential stuffing) directly in the SIEM to complement the Python analytics.

See `references/siem-detection-rules.md` for the ready-to-deploy Splunk SPL queries.

### Step 6: Correlate and Score Authentication Anomalies

Combine multiple detection signals into a composite risk score. Each anomaly type carries a base weight (impossible travel 40, MFA bypass 45, password spray 35, etc.) adjusted by a severity multiplier; the summed score normalizes to 0-100 and maps to a risk level with a recommended action (suspension, MFA re-enrollment, step-up auth, monitor).

See `references/detection-code.md` (Step 6) for the `calculate_auth_risk_score()` implementation.

## Key Concepts

| Term | Definition |
|------|------------|
| **Impossible Travel** | Authentication anomaly where a user logs in from two geographically distant locations within a timeframe that makes physical travel impossible |
| **Password Spraying** | Credential attack that tries a small number of commonly used passwords against many accounts to avoid lockout thresholds |
| **Credential Stuffing** | Automated attack using stolen username/password pairs from data breaches to gain unauthorized access to accounts |
| **UEBA** | User and Entity Behavior Analytics technology that builds behavioral baselines and detects deviations using machine learning and statistical analysis |
| **Behavioral Baseline** | Statistical profile of a user's normal authentication patterns including typical hours, locations, devices, and applications |
| **Isolation Forest** | Unsupervised machine learning algorithm that detects anomalies by isolating observations that differ from the majority of data points |
| **Risk Score** | Composite numerical value aggregating multiple anomaly signals with weighted scoring to prioritize authentication threats |

## Tools & Systems

- **Microsoft Sentinel UEBA**: Cloud-native SIEM with built-in entity behavior analytics for Azure AD and multi-cloud authentication anomaly detection
- **Exabeam Advanced Analytics**: UEBA platform using machine learning for user session analysis and automated threat timeline construction
- **Splunk UBA**: Behavioral analytics add-on for Splunk providing pre-built authentication anomaly models and risk scoring
- **Elastic SIEM ML Jobs**: Machine learning anomaly detection jobs for authentication log analysis in the Elastic Stack

## Common Scenarios

### Scenario: Detecting Compromised Executive Account After Password Spray

**Context**: SOC observes a spike in failed authentication attempts from a cloud VPS IP address targeting 200+ accounts. Two hours later, an executive account shows successful authentication from the same IP range followed by mailbox rule creation and data exfiltration.

**Approach**:
1. Run password spray detection across the timeframe to identify all targeted accounts
2. Cross-reference targeted accounts with subsequent successful logins from related IP ranges
3. Build behavioral baseline for the executive account and flag all deviations
4. Check for impossible travel between the executive's last legitimate login and the attacker's session
5. Identify post-compromise activity: mailbox rules, file downloads, delegated access changes
6. Calculate composite risk score combining password spray, new IP, off-hours login, and new device signals
7. Trigger automated response: force session termination, disable account, notify manager

**Pitfalls**:
- Relying on single-signal detection (failed logins only) misses successful spray results
- Not correlating across identity providers when users have accounts in multiple IdPs
- Static thresholds that do not account for legitimate VPN IP changes or travel
- Ignoring successful authentications after the spray window closes (attackers may wait before using credentials)

## Output Format

```
AUTHENTICATION ANOMALY DETECTION REPORT
=========================================
Analysis Period:   2026-02-01 to 2026-02-24
Total Auth Events: 2,847,392
Users Monitored:   3,847
Alert Sources:     Azure AD, Okta, Windows AD

THREAT DETECTION SUMMARY
Password Spray Attacks:    3
Brute Force Attacks:       12
Impossible Travel:         8
Credential Stuffing:       1
Behavioral Anomalies:      47

HIGH-RISK ACCOUNTS
[CRITICAL] j.smith@corp.com     Score: 92
  - Impossible travel: Chicago -> Moscow (7,876 km in 0.5h)
  - Password spray target followed by successful login
  - New device and browser fingerprint
  - Off-hours access to SharePoint and email
  Action: Account suspended, SOC investigation initiated

[HIGH] m.johnson@corp.com       Score: 67
  - Login from new country (Brazil)
  - New source IP not matching VPN ranges
  - Access to HR application outside normal pattern
  Action: MFA re-enrollment required, manager notified

[MEDIUM] a.williams@corp.com    Score: 38
  - Weekend login at 03:00 UTC
  - New device (Linux, typically Windows user)
  Action: Step-up authentication applied

ATTACK CAMPAIGN DETAILS
Password Spray Campaign #1:
  Source:            185.220.101.x/24 (Tor exit node)
  Targeted Users:    247
  Success Rate:      0.8% (2 accounts compromised)
  Compromised:       j.smith@corp.com, r.davis@corp.com
  Duration:          45 minutes
  Pattern:           2 attempts per user, 3-second interval
```
