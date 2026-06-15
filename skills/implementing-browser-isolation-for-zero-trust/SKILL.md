---
name: implementing-browser-isolation-for-zero-trust
description: 'Deploys remote browser isolation (RBI) as a core component of a Zero
  Trust architecture. Implements isolation policies with URL categorization and risk-based
  routing, content disarming and reconstruction (CDR) for file sanitization, data
  loss prevention controls within isolated sessions, and integration with Secure Web
  Gateway and ZTNA platforms. Based on Cloudflare Browser Isolation, Menlo Security,
  and Zscaler RBI approaches. Use when hardening web access against zero-day exploits,
  phishing, credential theft, and browser-based data exfiltration.

  '
domain: cybersecurity
subdomain: network-security
tags:
- browser-isolation
- zero-trust
- RBI
- CDR
- URL-categorization
- content-disarming
- secure-web-gateway
version: '1.0'
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1003
---

# Implementing Browser Isolation for Zero Trust

## When to Use

- When deploying remote browser isolation as part of a Zero Trust security architecture
- When protecting users from zero-day browser exploits and drive-by downloads
- When implementing content disarming and reconstruction for file downloads
- When enforcing data loss prevention policies for web browsing sessions
- When securing access to untrusted or uncategorized websites
- When integrating browser isolation with existing SWG and ZTNA infrastructure
- When protecting against phishing and credential theft via isolated rendering

## Prerequisites

- Familiarity with Zero Trust architecture principles and network security
- Understanding of Secure Web Gateway (SWG) and proxy deployment models
- Access to a test or lab environment for policy validation
- Python 3.8+ with required dependencies installed
- DNS and proxy infrastructure for traffic routing

## Instructions

### Phase 1: URL Categorization and Risk Classification

Build a URL categorization engine that classifies websites by risk level to
determine isolation policy. URLs are scored based on threat intelligence feeds,
domain reputation, content category, and historical risk indicators.

```python
from agent import BrowserIsolationPolicyEngine

engine = BrowserIsolationPolicyEngine(
    organization="Acme Corp",
    default_isolation_mode="isolate_risky",
)

# Classify a URL and determine isolation action
result = engine.classify_url("https://docs.google.com/spreadsheets/d/abc123")
print(f"Category: {result['category']}")
print(f"Risk Level: {result['risk_level']}")
print(f"Isolation Action: {result['action']}")
# Output: Category: cloud_productivity
#         Risk Level: low
#         Action: allow_direct

result = engine.classify_url("https://unknown-sketchy-domain.xyz/download.html")
print(f"Category: {result['category']}")
print(f"Risk Level: {result['risk_level']}")
print(f"Isolation Action: {result['action']}")
# Output: Category: uncategorized
#         Risk Level: high
#         Action: full_isolation
```

### Phase 2: Isolation Policy Configuration

Define isolation policies that map URL categories and risk levels to specific
isolation modes and DLP restrictions. Policies support granular controls including
clipboard, file download, upload, and printing restrictions.

```python
# Configure isolation policies
engine.add_isolation_policy(
    name="Block Uncategorized Sites",
    description="Fully isolate all uncategorized or newly registered domains",
    match_criteria={
        "url_categories": ["uncategorized", "newly_registered"],
        "risk_levels": ["high", "critical"],
    },
    isolation_mode="full_isolation",
    dlp_controls={
        "disable_copy_paste": True,
        "disable_download": True,
        "disable_upload": True,
        "disable_printing": True,
        "disable_keyboard_input": False,
        "watermark_session": True,
    },
)

engine.add_isolation_policy(
    name="Isolate Webmail with DLP",
    description="Isolate personal webmail with download restrictions",
    match_criteria={
        "url_categories": ["webmail"],
        "domains": ["mail.google.com", "outlook.live.com", "mail.yahoo.com"],
    },
    isolation_mode="read_only_isolation",
    dlp_controls={
        "disable_copy_paste": True,
        "disable_download": True,
        "disable_upload": True,
        "disable_printing": True,
        "disable_keyboard_input": False,
        "watermark_session": False,
    },
)

engine.add_isolation_policy(
    name="CDR for File Downloads",
    description="Apply content disarm and reconstruction to all file downloads",
    match_criteria={
        "url_categories": ["*"],
        "file_types": ["pdf", "docx", "xlsx", "pptx", "zip", "exe", "msi"],
    },
    isolation_mode="cdr_passthrough",
    cdr_config={
        "strip_macros": True,
        "strip_embedded_objects": True,
        "strip_javascript": True,
        "strip_active_content": True,
        "flatten_pdf": True,
        "reconstruct_to_safe_format": True,
        "max_file_size_mb": 50,
        "allowed_file_types": ["pdf", "docx", "xlsx", "pptx", "png", "jpg"],
    },
)

engine.add_isolation_policy(
    name="Allow Trusted SaaS Direct",
    description="Allow direct access to sanctioned SaaS applications",
    match_criteria={
        "url_categories": ["cloud_productivity", "business_saas"],
        "domains": [
            "*.office365.com", "*.office.com", "*.microsoft.com",
            "*.salesforce.com", "*.slack.com", "*.github.com",
        ],
        "risk_levels": ["low"],
    },
    isolation_mode="allow_direct",
    dlp_controls={
        "disable_copy_paste": False,
        "disable_download": False,
        "disable_upload": False,
        "log_all_downloads": True,
    },
)

# List all policies
for policy in engine.list_policies():
    print(f"  [{policy['priority']}] {policy['name']} -> {policy['isolation_mode']}")
```

### Phase 3: Content Disarming and Reconstruction (CDR)

Implement CDR processing to sanitize downloaded files by deconstructing them,
stripping potentially malicious elements (macros, embedded objects, scripts),
and reconstructing clean versions that preserve usability.

```python
# Process a file through CDR
cdr_result = engine.process_file_cdr(
    file_path="/tmp/downloads/quarterly_report.docx",
    source_url="https://partner-portal.example.com/reports/q4.docx",
    cdr_profile="strict",
)

print(f"Original file: {cdr_result['original']['filename']}")
print(f"Original size: {cdr_result['original']['size_bytes']} bytes")
print(f"Threats found: {cdr_result['threats_found']}")
for threat in cdr_result['threats_detail']:
    print(f"  - {threat['type']}: {threat['description']} [{threat['action']}]")
print(f"Clean file: {cdr_result['reconstructed']['filename']}")
print(f"Clean size: {cdr_result['reconstructed']['size_bytes']} bytes")
print(f"File integrity preserved: {cdr_result['reconstructed']['usable']}")

# Example output:
# Original file: quarterly_report.docx
# Original size: 245760 bytes
# Threats found: 3
#   - macro: VBA macro with AutoOpen trigger [STRIPPED]
#   - embedded_ole: Embedded OLE object (executable) [STRIPPED]
#   - external_link: External template reference [STRIPPED]
# Clean file: quarterly_report_clean.docx
# Clean size: 198432 bytes
# File integrity preserved: True
```

### Phase 4: Session Control and Monitoring

Implement real-time session monitoring for isolated browsing sessions with
keystroke logging policy, clipboard interception, and download tracking.
Integrate with SIEM for security event correlation.

```python
# Create an isolation session
session = engine.create_isolation_session(
    user_id="jsmith@acme.com",
    user_groups=["engineering", "contractors"],
    device_posture={
        "os": "Windows 11",
        "managed": True,
        "edr_running": True,
        "disk_encrypted": True,
        "os_patched": True,
    },
    target_url="https://external-vendor.example.com/portal",
)

print(f"Session ID: {session['session_id']}")
print(f"Isolation Mode: {session['isolation_mode']}")
print(f"Applied Policy: {session['applied_policy']}")
print(f"DLP Controls: {json.dumps(session['dlp_controls'], indent=2)}")

# Monitor session events
events = engine.get_session_events(session_id=session["session_id"])
for event in events:
    print(f"  [{event['timestamp']}] {event['event_type']}: {event['details']}")

# Generate session audit report
audit = engine.generate_session_audit(
    user_id="jsmith@acme.com",
    date_range=("2026-03-01", "2026-03-19"),
)
print(f"Total sessions: {audit['total_sessions']}")
print(f"Isolated sessions: {audit['isolated_sessions']}")
print(f"Files processed via CDR: {audit['cdr_processed_files']}")
print(f"DLP violations: {audit['dlp_violations']}")
```

### Phase 5: Integration with Zero Trust Platform

Integrate browser isolation with the broader Zero Trust architecture including
identity provider, device posture checks, and conditional access policies.

```python
# Define Zero Trust conditional access integration
zt_policy = engine.create_zero_trust_integration(
    identity_provider="Azure AD",
    conditional_access_rules=[
        {
            "name": "Unmanaged Device Isolation",
            "condition": {"device_managed": False},
            "action": "full_isolation",
            "dlp_override": {"disable_download": True, "disable_upload": True},
        },
        {
            "name": "High Risk User Isolation",
            "condition": {"user_risk_level": "high"},
            "action": "full_isolation",
            "dlp_override": {"disable_copy_paste": True, "watermark_session": True},
        },
        {
            "name": "Contractor Restricted Access",
            "condition": {"user_group": "contractors"},
            "action": "read_only_isolation",
            "dlp_override": {"disable_download": True, "disable_printing": True},
        },
        {
            "name": "Privileged Admin Isolation",
            "condition": {"user_group": "admins", "target_category": "admin_console"},
            "action": "full_isolation",
            "dlp_override": {"watermark_session": True, "record_session": True},
        },
    ],
    swg_integration={
        "proxy_mode": "explicit",
        "pac_url": "https://pac.acme.com/proxy.pac",
        "ssl_inspection": True,
        "bypass_domains": ["*.acme.internal"],
    },
)

# Evaluate a request against all policies
decision = engine.evaluate_access_request(
    user_id="contractor@vendor.com",
    user_groups=["contractors"],
    device_posture={"managed": False, "edr_running": False},
    target_url="https://sensitive-app.acme.com/dashboard",
    user_risk_level="medium",
)
print(f"Decision: {decision['action']}")
print(f"Matched Rules: {[r['name'] for r in decision['matched_rules']]}")
print(f"DLP Controls: {decision['effective_dlp_controls']}")
```

## Examples

### Quick Policy Deployment for Phishing Protection

```python
engine = BrowserIsolationPolicyEngine(default_isolation_mode="isolate_risky")

# Isolate all links from email
engine.add_isolation_policy(
    name="Email Link Isolation",
    description="Isolate all URLs clicked from email clients",
    match_criteria={
        "referrer_categories": ["email_client"],
        "url_categories": ["*"],
    },
    isolation_mode="full_isolation",
    dlp_controls={
        "disable_keyboard_input": True,
        "disable_download": True,
        "watermark_session": True,
    },
)

# Test against a phishing URL
result = engine.evaluate_access_request(
    user_id="user@acme.com",
    target_url="https://micr0soft-login.phishing.com/auth",
    referrer="https://mail.google.com",
    user_risk_level="low",
)
print(f"Action: {result['action']}")  # full_isolation
```

### CDR Pipeline for All Downloads

```python
engine = BrowserIsolationPolicyEngine()

# Scan a batch of downloaded files through CDR
files = [
    "/tmp/downloads/invoice.pdf",
    "/tmp/downloads/contract.docx",
    "/tmp/downloads/data_export.xlsx",
    "/tmp/downloads/presentation.pptx",
]

batch_result = engine.batch_cdr_process(
    files=files,
    cdr_profile="strict",
    quarantine_on_threat=True,
)

print(f"Processed: {batch_result['total_processed']}")
print(f"Clean: {batch_result['clean_count']}")
print(f"Threats neutralized: {batch_result['threats_neutralized']}")
print(f"Quarantined: {batch_result['quarantined_count']}")
for f in batch_result["results"]:
    status = "CLEAN" if f["clean"] else "SANITIZED"
    print(f"  [{status}] {f['filename']}: {f['threats_found']} threats")
```

### Generating Isolation Policy Compliance Report

```python
engine = BrowserIsolationPolicyEngine()

report = engine.generate_compliance_report(
    date_range=("2026-03-01", "2026-03-19"),
    include_metrics=True,
)

print(f"Total web requests: {report['total_requests']}")
print(f"Isolated requests: {report['isolated_requests']} ({report['isolation_rate']}%)")
print(f"CDR processed files: {report['cdr_stats']['total_files']}")
print(f"Threats neutralized: {report['cdr_stats']['threats_neutralized']}")
print(f"DLP violations blocked: {report['dlp_violations_blocked']}")
print(f"Zero-day attacks prevented: {report['zero_day_blocked']}")
```
