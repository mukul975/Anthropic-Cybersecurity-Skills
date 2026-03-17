---
name: implementing-patch-management-for-ot-systems
description: >
  This skill covers implementing a structured patch management program for OT/ICS
  environments where traditional IT patching approaches can cause process disruption
  or safety hazards. It addresses vendor compatibility testing, risk-based patch
  prioritization, staged deployment through test environments, maintenance window
  coordination, rollback procedures, and compensating controls when patches cannot
  be applied due to operational constraints or vendor restrictions.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, patch-management, vulnerability-management]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Patch Management for OT Systems

## When to Use

- When establishing a formal OT patch management program for the first time
- When responding to critical ICS-CERT advisories affecting deployed OT systems
- When preparing for NERC CIP-007-6 or IEC 62443 patch management compliance audits
- When planning patch deployment during limited maintenance windows in continuous operations
- When evaluating compensating controls for systems that cannot be patched

**Do not use** for IT-only patch management without OT considerations, for emergency patching during active cyber incidents (see performing-ot-incident-response), or for firmware upgrades that change PLC functionality (requires separate change management).

## Prerequisites

- OT asset inventory with firmware/OS versions for all patchable systems
- Vendor patch notification subscriptions (Siemens ProductCERT, Rockwell, Schneider, etc.)
- Test/staging environment mirroring production OT systems for patch validation
- Maintenance window schedule aligned with process shutdowns and turnarounds
- Change management board approval process including operations and safety representatives

## Workflow

### Step 1: Establish OT Patch Management Program

Define the patch management lifecycle adapted for OT environments where availability and safety take priority over immediate vulnerability remediation.

```python
#!/usr/bin/env python3
"""OT Patch Management Program Manager.

Tracks patches for OT systems, manages risk-based prioritization,
coordinates testing and deployment, and documents compensating
controls for unpatchable systems.
"""

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum


class PatchStatus(str, Enum):
    IDENTIFIED = "identified"
    EVALUATING = "evaluating"
    TESTING = "testing"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    DEPLOYED = "deployed"
    DEFERRED = "deferred"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class OTPatch:
    patch_id: str
    vendor: str
    product: str
    affected_versions: str
    cve_ids: list
    cvss_score: float
    ics_cert_advisory: str
    description: str
    status: str = PatchStatus.IDENTIFIED
    identified_date: str = ""
    evaluation_deadline: str = ""  # 35 days per CIP-007
    test_date: str = ""
    deployment_date: str = ""
    affected_assets: list = field(default_factory=list)
    test_results: str = ""
    compensating_controls: str = ""
    risk_rating: str = ""
    maintenance_window: str = ""
    rollback_procedure: str = ""


class OTPatchManager:
    """Manages the OT patch lifecycle."""

    def __init__(self):
        self.patches = []
        self.assets = {}
        self.vendor_feeds = {}

    def add_patch(self, patch: OTPatch):
        """Register a new patch for tracking."""
        # Set evaluation deadline (35 calendar days per NERC CIP-007)
        if not patch.evaluation_deadline:
            identified = datetime.fromisoformat(patch.identified_date)
            patch.evaluation_deadline = (identified + timedelta(days=35)).isoformat()

        self.patches.append(patch)

    def prioritize_patches(self):
        """Risk-based prioritization for OT patches."""
        for patch in self.patches:
            if patch.status in (PatchStatus.DEPLOYED, PatchStatus.NOT_APPLICABLE):
                continue

            # OT-specific risk scoring
            score = patch.cvss_score

            # Increase priority for actively exploited vulnerabilities
            if "CISA KEV" in patch.ics_cert_advisory:
                score += 2.0

            # Increase priority for network-exposed OT systems
            for asset_id in patch.affected_assets:
                asset = self.assets.get(asset_id, {})
                if asset.get("network_exposed"):
                    score += 1.0
                if asset.get("purdue_level") in ("Level 0-1", "Level 2"):
                    score += 1.5

            score = min(score, 10.0)

            if score >= 9.0:
                patch.risk_rating = "critical"
            elif score >= 7.0:
                patch.risk_rating = "high"
            elif score >= 4.0:
                patch.risk_rating = "medium"
            else:
                patch.risk_rating = "low"

    def get_patches_needing_evaluation(self):
        """Get patches approaching evaluation deadline."""
        now = datetime.now()
        approaching = []
        for patch in self.patches:
            if patch.status == PatchStatus.IDENTIFIED:
                deadline = datetime.fromisoformat(patch.evaluation_deadline)
                days_remaining = (deadline - now).days
                if days_remaining <= 7:
                    approaching.append((patch, days_remaining))
        return sorted(approaching, key=lambda x: x[1])

    def defer_patch(self, patch_id, reason, compensating_controls):
        """Defer a patch with documented compensating controls."""
        for patch in self.patches:
            if patch.patch_id == patch_id:
                patch.status = PatchStatus.DEFERRED
                patch.compensating_controls = compensating_controls
                patch.test_results = f"Deferred: {reason}"
                break

    def generate_report(self):
        """Generate patch management status report."""
        self.prioritize_patches()

        report = []
        report.append("=" * 70)
        report.append("OT PATCH MANAGEMENT STATUS REPORT")
        report.append(f"Date: {datetime.now().isoformat()}")
        report.append("=" * 70)

        # Status summary
        status_counts = defaultdict(int)
        for p in self.patches:
            status_counts[p.status] += 1

        report.append("\nPATCH STATUS SUMMARY:")
        for status, count in status_counts.items():
            report.append(f"  {status}: {count}")

        # Approaching deadlines
        approaching = self.get_patches_needing_evaluation()
        if approaching:
            report.append("\nAPPROACHING EVALUATION DEADLINES:")
            for patch, days in approaching:
                report.append(f"  [{patch.patch_id}] {patch.description} - {days} days remaining")

        # Critical/High priority patches
        urgent = [p for p in self.patches
                  if p.risk_rating in ("critical", "high")
                  and p.status not in (PatchStatus.DEPLOYED, PatchStatus.NOT_APPLICABLE)]
        if urgent:
            report.append(f"\nURGENT PATCHES ({len(urgent)}):")
            for p in urgent:
                report.append(f"  [{p.patch_id}] [{p.risk_rating.upper()}] {p.description}")
                report.append(f"    CVEs: {', '.join(p.cve_ids)}")
                report.append(f"    Status: {p.status}")
                report.append(f"    Affected Assets: {len(p.affected_assets)}")

        # Deferred patches with compensating controls
        deferred = [p for p in self.patches if p.status == PatchStatus.DEFERRED]
        if deferred:
            report.append(f"\nDEFERRED PATCHES ({len(deferred)}):")
            for p in deferred:
                report.append(f"  [{p.patch_id}] {p.description}")
                report.append(f"    Reason: {p.test_results}")
                report.append(f"    Compensating Controls: {p.compensating_controls}")

        return "\n".join(report)


if __name__ == "__main__":
    manager = OTPatchManager()

    # Example patches
    manager.add_patch(OTPatch(
        patch_id="OT-PATCH-001",
        vendor="Siemens",
        product="SIMATIC S7-1500",
        affected_versions="< V3.0.1",
        cve_ids=["CVE-2023-44374"],
        cvss_score=8.8,
        ics_cert_advisory="ICSA-23-348-01",
        description="S7-1500 memory corruption via crafted packets",
        identified_date="2026-01-15",
        affected_assets=["PLC-01", "PLC-02", "PLC-03"],
    ))

    manager.add_patch(OTPatch(
        patch_id="OT-PATCH-002",
        vendor="Rockwell Automation",
        product="FactoryTalk View SE",
        affected_versions="< V13.0",
        cve_ids=["CVE-2024-21914"],
        cvss_score=7.5,
        ics_cert_advisory="ICSA-24-046-02",
        description="FactoryTalk View remote code execution",
        identified_date="2026-02-01",
        affected_assets=["HMI-01", "HMI-02"],
    ))

    print(manager.generate_report())
```

### Step 2: Test Patches in Staging Environment

Never deploy patches directly to production OT systems. Use a test environment that mirrors production to validate patch compatibility.

```yaml
# OT Patch Testing Procedure
patch_testing:
  environment:
    description: "Staging lab mirroring production OT architecture"
    components:
      - "Virtual PLC simulators matching production firmware"
      - "Test HMI stations with identical software versions"
      - "Test historian with representative data"
      - "Network configuration matching production VLANs/firewalls"

  test_cases:
    functional:
      - "PLC programs execute correctly after OS patch"
      - "HMI displays update with correct process values"
      - "Historian data collection continues uninterrupted"
      - "Alarm and event handling functions properly"
      - "Communication between PLCs maintains cycle time"
      - "Safety system trip tests pass (if SIS affected)"

    performance:
      - "PLC scan time remains within acceptable limits (<50ms increase)"
      - "HMI screen refresh rate unchanged"
      - "Historian collection interval maintained"
      - "Network latency between zones unchanged"

    compatibility:
      - "Third-party applications function correctly"
      - "OPC UA/DA connections establish successfully"
      - "Custom scripts and batch processes execute"
      - "Backup and restore procedures work"

    rollback:
      - "System can be reverted to pre-patch state"
      - "Rollback procedure documented and tested"
      - "Estimated rollback time: [N] minutes"

  documentation:
    required:
      - "Test plan with pass/fail criteria"
      - "Test execution results with screenshots"
      - "Performance measurements before and after"
      - "Sign-off by operations, engineering, and security"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Compensating Control | Alternative security measure applied when a patch cannot be deployed, such as firewall rules, IPS signatures, or network isolation |
| Vendor Compatibility | Confirmation from the OT vendor that a patch (especially OS patches) is compatible with their control system software |
| Maintenance Window | Scheduled period for system modifications, aligned with process shutdowns or reduced-risk operational periods |
| Virtual Patching | Deploying IDS/IPS rules to detect and block exploitation attempts for known vulnerabilities without modifying the target system |
| Evaluation Deadline | NERC CIP-007-6 requires patch evaluation within 35 calendar days of availability |
| Turnaround | Major scheduled shutdown of a process unit for maintenance, providing opportunity for extensive OT patching |

## Tools & Systems

- **WSUS/SCCM**: Microsoft patch management for Windows-based OT systems (HMIs, historians, engineering workstations)
- **Siemens ProductCERT**: Siemens security advisory service for industrial products
- **Claroty xDome**: OT vulnerability management with patch availability tracking and risk scoring
- **Tripwire Enterprise**: Configuration monitoring detecting unauthorized changes and tracking patch status

## Output Format

```
OT Patch Management Report
============================
Reporting Period: YYYY-MM to YYYY-MM

PATCH STATUS:
  Identified: [N]
  Evaluating: [N]
  Testing: [N]
  Deployed: [N]
  Deferred: [N]

COMPLIANCE:
  Evaluated within 35 days: [N]/[N] (CIP-007-6 R2)
  Deployed or mitigated: [N]/[N]
  Deferred with compensating controls: [N]
```
