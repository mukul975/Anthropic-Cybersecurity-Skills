---
name: implementing-conduit-security-for-ot-remote-access
description: >
  Implement secure conduit architecture for OT remote access following IEC 62443
  zones and conduits model, deploying jump servers, MFA-enabled gateways, session
  recording, and approval-based workflows to control vendor and engineer access
  to industrial control systems without exposing OT networks directly.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, remote-access, iec62443, jump-server, zero-trust, conduit, mfa]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Conduit Security for OT Remote Access

## When to Use

- When replacing direct VPN connections from IT or vendors into OT control networks
- When implementing IEC 62443-compliant conduit architecture for remote access paths
- When deploying secure remote access for third-party vendor maintenance of ICS equipment
- When building approval-based access workflows for privileged OT system access
- When remediating audit findings about uncontrolled remote access to SCADA systems

**Do not use** for designing the overall Purdue Model segmentation (see implementing-purdue-model-network-segmentation), for deploying IT-only remote access solutions, or for configuring local console access to PLCs.

## Prerequisites

- IT/OT DMZ (Level 3.5) deployed with dual-firewall architecture
- Jump server or privileged access management (PAM) platform (CyberArk, BeyondTrust)
- Multi-factor authentication (MFA) infrastructure for OT remote access users
- Session recording capability for compliance and forensic purposes
- Approval workflow system (ServiceNow, ticketing) for access requests

## Workflow

### Step 1: Design Conduit Architecture for Remote Access

```yaml
# IEC 62443 Conduit Security Architecture for OT Remote Access
# All remote access terminates in DMZ - never passes through to OT directly

conduit_architecture:
  remote_access_conduit:
    conduit_id: "RA-001"
    source_zone: "Enterprise IT (Level 4)"
    destination_zone: "OT DMZ (Level 3.5)"
    security_level_target: "SL3"

    components:
      external_gateway:
        type: "VPN Concentrator"
        location: "Enterprise DMZ"
        ip: "10.200.1.10"
        protocols: ["IPsec", "SSL-VPN"]
        authentication: "MFA required (certificate + OTP)"

      dmz_jump_server:
        type: "Privileged Access Workstation"
        location: "OT DMZ (Level 3.5)"
        ip: "10.10.150.20"
        os: "Windows Server 2022 (hardened)"
        controls:
          - "Local admin accounts disabled"
          - "USB ports disabled"
          - "Clipboard transfer disabled by default"
          - "Session recording enabled (all keystrokes and screen)"
          - "Maximum session duration: 4 hours"
          - "Automatic logoff after 15 minutes idle"
          - "Application whitelisting enforced"

      ot_access_gateway:
        type: "Industrial Remote Access Gateway"
        location: "OT DMZ / Level 3 boundary"
        ip: "10.10.150.25"
        controls:
          - "Only pre-approved destination IPs reachable"
          - "Protocol-level filtering (RDP, SSH, VNC only)"
          - "Time-limited sessions with automatic expiry"
          - "Approval-based access (plant manager must authorize)"

    data_flow:
      - step: 1
        description: "User authenticates via enterprise VPN with MFA"
        source: "Remote user"
        destination: "VPN concentrator"
        protocol: "IPsec/SSL-VPN"
      - step: 2
        description: "User connects to jump server in OT DMZ"
        source: "VPN tunnel"
        destination: "DMZ jump server"
        protocol: "RDP with NLA"
      - step: 3
        description: "From jump server, user accesses specific OT system"
        source: "DMZ jump server"
        destination: "Approved OT target"
        protocol: "RDP/SSH/VNC"
        condition: "Only after manager approval and within time window"

    prohibited_flows:
      - "Direct VPN tunnel from external to Level 1/2 OT devices"
      - "Split tunneling allowing internet access during OT session"
      - "File transfer from jump server to OT without scanning"
      - "Persistent VPN connections (auto-reconnect disabled)"

  vendor_access_conduit:
    conduit_id: "VA-001"
    source_zone: "Vendor External Network"
    destination_zone: "OT DMZ (Level 3.5)"
    security_level_target: "SL3"

    workflow:
      request:
        - "Vendor submits access request via portal (24h advance)"
        - "Request includes: purpose, target systems, duration, personnel"
        - "Plant operations manager reviews and approves/rejects"
        - "Time-limited credentials generated upon approval"
      session:
        - "Vendor connects via dedicated vendor VPN gateway"
        - "MFA authentication (vendor receives OTP via SMS/app)"
        - "Session lands on vendor-specific jump server (isolated from internal jump)"
        - "All actions recorded (video + keystroke logging)"
        - "OT engineer monitors vendor session in real-time"
      termination:
        - "Session auto-terminates at approved end time"
        - "Credentials automatically revoked"
        - "Session recording archived for 90 days"
        - "Access log forwarded to SIEM"
```

### Step 2: Implement Access Control and Monitoring

```python
#!/usr/bin/env python3
"""OT Remote Access Conduit Manager.

Manages approval-based remote access to OT systems through
secure conduit architecture with session recording, MFA
enforcement, and time-limited access windows.
"""

import json
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum


class AccessRequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RemoteAccessRequest:
    """Represents an OT remote access request."""

    def __init__(self, requestor: str, requestor_type: str, purpose: str,
                 target_systems: List[str], duration_hours: int,
                 requested_start: str):
        self.id = f"OT-RA-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.requestor = requestor
        self.requestor_type = requestor_type  # "internal_engineer" or "vendor"
        self.purpose = purpose
        self.target_systems = target_systems
        self.duration_hours = duration_hours
        self.requested_start = requested_start
        self.status = AccessRequestStatus.PENDING
        self.created = datetime.now().isoformat()
        self.approved_by = None
        self.session_id = None
        self.audit_trail = []

    def approve(self, approver: str, conditions: str = ""):
        """Approve the access request."""
        self.status = AccessRequestStatus.APPROVED
        self.approved_by = approver
        self.audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "action": "APPROVED",
            "actor": approver,
            "conditions": conditions,
        })

    def reject(self, rejector: str, reason: str):
        """Reject the access request."""
        self.status = AccessRequestStatus.REJECTED
        self.audit_trail.append({
            "timestamp": datetime.now().isoformat(),
            "action": "REJECTED",
            "actor": rejector,
            "reason": reason,
        })


class OTConduitManager:
    """Manages OT remote access conduit security."""

    def __init__(self):
        self.access_requests: Dict[str, RemoteAccessRequest] = {}
        self.active_sessions: Dict[str, dict] = {}
        self.policy = self._load_policy()

    def _load_policy(self) -> dict:
        """Load remote access policy."""
        return {
            "max_session_hours": 4,
            "idle_timeout_minutes": 15,
            "mfa_required": True,
            "session_recording": True,
            "clipboard_transfer": False,
            "file_transfer": "scan_required",
            "advance_notice_hours": 24,
            "vendor_escort_required": True,
            "prohibited_targets": ["SIS-*", "SAFETY-*"],
            "allowed_protocols": ["RDP", "SSH", "VNC"],
            "blocked_protocols": ["Telnet", "FTP", "SMB"],
        }

    def submit_request(self, request: RemoteAccessRequest) -> str:
        """Submit a new remote access request."""
        # Validate against policy
        violations = []

        if request.duration_hours > self.policy["max_session_hours"]:
            violations.append(
                f"Duration {request.duration_hours}h exceeds maximum {self.policy['max_session_hours']}h"
            )

        for target in request.target_systems:
            for prohibited in self.policy["prohibited_targets"]:
                pattern = prohibited.replace("*", "")
                if target.startswith(pattern):
                    violations.append(f"Target {target} is in prohibited list (safety systems)")

        if violations:
            print(f"[!] Policy violations found:")
            for v in violations:
                print(f"    - {v}")
            return ""

        self.access_requests[request.id] = request
        print(f"[+] Access request {request.id} submitted for approval")
        return request.id

    def list_pending_requests(self):
        """List all pending access requests for approval."""
        pending = [r for r in self.access_requests.values()
                   if r.status == AccessRequestStatus.PENDING]

        print(f"\n{'='*65}")
        print("PENDING OT REMOTE ACCESS REQUESTS")
        print(f"{'='*65}")

        if not pending:
            print("  No pending requests")
            return

        for req in pending:
            print(f"\n  Request: {req.id}")
            print(f"    Requestor: {req.requestor} ({req.requestor_type})")
            print(f"    Purpose: {req.purpose}")
            print(f"    Targets: {', '.join(req.target_systems)}")
            print(f"    Duration: {req.duration_hours} hours")
            print(f"    Start: {req.requested_start}")
            print(f"    Submitted: {req.created}")

    def generate_audit_report(self):
        """Generate audit report of all remote access activity."""
        print(f"\n{'='*65}")
        print("OT REMOTE ACCESS AUDIT REPORT")
        print(f"{'='*65}")
        print(f"Report Date: {datetime.now().isoformat()}")
        print(f"Total Requests: {len(self.access_requests)}")

        status_counts = {}
        for req in self.access_requests.values():
            status = req.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        print(f"\nRequest Status:")
        for status, count in status_counts.items():
            print(f"  {status}: {count}")

        print(f"\nDetailed Audit Trail:")
        for req in self.access_requests.values():
            print(f"\n  {req.id} - {req.requestor} ({req.requestor_type})")
            print(f"    Status: {req.status.value}")
            print(f"    Targets: {', '.join(req.target_systems)}")
            for entry in req.audit_trail:
                print(f"    [{entry['timestamp']}] {entry['action']} by {entry['actor']}")


if __name__ == "__main__":
    manager = OTConduitManager()

    # Vendor access request
    vendor_req = RemoteAccessRequest(
        requestor="John Smith - Siemens Field Service",
        requestor_type="vendor",
        purpose="Annual PLC firmware update for S7-1500 controllers",
        target_systems=["PLC-REACTOR-01", "PLC-REACTOR-02"],
        duration_hours=3,
        requested_start="2025-03-15T08:00:00",
    )

    req_id = manager.submit_request(vendor_req)
    if req_id:
        manager.list_pending_requests()

    # Simulate approval
    manager.access_requests[req_id].approve(
        approver="Plant Manager - Jane Doe",
        conditions="OT engineer must shadow the vendor session",
    )

    manager.generate_audit_report()
```

## Key Concepts

| Term | Definition |
|------|------------|
| Conduit | IEC 62443 controlled communication path between security zones with defined security policies |
| Jump Server | Hardened intermediary server in the DMZ through which all remote OT access must transit |
| Session Recording | Capture of all screen activity, keystrokes, and commands during a remote access session for audit |
| Approval-Based Access | Workflow requiring plant operations manager authorization before remote access credentials are activated |
| Vendor Escort | Practice of having an internal OT engineer monitor vendor remote sessions in real time |
| Break-Glass Access | Emergency access procedure bypassing normal approval workflow for critical situations |

## Output Format

```
OT REMOTE ACCESS CONDUIT REPORT
==================================
Date: YYYY-MM-DD

CONDUIT STATUS:
  Internal Access Conduit: [Active/Inactive]
  Vendor Access Conduit: [Active/Inactive]

ACCESS REQUESTS (Last 30 Days):
  Submitted: [count]
  Approved: [count]
  Rejected: [count]
  Average Session Duration: [hours]

POLICY COMPLIANCE:
  MFA Enforcement: [100%]
  Session Recording: [100%]
  Time-Limited Sessions: [compliance %]
  Prohibited Target Attempts: [count blocked]
```
