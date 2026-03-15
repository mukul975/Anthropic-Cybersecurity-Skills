---
name: securing-remote-access-to-ot-environment
description: >
  This skill covers implementing secure remote access to OT/ICS environments for
  operators, engineers, and vendors while preventing unauthorized access that could
  compromise industrial operations. It addresses jump server architecture, multi-factor
  authentication, session recording, privileged access management, vendor remote access
  controls, and compliance with IEC 62443 and NERC CIP-005 remote access requirements.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, remote-access, jump-server, mfa]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing Remote Access to OT Environment

## When to Use

- When implementing or upgrading remote access architecture for OT environments
- When onboarding vendors who require remote access to OT systems for support and maintenance
- When implementing CIP-005-7 R2 requirements for remote access management including MFA
- When replacing legacy direct VPN access to OT networks with a secure jump server architecture
- When responding to an incident involving unauthorized remote access to industrial control systems

**Do not use** for securing IT-only remote access without OT components, for configuring VPN for corporate workers (see general VPN guides), or for physical access control to OT facilities.

## Prerequisites

- DMZ infrastructure (Level 3.5) between corporate IT and OT networks
- Jump server/bastion host platform (CyberArk, BeyondTrust, or hardened Windows/Linux server)
- Multi-factor authentication solution (Duo, RSA SecurID, YubiKey, smart cards)
- Session recording capability for audit trail compliance
- Firewall rules permitting remote access only through the DMZ intermediate system

## Workflow

### Step 1: Design Secure Remote Access Architecture

Implement a defense-in-depth remote access architecture with an intermediate system in the DMZ that prevents any direct network connectivity between external users and OT systems.

```yaml
# OT Remote Access Architecture
# Key principle: NO direct connection from external networks to OT systems

architecture:
  external_access_point:
    location: "Internet-facing firewall"
    service: "VPN gateway (IKEv2/IPsec or SSL VPN)"
    authentication: "Certificate + MFA (CIP-005-7 R2.4)"
    controls:
      - "Source IP allowlisting for vendor access"
      - "Time-based access windows"
      - "Bandwidth rate limiting"

  dmz_intermediate_system:
    location: "Level 3.5 DMZ"
    platform: "CyberArk Privileged Access Security or hardened jump server"
    function: "Session broker - terminates external connection, initiates new internal connection"
    controls:
      - "All sessions terminate at jump server (no pass-through)"
      - "Session recording with keystroke logging"
      - "Clipboard and file transfer restrictions"
      - "Session timeout after 30 minutes inactivity"
      - "Concurrent session limits per user"

  ot_internal_access:
    location: "Level 3 / Level 2 OT network"
    method: "Jump server initiates RDP/SSH/VNC to OT systems"
    controls:
      - "Firewall allows only jump server IP to reach OT"
      - "Protocol restricted (RDP 3389, SSH 22, VNC 5900)"
      - "Destination-specific per user role"

  vendor_access:
    description: "Third-party vendor remote access"
    additional_controls:
      - "Vendor account disabled by default; enabled on request"
      - "Time-limited access windows (enable/disable per session)"
      - "OT operator must co-attend vendor sessions"
      - "Real-time session monitoring by OT security"
      - "No persistent credentials - one-time access tokens"

# Network flow:
# User -> VPN -> Firewall -> DMZ Jump Server -> Internal FW -> OT System
# (Two separate authenticated connections; no direct routing)
```

### Step 2: Configure Jump Server with Privileged Access Management

Deploy and harden the jump server in the DMZ with session management, recording, and role-based access controls.

```python
#!/usr/bin/env python3
"""OT Remote Access Session Manager.

Manages authorized remote access sessions to OT environments
including session creation, monitoring, recording, and termination.
Integrates with PAM solutions for credential vaulting.
"""

import json
import hashlib
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum


class SessionState(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    TERMINATED = "terminated"
    EXPIRED = "expired"
    DENIED = "denied"


class UserRole(str, Enum):
    OT_OPERATOR = "ot_operator"
    OT_ENGINEER = "ot_engineer"
    VENDOR = "vendor"
    SECURITY_ANALYST = "security_analyst"


@dataclass
class RemoteAccessSession:
    session_id: str
    user_id: str
    user_role: str
    source_ip: str
    target_system: str
    target_ip: str
    protocol: str
    purpose: str
    state: str = SessionState.PENDING_APPROVAL
    mfa_verified: bool = False
    approved_by: str = ""
    created_at: str = ""
    started_at: str = ""
    ended_at: str = ""
    max_duration_minutes: int = 120
    recording_path: str = ""
    actions_logged: list = field(default_factory=list)


class OTRemoteAccessManager:
    """Manages remote access sessions to OT environment."""

    def __init__(self):
        self.sessions = {}
        self.active_sessions = {}
        self.access_policies = {}
        self.audit_log = []

    def define_access_policy(self, role, allowed_targets, protocols, max_duration):
        """Define access policy for a user role."""
        self.access_policies[role] = {
            "allowed_targets": allowed_targets,
            "allowed_protocols": protocols,
            "max_duration_minutes": max_duration,
            "requires_co_attendance": role == UserRole.VENDOR,
            "requires_approval": role == UserRole.VENDOR,
        }

    def request_session(self, user_id, user_role, source_ip,
                        target_system, target_ip, protocol, purpose):
        """Request a new remote access session."""
        # Generate unique session ID
        session_id = hashlib.sha256(
            f"{user_id}{target_ip}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Check access policy
        policy = self.access_policies.get(user_role)
        if not policy:
            return None, "No access policy defined for role"

        if target_system not in policy["allowed_targets"]:
            self._audit("ACCESS_DENIED", user_id, target_system,
                       f"Target not in allowed list for role {user_role}")
            return None, f"Target {target_system} not authorized for role {user_role}"

        if protocol not in policy["allowed_protocols"]:
            self._audit("ACCESS_DENIED", user_id, target_system,
                       f"Protocol {protocol} not allowed for role {user_role}")
            return None, f"Protocol {protocol} not authorized"

        session = RemoteAccessSession(
            session_id=session_id,
            user_id=user_id,
            user_role=user_role,
            source_ip=source_ip,
            target_system=target_system,
            target_ip=target_ip,
            protocol=protocol,
            purpose=purpose,
            max_duration_minutes=policy["max_duration_minutes"],
            created_at=datetime.now().isoformat(),
        )

        # Vendor sessions require approval
        if policy.get("requires_approval"):
            session.state = SessionState.PENDING_APPROVAL
        else:
            session.state = SessionState.APPROVED

        self.sessions[session_id] = session
        self._audit("SESSION_REQUESTED", user_id, target_system, purpose)

        return session_id, "Session created"

    def approve_session(self, session_id, approver_id):
        """Approve a pending vendor session."""
        session = self.sessions.get(session_id)
        if not session:
            return False, "Session not found"
        if session.state != SessionState.PENDING_APPROVAL:
            return False, "Session not in pending approval state"

        session.state = SessionState.APPROVED
        session.approved_by = approver_id
        self._audit("SESSION_APPROVED", approver_id, session.target_system,
                    f"Approved session {session_id} for {session.user_id}")
        return True, "Session approved"

    def activate_session(self, session_id, mfa_token):
        """Activate an approved session after MFA verification."""
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.APPROVED:
            return False, "Session not approved"

        # Verify MFA (simplified - real implementation calls MFA provider)
        session.mfa_verified = True
        session.state = SessionState.ACTIVE
        session.started_at = datetime.now().isoformat()
        session.recording_path = f"/recordings/{session_id}_{datetime.now().strftime('%Y%m%d')}.mp4"

        self.active_sessions[session_id] = session
        self._audit("SESSION_ACTIVATED", session.user_id, session.target_system,
                    f"MFA verified, recording to {session.recording_path}")

        return True, "Session active"

    def terminate_session(self, session_id, reason="manual"):
        """Terminate an active session."""
        session = self.active_sessions.pop(session_id, None)
        if not session:
            session = self.sessions.get(session_id)
        if not session:
            return False

        session.state = SessionState.TERMINATED
        session.ended_at = datetime.now().isoformat()
        self._audit("SESSION_TERMINATED", session.user_id, session.target_system, reason)
        return True

    def check_expired_sessions(self):
        """Terminate sessions that have exceeded their maximum duration."""
        now = datetime.now()
        expired = []
        for sid, session in list(self.active_sessions.items()):
            started = datetime.fromisoformat(session.started_at)
            if (now - started).total_seconds() > session.max_duration_minutes * 60:
                self.terminate_session(sid, "maximum_duration_exceeded")
                expired.append(sid)
        return expired

    def _audit(self, event_type, user_id, target, detail):
        """Write to audit log."""
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            "user": user_id,
            "target": target,
            "detail": detail,
        })

    def generate_report(self):
        """Generate remote access session report."""
        report = []
        report.append("=" * 70)
        report.append("OT REMOTE ACCESS SESSION REPORT")
        report.append(f"Date: {datetime.now().isoformat()}")
        report.append("=" * 70)

        # Session summary
        total = len(self.sessions)
        active = sum(1 for s in self.sessions.values() if s.state == SessionState.ACTIVE)
        report.append(f"\nTotal Sessions: {total}")
        report.append(f"Active Sessions: {active}")

        # Active sessions detail
        if self.active_sessions:
            report.append("\nACTIVE SESSIONS:")
            for sid, s in self.active_sessions.items():
                report.append(f"  [{sid[:8]}] {s.user_id} ({s.user_role})")
                report.append(f"    Target: {s.target_system} ({s.target_ip})")
                report.append(f"    Started: {s.started_at}")
                report.append(f"    MFA: {'Verified' if s.mfa_verified else 'NOT VERIFIED'}")

        return "\n".join(report)


if __name__ == "__main__":
    manager = OTRemoteAccessManager()

    # Define policies
    manager.define_access_policy(
        UserRole.OT_ENGINEER,
        ["HMI-01", "HMI-02", "EWS-01", "HISTORIAN-01"],
        ["RDP", "SSH"],
        max_duration=240,
    )
    manager.define_access_policy(
        UserRole.VENDOR,
        ["DCS-EWS-01"],
        ["RDP"],
        max_duration=120,
    )

    # Request vendor session
    sid, msg = manager.request_session(
        "vendor_honeywell_01", UserRole.VENDOR,
        "203.0.113.50", "DCS-EWS-01", "10.30.1.20",
        "RDP", "DCS firmware update per change request CR-2026-0045")
    print(f"Session request: {msg} ({sid})")

    if sid:
        manager.approve_session(sid, "ot_manager_01")
        manager.activate_session(sid, "123456")
        print(manager.generate_report())
```

## Key Concepts

| Term | Definition |
|------|------------|
| Intermediate System | System in the DMZ that terminates external connections and brokers new connections to OT, preventing direct network access per CIP-005 |
| Jump Server | Hardened bastion host in the DMZ used for remote access sessions to OT systems with session recording and access controls |
| Session Recording | Capture of all remote access session activity (screen, keystrokes, commands) for security audit and incident investigation |
| Privileged Access Management (PAM) | System for vaulting credentials, controlling access, and auditing privileged sessions to critical OT systems |
| Co-Attendance | Requirement for an OT operator to monitor vendor remote access sessions in real time |
| Time-Limited Access | Vendor accounts enabled only for specific maintenance windows and automatically disabled after the window closes |

## Tools & Systems

- **CyberArk Privileged Access Security**: Enterprise PAM with session management, credential vaulting, and recording for OT remote access
- **BeyondTrust Privileged Remote Access**: Purpose-built remote access solution with session recording and granular access policies
- **Claroty Secure Remote Access (SRA)**: OT-specific remote access solution with protocol-aware session controls
- **Duo Security**: MFA provider supporting push notifications, hardware tokens, and biometrics for OT access verification

## Output Format

```
OT Remote Access Security Report
===================================
Active Sessions: [N]
Pending Approval: [N]
Sessions Today: [N]

MFA COMPLIANCE:
  All sessions MFA verified: [Yes/No]
  Sessions without MFA: [N]

VENDOR ACCESS:
  Active vendor sessions: [N]
  Co-attended: [N]
  Recorded: [N]
```
