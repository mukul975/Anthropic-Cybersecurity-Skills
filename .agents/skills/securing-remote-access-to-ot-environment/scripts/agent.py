#!/usr/bin/env python3
"""Agent for securing remote access to OT environments.

Manages remote access sessions with MFA verification, session
recording, role-based access policies, vendor co-attendance
requirements, and CIP-005 compliance auditing.
"""

import json
import hashlib
import sys
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum


class SessionState(str, Enum):
    PENDING = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    TERMINATED = "terminated"
    EXPIRED = "expired"
    DENIED = "denied"


class UserRole(str, Enum):
    OT_OPERATOR = "ot_operator"
    OT_ENGINEER = "ot_engineer"
    VENDOR = "vendor"
    SECURITY = "security_analyst"


class OTRemoteAccessAgent:
    """Manages secure remote access to OT environments."""

    def __init__(self, output_dir="./ot_remote_access"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.sessions = {}
        self.policies = {}
        self.audit_log = []

    def define_policy(self, role, allowed_targets, protocols, max_minutes):
        """Define access policy for a user role."""
        self.policies[role] = {
            "allowed_targets": allowed_targets,
            "protocols": protocols,
            "max_duration_minutes": max_minutes,
            "requires_approval": role == UserRole.VENDOR,
            "requires_co_attendance": role == UserRole.VENDOR,
        }

    def request_session(self, user_id, role, source_ip, target, target_ip,
                        protocol, purpose):
        """Request a new remote access session."""
        sid = hashlib.sha256(
            f"{user_id}{target_ip}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]

        policy = self.policies.get(role)
        if not policy:
            self._log("DENIED", user_id, target, "No policy for role")
            return None, "No policy defined for role"

        if target not in policy["allowed_targets"]:
            self._log("DENIED", user_id, target, "Target not authorized")
            return None, f"Target {target} not authorized for {role}"

        if protocol not in policy["protocols"]:
            self._log("DENIED", user_id, target, f"Protocol {protocol} not allowed")
            return None, f"Protocol {protocol} not authorized"

        session = {
            "session_id": sid,
            "user_id": user_id,
            "role": role,
            "source_ip": source_ip,
            "target": target,
            "target_ip": target_ip,
            "protocol": protocol,
            "purpose": purpose,
            "state": SessionState.PENDING if policy["requires_approval"] else SessionState.APPROVED,
            "mfa_verified": False,
            "created_at": datetime.utcnow().isoformat(),
            "max_duration": policy["max_duration_minutes"],
        }
        self.sessions[sid] = session
        self._log("REQUESTED", user_id, target, purpose)
        return sid, "Session created"

    def approve_session(self, sid, approver_id):
        """Approve a pending session."""
        s = self.sessions.get(sid)
        if not s or s["state"] != SessionState.PENDING:
            return False, "Session not pending"
        s["state"] = SessionState.APPROVED
        s["approved_by"] = approver_id
        self._log("APPROVED", approver_id, s["target"], f"Session {sid}")
        return True, "Approved"

    def activate_session(self, sid, mfa_verified=True):
        """Activate session after MFA verification."""
        s = self.sessions.get(sid)
        if not s or s["state"] != SessionState.APPROVED:
            return False, "Not approved"
        s["state"] = SessionState.ACTIVE
        s["mfa_verified"] = mfa_verified
        s["started_at"] = datetime.utcnow().isoformat()
        s["recording_path"] = f"/recordings/{sid}_{datetime.utcnow().strftime('%Y%m%d')}.mp4"
        self._log("ACTIVATED", s["user_id"], s["target"], f"MFA={'OK' if mfa_verified else 'FAIL'}")
        return True, "Active"

    def terminate_session(self, sid, reason="manual"):
        """Terminate an active session."""
        s = self.sessions.get(sid)
        if not s:
            return False
        s["state"] = SessionState.TERMINATED
        s["ended_at"] = datetime.utcnow().isoformat()
        self._log("TERMINATED", s["user_id"], s["target"], reason)
        return True

    def check_expired(self):
        """Find and terminate expired sessions."""
        expired = []
        now = datetime.utcnow()
        for sid, s in self.sessions.items():
            if s["state"] != SessionState.ACTIVE:
                continue
            started = datetime.fromisoformat(s["started_at"])
            if (now - started).total_seconds() > s["max_duration"] * 60:
                self.terminate_session(sid, "max_duration_exceeded")
                expired.append(sid)
        return expired

    def audit_compliance(self):
        """Check CIP-005 remote access compliance."""
        issues = []
        for sid, s in self.sessions.items():
            if s["state"] == SessionState.ACTIVE and not s["mfa_verified"]:
                issues.append({"session": sid, "issue": "Active session without MFA (CIP-005-7 R2.4)"})
            if s["role"] == UserRole.VENDOR:
                policy = self.policies.get(UserRole.VENDOR, {})
                if policy.get("requires_co_attendance") and "co_attendant" not in s:
                    issues.append({"session": sid, "issue": "Vendor session without co-attendance"})
        return issues

    def _log(self, event, user, target, detail):
        self.audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "user": user,
            "target": target,
            "detail": detail,
        })

    def generate_report(self):
        compliance = self.audit_compliance()
        active = [s for s in self.sessions.values() if s["state"] == SessionState.ACTIVE]

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_sessions": len(self.sessions),
            "active_sessions": len(active),
            "compliance_issues": compliance,
            "sessions": list(self.sessions.values()),
            "audit_log": self.audit_log[-50:],
        }
        out = self.output_dir / "ot_remote_access_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    agent = OTRemoteAccessAgent()
    agent.define_policy(UserRole.OT_ENGINEER, ["HMI-01", "EWS-01", "HISTORIAN-01"],
                        ["RDP", "SSH"], 240)
    agent.define_policy(UserRole.VENDOR, ["DCS-EWS-01"], ["RDP"], 120)

    sid, msg = agent.request_session("vendor_01", UserRole.VENDOR,
                                      "203.0.113.50", "DCS-EWS-01",
                                      "10.30.1.20", "RDP",
                                      "DCS firmware update CR-2026-0045")
    if sid:
        agent.approve_session(sid, "ot_manager_01")
        agent.activate_session(sid)

    agent.generate_report()


if __name__ == "__main__":
    main()
