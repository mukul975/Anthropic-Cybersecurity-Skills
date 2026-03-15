#!/usr/bin/env python3
"""
Just-In-Time Access Provisioning Engine

Manages JIT access requests, approval workflows, time-bound grants,
automatic revocation, and audit logging for zero-standing-privilege
implementations.
"""

import json
import datetime
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EMERGENCY = "emergency"


@dataclass
class JITAccessRequest:
    """A just-in-time access request."""
    request_id: str
    requester: str
    target_resource: str
    resource_type: str  # server, database, application, cloud_role
    requested_duration_minutes: int
    justification: str
    risk_level: RiskLevel = RiskLevel.MEDIUM
    status: RequestStatus = RequestStatus.PENDING
    approvers: List[str] = field(default_factory=list)
    approved_by: List[str] = field(default_factory=list)
    denied_by: str = ""
    created_at: str = ""
    granted_at: str = ""
    expires_at: str = ""
    revoked_at: str = ""
    is_emergency: bool = False
    ticket_id: str = ""


@dataclass
class ResourcePolicy:
    """Policy for a protected resource."""
    resource_pattern: str
    resource_type: str
    max_duration_minutes: int
    risk_level: RiskLevel
    auto_approve: bool = False
    required_approvals: int = 1
    approver_roles: List[str] = field(default_factory=list)
    mfa_required: bool = True
    session_recording: bool = False


class JITAccessEngine:
    """Manages the full JIT access lifecycle."""

    def __init__(self):
        self.requests: Dict[str, JITAccessRequest] = {}
        self.policies: List[ResourcePolicy] = []
        self.audit_log: List[Dict] = []

    def add_policy(self, policy: ResourcePolicy):
        """Register a resource access policy."""
        self.policies.append(policy)

    def _get_policy(self, resource: str, resource_type: str) -> Optional[ResourcePolicy]:
        """Find matching policy for a resource."""
        for policy in self.policies:
            if policy.resource_type == resource_type:
                if policy.resource_pattern == "*" or policy.resource_pattern in resource:
                    return policy
        return None

    def _generate_request_id(self) -> str:
        return f"JIT-{datetime.datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

    def _log_event(self, event_type: str, request_id: str, details: Dict):
        """Record audit event."""
        self.audit_log.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "event_type": event_type,
            "request_id": request_id,
            **details
        })

    def submit_request(self, requester: str, target_resource: str,
                       resource_type: str, duration_minutes: int,
                       justification: str, is_emergency: bool = False,
                       ticket_id: str = "") -> JITAccessRequest:
        """Submit a new JIT access request."""
        policy = self._get_policy(target_resource, resource_type)
        if not policy:
            raise ValueError(f"No policy found for resource type: {resource_type}")

        # Enforce maximum duration
        actual_duration = min(duration_minutes, policy.max_duration_minutes)
        if is_emergency:
            actual_duration = min(actual_duration, 120)  # 2-hour max for emergency

        request = JITAccessRequest(
            request_id=self._generate_request_id(),
            requester=requester,
            target_resource=target_resource,
            resource_type=resource_type,
            requested_duration_minutes=actual_duration,
            justification=justification,
            risk_level=policy.risk_level,
            created_at=datetime.datetime.now().isoformat(),
            is_emergency=is_emergency,
            ticket_id=ticket_id
        )

        if is_emergency:
            # Emergency: grant immediately, require post-facto review
            request.status = RequestStatus.EMERGENCY
            now = datetime.datetime.now()
            request.granted_at = now.isoformat()
            request.expires_at = (now + datetime.timedelta(minutes=actual_duration)).isoformat()
            self._log_event("EMERGENCY_GRANT", request.request_id, {
                "requester": requester,
                "resource": target_resource,
                "duration_minutes": actual_duration,
                "justification": justification
            })
        elif policy.auto_approve and policy.risk_level == RiskLevel.LOW:
            # Auto-approve low-risk
            request.status = RequestStatus.APPROVED
            request.approved_by = ["AUTO"]
            self._log_event("AUTO_APPROVED", request.request_id, {
                "requester": requester,
                "resource": target_resource,
                "reason": "Low-risk auto-approve policy"
            })
            self._activate_access(request)
        else:
            # Route for approval
            request.approvers = policy.approver_roles
            request.status = RequestStatus.PENDING
            self._log_event("REQUEST_SUBMITTED", request.request_id, {
                "requester": requester,
                "resource": target_resource,
                "required_approvals": policy.required_approvals,
                "approvers": policy.approver_roles
            })

        self.requests[request.request_id] = request
        return request

    def approve_request(self, request_id: str, approver: str) -> JITAccessRequest:
        """Approve a JIT access request."""
        request = self.requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")
        if request.status not in (RequestStatus.PENDING,):
            raise ValueError(f"Request {request_id} is not pending approval")

        request.approved_by.append(approver)
        policy = self._get_policy(request.target_resource, request.resource_type)
        required = policy.required_approvals if policy else 1

        self._log_event("APPROVAL_RECORDED", request_id, {
            "approver": approver,
            "approvals_count": len(request.approved_by),
            "required": required
        })

        if len(request.approved_by) >= required:
            request.status = RequestStatus.APPROVED
            self._activate_access(request)

        return request

    def deny_request(self, request_id: str, denier: str, reason: str = "") -> JITAccessRequest:
        """Deny a JIT access request."""
        request = self.requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        request.status = RequestStatus.DENIED
        request.denied_by = denier
        self._log_event("REQUEST_DENIED", request_id, {
            "denied_by": denier,
            "reason": reason
        })
        return request

    def _activate_access(self, request: JITAccessRequest):
        """Activate the approved access grant."""
        now = datetime.datetime.now()
        request.status = RequestStatus.ACTIVE
        request.granted_at = now.isoformat()
        request.expires_at = (now + datetime.timedelta(
            minutes=request.requested_duration_minutes
        )).isoformat()

        self._log_event("ACCESS_ACTIVATED", request.request_id, {
            "requester": request.requester,
            "resource": request.target_resource,
            "granted_at": request.granted_at,
            "expires_at": request.expires_at
        })

    def check_expirations(self) -> List[JITAccessRequest]:
        """Check and revoke expired access grants."""
        now = datetime.datetime.now()
        expired = []

        for request in self.requests.values():
            if request.status in (RequestStatus.ACTIVE, RequestStatus.EMERGENCY):
                if request.expires_at:
                    expiry = datetime.datetime.fromisoformat(request.expires_at)
                    if now >= expiry:
                        request.status = RequestStatus.EXPIRED
                        request.revoked_at = now.isoformat()
                        expired.append(request)
                        self._log_event("ACCESS_EXPIRED", request.request_id, {
                            "requester": request.requester,
                            "resource": request.target_resource,
                            "expired_at": request.revoked_at
                        })

        return expired

    def revoke_access(self, request_id: str, reason: str = "") -> JITAccessRequest:
        """Manually revoke an active access grant."""
        request = self.requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        request.status = RequestStatus.REVOKED
        request.revoked_at = datetime.datetime.now().isoformat()
        self._log_event("ACCESS_REVOKED", request_id, {
            "requester": request.requester,
            "resource": request.target_resource,
            "reason": reason
        })
        return request

    def get_active_grants(self) -> List[JITAccessRequest]:
        """List all currently active access grants."""
        return [r for r in self.requests.values()
                if r.status in (RequestStatus.ACTIVE, RequestStatus.EMERGENCY)]

    def get_metrics(self) -> Dict:
        """Calculate JIT access metrics."""
        all_requests = list(self.requests.values())
        total = len(all_requests)
        if total == 0:
            return {"total": 0}

        by_status = {}
        for r in all_requests:
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1

        emergency_count = sum(1 for r in all_requests if r.is_emergency)

        # Calculate mean time to access
        approved = [r for r in all_requests if r.granted_at and r.created_at]
        if approved:
            total_wait = sum(
                (datetime.datetime.fromisoformat(r.granted_at) -
                 datetime.datetime.fromisoformat(r.created_at)).total_seconds()
                for r in approved
            )
            mean_tta = total_wait / len(approved) / 60  # minutes
        else:
            mean_tta = 0

        return {
            "total_requests": total,
            "by_status": by_status,
            "emergency_grants": emergency_count,
            "active_grants": len(self.get_active_grants()),
            "mean_time_to_access_minutes": round(mean_tta, 1),
            "audit_events": len(self.audit_log)
        }

    def generate_report(self) -> str:
        """Generate JIT access report."""
        metrics = self.get_metrics()
        active = self.get_active_grants()

        lines = [
            "=" * 70,
            "JUST-IN-TIME ACCESS PROVISIONING REPORT",
            "=" * 70,
            f"Report Date: {datetime.datetime.now().isoformat()}",
            f"Total Requests: {metrics['total_requests']}",
            f"Active Grants: {metrics['active_grants']}",
            f"Emergency Grants: {metrics['emergency_grants']}",
            f"Mean Time to Access: {metrics['mean_time_to_access_minutes']} minutes",
            f"Audit Events: {metrics['audit_events']}",
            "-" * 70,
            "",
            "STATUS BREAKDOWN:",
        ]
        for status, count in metrics.get("by_status", {}).items():
            lines.append(f"  {status}: {count}")
        lines.append("")

        if active:
            lines.append("ACTIVE GRANTS:")
            lines.append("-" * 40)
            for r in active:
                flag = " [EMERGENCY]" if r.is_emergency else ""
                lines.append(f"  {r.request_id}: {r.requester} -> {r.target_resource}{flag}")
                lines.append(f"    Expires: {r.expires_at}")
                lines.append(f"    Justification: {r.justification}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


def main():
    """Demo JIT access engine."""
    engine = JITAccessEngine()

    # Define resource policies
    engine.add_policy(ResourcePolicy(
        resource_pattern="*", resource_type="read_only",
        max_duration_minutes=60, risk_level=RiskLevel.LOW,
        auto_approve=True, required_approvals=0
    ))
    engine.add_policy(ResourcePolicy(
        resource_pattern="*", resource_type="production_server",
        max_duration_minutes=240, risk_level=RiskLevel.HIGH,
        auto_approve=False, required_approvals=2,
        approver_roles=["manager", "security_team"],
        session_recording=True
    ))
    engine.add_policy(ResourcePolicy(
        resource_pattern="*", resource_type="database_admin",
        max_duration_minutes=120, risk_level=RiskLevel.CRITICAL,
        auto_approve=False, required_approvals=2,
        approver_roles=["dba_lead", "security_team"],
        mfa_required=True, session_recording=True
    ))

    # Submit requests
    r1 = engine.submit_request("alice", "docs-server", "read_only", 30,
                               "Need to check documentation")
    r2 = engine.submit_request("bob", "prod-web-01", "production_server", 120,
                               "Deploy hotfix for CVE-2026-1234", ticket_id="INC-5678")
    r3 = engine.submit_request("charlie", "prod-db-01", "database_admin", 60,
                               "Critical production outage", is_emergency=True)

    # Approve prod server access
    engine.approve_request(r2.request_id, "manager_dave")
    engine.approve_request(r2.request_id, "security_eve")

    print(engine.generate_report())


if __name__ == "__main__":
    main()
