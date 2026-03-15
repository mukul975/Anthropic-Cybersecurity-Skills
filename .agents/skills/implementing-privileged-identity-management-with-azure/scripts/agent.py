#!/usr/bin/env python3
"""Manage Azure AD PIM: eligible role assignments, JIT activation, access reviews via Microsoft Graph API."""

import argparse
import json
import sys
from datetime import datetime, timezone


def get_graph_token(tenant_id, client_id, client_secret):
    """Acquire OAuth2 token for Microsoft Graph API using client credentials flow."""
    try:
        import msal
    except ImportError:
        print("Install required package: pip install msal", file=sys.stderr)
        sys.exit(1)

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        print(f"Token acquisition failed: {result.get('error_description', 'Unknown error')}", file=sys.stderr)
        sys.exit(1)
    return result["access_token"]


def graph_request(token, method, endpoint, body=None):
    """Make authenticated request to Microsoft Graph API."""
    import requests

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    url = f"https://graph.microsoft.com/v1.0{endpoint}"

    if method == "GET":
        resp = requests.get(url, headers=headers, timeout=30)
    elif method == "POST":
        resp = requests.post(url, headers=headers, json=body, timeout=30)
    elif method == "PATCH":
        resp = requests.patch(url, headers=headers, json=body, timeout=30)
    else:
        raise ValueError(f"Unsupported method: {method}")

    if resp.status_code >= 400:
        return {"error": resp.status_code, "message": resp.text}
    return resp.json() if resp.text else {}


def list_eligible_assignments(token):
    """List all eligible role assignments via PIM."""
    results = []
    endpoint = "/roleManagement/directory/roleEligibilityScheduleInstances"
    response = graph_request(token, "GET", endpoint)

    if "error" in response:
        return [response]

    for item in response.get("value", []):
        results.append({
            "id": item.get("id"),
            "principal_id": item.get("principalId"),
            "role_definition_id": item.get("roleDefinitionId"),
            "directory_scope_id": item.get("directoryScopeId"),
            "start_date_time": item.get("startDateTime"),
            "end_date_time": item.get("endDateTime"),
            "assignment_type": item.get("assignmentType"),
            "member_type": item.get("memberType")
        })
    return results


def list_active_assignments(token):
    """List all active (permanent and temporary) role assignments."""
    results = []
    endpoint = "/roleManagement/directory/roleAssignmentScheduleInstances"
    response = graph_request(token, "GET", endpoint)

    if "error" in response:
        return [response]

    for item in response.get("value", []):
        results.append({
            "id": item.get("id"),
            "principal_id": item.get("principalId"),
            "role_definition_id": item.get("roleDefinitionId"),
            "directory_scope_id": item.get("directoryScopeId"),
            "start_date_time": item.get("startDateTime"),
            "end_date_time": item.get("endDateTime"),
            "assignment_type": item.get("assignmentType"),
            "member_type": item.get("memberType")
        })
    return results


def create_eligible_assignment(token, principal_id, role_definition_id, justification, duration_hours=8):
    """Create an eligible role assignment via PIM eligibility schedule request."""
    body = {
        "action": "adminAssign",
        "justification": justification,
        "roleDefinitionId": role_definition_id,
        "directoryScopeId": "/",
        "principalId": principal_id,
        "scheduleInfo": {
            "startDateTime": datetime.now(timezone.utc).isoformat(),
            "expiration": {
                "type": "afterDuration",
                "duration": f"PT{duration_hours}H"
            }
        }
    }
    endpoint = "/roleManagement/directory/roleEligibilityScheduleRequests"
    return graph_request(token, "POST", endpoint, body)


def activate_eligible_role(token, role_definition_id, justification, duration_hours=1):
    """Activate an eligible role assignment (self-activate JIT access)."""
    body = {
        "action": "selfActivate",
        "justification": justification,
        "roleDefinitionId": role_definition_id,
        "directoryScopeId": "/",
        "principalId": "me",
        "scheduleInfo": {
            "startDateTime": datetime.now(timezone.utc).isoformat(),
            "expiration": {
                "type": "afterDuration",
                "duration": f"PT{duration_hours}H"
            }
        }
    }
    endpoint = "/roleManagement/directory/roleAssignmentScheduleRequests"
    return graph_request(token, "POST", endpoint, body)


def list_role_definitions(token):
    """List all Microsoft Entra role definitions."""
    endpoint = "/roleManagement/directory/roleDefinitions"
    response = graph_request(token, "GET", endpoint)
    if "error" in response:
        return [response]
    return [
        {
            "id": r.get("id"),
            "display_name": r.get("displayName"),
            "is_built_in": r.get("isBuiltIn"),
            "is_enabled": r.get("isEnabled")
        }
        for r in response.get("value", [])
    ]


def audit_pim_activations(token, days=7):
    """Query directory audit logs for PIM role activation events."""
    from datetime import timedelta
    start_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    endpoint = (
        f"/auditLogs/directoryAudits?"
        f"$filter=activityDisplayName eq 'Add member to role completed (PIM activation)' "
        f"and activityDateTime ge {start_date}"
    )
    response = graph_request(token, "GET", endpoint)
    if "error" in response:
        return [response]

    activations = []
    for entry in response.get("value", []):
        activations.append({
            "activity": entry.get("activityDisplayName"),
            "timestamp": entry.get("activityDateTime"),
            "initiated_by": entry.get("initiatedBy", {}).get("user", {}).get("userPrincipalName"),
            "target_resources": [
                {"display_name": t.get("displayName"), "type": t.get("type")}
                for t in entry.get("targetResources", [])
            ],
            "result": entry.get("result")
        })
    return activations


def get_role_management_policies(token):
    """Retrieve role management policies to check MFA/approval requirements."""
    endpoint = "/policies/roleManagementPolicies"
    response = graph_request(token, "GET", endpoint)
    if "error" in response:
        return [response]

    policies = []
    for policy in response.get("value", []):
        policies.append({
            "id": policy.get("id"),
            "display_name": policy.get("displayName"),
            "scope_id": policy.get("scopeId"),
            "scope_type": policy.get("scopeType"),
            "last_modified": policy.get("lastModifiedDateTime")
        })
    return policies


def generate_audit_report(token):
    """Generate comprehensive PIM audit report."""
    eligible = list_eligible_assignments(token)
    active = list_active_assignments(token)
    roles = list_role_definitions(token)

    permanent_active = [a for a in active if not a.get("end_date_time")]
    temporary_active = [a for a in active if a.get("end_date_time")]

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_role_definitions": len(roles),
            "eligible_assignments": len(eligible),
            "active_assignments": len(active),
            "permanent_active_assignments": len(permanent_active),
            "temporary_active_assignments": len(temporary_active)
        },
        "findings": [],
        "eligible_assignments": eligible,
        "permanent_active_assignments": permanent_active
    }

    if len(permanent_active) > 0:
        report["findings"].append({
            "severity": "High",
            "check": "permanent_privileged_assignments",
            "message": f"{len(permanent_active)} permanent active role assignments found — consider converting to eligible",
            "count": len(permanent_active)
        })

    if len(eligible) == 0 and len(active) > 0:
        report["findings"].append({
            "severity": "High",
            "check": "no_eligible_assignments",
            "message": "No eligible (JIT) assignments configured — all access is permanent"
        })

    return report


def main():
    parser = argparse.ArgumentParser(description="Azure AD PIM management via Microsoft Graph API")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="Application (client) ID")
    parser.add_argument("--client-secret", required=True, help="Client secret")

    subparsers = parser.add_subparsers(dest="command", help="PIM operation")

    subparsers.add_parser("list-eligible", help="List eligible role assignments")
    subparsers.add_parser("list-active", help="List active role assignments")
    subparsers.add_parser("list-roles", help="List role definitions")
    subparsers.add_parser("audit-report", help="Generate PIM audit report")

    audit_parser = subparsers.add_parser("audit-activations", help="Query PIM activation logs")
    audit_parser.add_argument("--days", type=int, default=7, help="Look back N days (default: 7)")

    create_parser = subparsers.add_parser("create-eligible", help="Create eligible assignment")
    create_parser.add_argument("--principal-id", required=True, help="User/group object ID")
    create_parser.add_argument("--role-id", required=True, help="Role definition ID")
    create_parser.add_argument("--justification", required=True, help="Business justification")
    create_parser.add_argument("--duration", type=int, default=8, help="Duration in hours (default: 8)")

    activate_parser = subparsers.add_parser("activate", help="Activate eligible role (JIT)")
    activate_parser.add_argument("--role-id", required=True, help="Role definition ID")
    activate_parser.add_argument("--justification", required=True, help="Activation justification")
    activate_parser.add_argument("--duration", type=int, default=1, help="Duration in hours (default: 1)")

    subparsers.add_parser("policies", help="List role management policies")

    args = parser.parse_args()
    token = get_graph_token(args.tenant_id, args.client_id, args.client_secret)

    if args.command == "list-eligible":
        result = list_eligible_assignments(token)
    elif args.command == "list-active":
        result = list_active_assignments(token)
    elif args.command == "list-roles":
        result = list_role_definitions(token)
    elif args.command == "audit-report":
        result = generate_audit_report(token)
    elif args.command == "audit-activations":
        result = audit_pim_activations(token, args.days)
    elif args.command == "create-eligible":
        result = create_eligible_assignment(token, args.principal_id, args.role_id, args.justification, args.duration)
    elif args.command == "activate":
        result = activate_eligible_role(token, args.role_id, args.justification, args.duration)
    elif args.command == "policies":
        result = get_role_management_policies(token)
    else:
        parser.print_help()
        sys.exit(0)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
