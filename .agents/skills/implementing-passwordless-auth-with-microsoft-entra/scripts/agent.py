#!/usr/bin/env python3
"""Microsoft Entra ID passwordless authentication audit agent using MS Graph API."""

import json
import sys
import argparse
from datetime import datetime

try:
    import requests
    from msal import ConfidentialClientApplication
except ImportError:
    print("Install: pip install msal requests")
    sys.exit(1)


GRAPH_URL = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


def get_access_token(tenant_id, client_id, client_secret):
    """Authenticate to Microsoft Graph using client credentials."""
    app = ConfidentialClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret)
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in result:
        return result["access_token"]
    print(f"[!] Auth failed: {result.get('error_description', 'Unknown error')}")
    sys.exit(1)


def graph_get(token, endpoint, beta=False):
    """Make authenticated GET request to Microsoft Graph."""
    base = GRAPH_BETA if beta else GRAPH_URL
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.get(f"{base}{endpoint}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_auth_methods_policy(token):
    """Get authentication methods policy to check passwordless configuration."""
    return graph_get(token, "/policies/authenticationMethodsPolicy", beta=True)


def get_fido2_policy(token):
    """Get FIDO2 security key configuration."""
    policy = get_auth_methods_policy(token)
    for method in policy.get("authenticationMethodConfigurations", []):
        if method.get("id") == "fido2":
            return {
                "state": method.get("state"),
                "is_attestation_enforced": method.get("isAttestationEnforced"),
                "is_self_service_allowed": method.get("isSelfServiceRegistrationAllowed"),
                "key_restrictions": method.get("keyRestrictions", {}),
            }
    return {"state": "not_configured"}


def get_microsoft_authenticator_policy(token):
    """Get Microsoft Authenticator configuration."""
    policy = get_auth_methods_policy(token)
    for method in policy.get("authenticationMethodConfigurations", []):
        if method.get("id") == "microsoftAuthenticator":
            return {
                "state": method.get("state"),
                "feature_settings": method.get("featureSettings", {}),
            }
    return {"state": "not_configured"}


def get_windows_hello_policy(token):
    """Get Windows Hello for Business configuration."""
    policy = get_auth_methods_policy(token)
    for method in policy.get("authenticationMethodConfigurations", []):
        if method.get("id") == "windowsHelloForBusiness":
            return {"state": method.get("state")}
    return {"state": "not_configured"}


def list_user_auth_methods(token, user_id):
    """List authentication methods registered by a specific user."""
    try:
        methods = graph_get(token, f"/users/{user_id}/authentication/methods")
        return [{"id": m.get("id"), "type": m.get("@odata.type", "").split(".")[-1]}
                for m in methods.get("value", [])]
    except Exception as e:
        return [{"error": str(e)}]


def get_users_without_passwordless(token, max_users=100):
    """Identify users who have not registered any passwordless method."""
    users = graph_get(token, f"/users?$top={max_users}&$select=id,displayName,userPrincipalName")
    users_without = []
    for user in users.get("value", []):
        methods = list_user_auth_methods(token, user["id"])
        passwordless_types = {"fido2AuthenticationMethod", "microsoftAuthenticatorAuthenticationMethod",
                              "windowsHelloForBusinessAuthenticationMethod"}
        user_types = {m.get("type") for m in methods if not m.get("error")}
        if not user_types.intersection(passwordless_types):
            users_without.append({
                "user": user["userPrincipalName"],
                "name": user.get("displayName", ""),
                "methods": [m.get("type") for m in methods if not m.get("error")],
            })
    return users_without


def get_sign_in_logs(token, days=7, passwordless_only=False):
    """Get recent sign-in logs to analyze authentication methods used."""
    filter_str = ""
    if passwordless_only:
        filter_str = "?$filter=authenticationDetails/any(a:a/authenticationMethod eq 'FIDO2 security key')"
    try:
        logs = graph_get(token, f"/auditLogs/signIns{filter_str}", beta=True)
        return [{"user": log.get("userPrincipalName"),
                 "app": log.get("appDisplayName"),
                 "status": log.get("status", {}).get("errorCode", 0),
                 "auth_detail": [d.get("authenticationMethod") for d in log.get("authenticationDetails", [])],
                 "time": log.get("createdDateTime")}
                for log in logs.get("value", [])[:50]]
    except Exception as e:
        return [{"error": str(e)}]


def get_conditional_access_policies(token):
    """List conditional access policies related to authentication strength."""
    try:
        policies = graph_get(token, "/identity/conditionalAccess/policies", beta=True)
        auth_strength_policies = []
        for p in policies.get("value", []):
            grant = p.get("grantControls", {})
            if grant and "authenticationStrength" in json.dumps(grant):
                auth_strength_policies.append({
                    "name": p.get("displayName"),
                    "state": p.get("state"),
                    "grant_controls": grant,
                })
        return auth_strength_policies
    except Exception as e:
        return [{"error": str(e)}]


def run_passwordless_audit(token):
    """Run comprehensive passwordless authentication audit."""
    print(f"\n{'='*60}")
    print(f"  MICROSOFT ENTRA PASSWORDLESS AUTH AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    fido2 = get_fido2_policy(token)
    print(f"--- FIDO2 SECURITY KEYS ---")
    print(f"  State: {fido2.get('state', 'unknown')}")
    print(f"  Attestation Enforced: {fido2.get('is_attestation_enforced', 'N/A')}")
    print(f"  Self-Service Registration: {fido2.get('is_self_service_allowed', 'N/A')}")

    authenticator = get_microsoft_authenticator_policy(token)
    print(f"\n--- MICROSOFT AUTHENTICATOR ---")
    print(f"  State: {authenticator.get('state', 'unknown')}")

    hello = get_windows_hello_policy(token)
    print(f"\n--- WINDOWS HELLO FOR BUSINESS ---")
    print(f"  State: {hello.get('state', 'unknown')}")

    ca_policies = get_conditional_access_policies(token)
    print(f"\n--- CONDITIONAL ACCESS (Auth Strength) ({len(ca_policies)}) ---")
    for p in ca_policies:
        print(f"  {p.get('name', 'N/A')}: {p.get('state', 'N/A')}")

    users_without = get_users_without_passwordless(token, max_users=50)
    print(f"\n--- USERS WITHOUT PASSWORDLESS ({len(users_without)}) ---")
    for u in users_without[:10]:
        print(f"  {u['user']} - Current methods: {', '.join(u['methods']) or 'none'}")

    print(f"\n{'='*60}\n")
    return {"fido2": fido2, "authenticator": authenticator, "hello": hello,
            "users_without_passwordless": len(users_without)}


def main():
    parser = argparse.ArgumentParser(description="Microsoft Entra Passwordless Auth Agent")
    parser.add_argument("--tenant-id", required=True, help="Azure AD tenant ID")
    parser.add_argument("--client-id", required=True, help="App registration client ID")
    parser.add_argument("--client-secret", required=True, help="App registration secret")
    parser.add_argument("--audit", action="store_true", help="Run passwordless audit")
    parser.add_argument("--user-methods", help="List auth methods for specific user")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    token = get_access_token(args.tenant_id, args.client_id, args.client_secret)

    if args.audit:
        report = run_passwordless_audit(token)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.user_methods:
        methods = list_user_auth_methods(token, args.user_methods)
        print(json.dumps(methods, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
