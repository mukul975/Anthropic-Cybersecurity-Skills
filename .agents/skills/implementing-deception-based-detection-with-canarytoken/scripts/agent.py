#!/usr/bin/env python3
"""Agent for deploying and monitoring Canary Tokens via the Thinkst Canary API."""

import json
import argparse
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

TOKEN_KINDS = {
    "http": "http",
    "dns": "dns",
    "doc-msword": "doc-msword",
    "pdf-acrobat-reader": "pdf-acrobat-reader",
    "web-image": "web-image",
    "cloned-web": "cloned-web",
    "aws-id": "aws-id",
    "qr-code": "qr-code",
    "sql": "sql",
    "svn": "svn",
    "smtp": "smtp",
    "windows-dir": "windows-dir",
    "sensitive-cmd": "sensitive-cmd",
}


class CanaryClient:
    """Client for the Thinkst Canary Console REST API."""

    def __init__(self, console_domain, auth_token):
        self.base_url = f"https://{console_domain}.canary.tools/api/v1"
        self.auth_token = auth_token

    def _get(self, endpoint, params=None):
        params = params or {}
        params["auth_token"] = self.auth_token
        resp = requests.get(f"{self.base_url}{endpoint}", params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint, data=None, files=None):
        data = data or {}
        data["auth_token"] = self.auth_token
        resp = requests.post(f"{self.base_url}{endpoint}", data=data, files=files, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def ping(self):
        """Test API connectivity."""
        return self._get("/ping")

    def create_token(self, kind, memo, **kwargs):
        """Create a new Canarytoken.

        Args:
            kind: Token type (http, dns, doc-msword, aws-id, etc.)
            memo: Description/reminder for the token
            **kwargs: Additional parameters (e.g., cloned_web for cloned-web type)
        """
        data = {"kind": kind, "memo": memo}
        data.update(kwargs)
        files = None
        if kind == "doc-msword" and "doc" in kwargs:
            doc_path = kwargs.pop("doc")
            data.pop("doc", None)
            files = {"doc": (doc_path, open(doc_path, "rb"),
                            "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
        return self._post("/canarytoken/create", data=data, files=files)

    def list_tokens(self):
        """List all Canarytokens on the console."""
        return self._get("/canarytokens/fetch")

    def get_token(self, canarytoken):
        """Get details for a specific token."""
        return self._get("/canarytoken/fetch", params={"canarytoken": canarytoken})

    def delete_token(self, canarytoken):
        """Delete a Canarytoken."""
        return self._post("/canarytoken/delete", data={"canarytoken": canarytoken})

    def get_alerts(self, newer_than=None):
        """Fetch recent alerts from triggered tokens."""
        params = {}
        if newer_than:
            params["newer_than"] = newer_than
        return self._get("/incidents/all", params=params)

    def get_token_alerts(self, canarytoken):
        """Fetch alerts for a specific token."""
        return self._get("/canarytoken/incidents", params={"canarytoken": canarytoken})

    def ack_alert(self, incident_id):
        """Acknowledge an alert."""
        return self._post("/incident/acknowledge", data={"incident": incident_id})


def create_deployment(client, deployment_plan):
    """Create multiple tokens based on a deployment plan."""
    results = []
    for token_spec in deployment_plan:
        kind = token_spec.get("kind", "http")
        memo = token_spec.get("memo", f"Canarytoken - {kind}")
        extra = {k: v for k, v in token_spec.items() if k not in ("kind", "memo")}
        try:
            resp = client.create_token(kind, memo, **extra)
            results.append({
                "kind": kind,
                "memo": memo,
                "status": "CREATED",
                "canarytoken": resp.get("canarytoken", {}).get("canarytoken", ""),
                "url": resp.get("canarytoken", {}).get("url", ""),
            })
        except Exception as e:
            results.append({"kind": kind, "memo": memo, "status": "FAILED", "error": str(e)})
    return results


def audit_token_coverage(client):
    """Audit deployed token coverage and generate report."""
    tokens_resp = client.list_tokens()
    tokens = tokens_resp.get("tokens", [])
    alerts_resp = client.get_alerts()
    alerts = alerts_resp.get("incidents", [])

    kind_counts = {}
    triggered_tokens = set()
    for token in tokens:
        kind = token.get("kind", "unknown")
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

    for alert in alerts:
        triggered_tokens.add(alert.get("canarytoken", ""))

    untriggered = [t for t in tokens if t.get("canarytoken", "") not in triggered_tokens]
    recommended_types = []
    for kind_name in TOKEN_KINDS:
        if kind_name not in kind_counts:
            recommended_types.append(kind_name)

    return {
        "total_tokens": len(tokens),
        "total_alerts": len(alerts),
        "tokens_by_kind": kind_counts,
        "triggered_token_count": len(triggered_tokens),
        "untriggered_tokens": len(untriggered),
        "missing_token_types": recommended_types,
        "coverage_score": round(len(kind_counts) / len(TOKEN_KINDS) * 100, 1),
    }


def full_audit(client):
    """Run comprehensive Canarytoken deployment audit."""
    coverage = audit_token_coverage(client)
    tokens_resp = client.list_tokens()
    tokens = tokens_resp.get("tokens", [])
    alerts_resp = client.get_alerts()
    alerts = alerts_resp.get("incidents", [])

    token_details = []
    for t in tokens[:30]:
        token_details.append({
            "canarytoken": t.get("canarytoken"),
            "kind": t.get("kind"),
            "memo": t.get("memo"),
            "created": t.get("created_printable"),
            "enabled": t.get("enabled"),
            "url": t.get("url", ""),
        })

    alert_details = []
    for a in alerts[:20]:
        alert_details.append({
            "incident_id": a.get("id"),
            "description": a.get("description"),
            "source_ip": a.get("src_host"),
            "timestamp": a.get("created_printable"),
            "canarytoken": a.get("canarytoken"),
            "acknowledged": a.get("acknowledged"),
        })

    return {
        "audit_type": "Canarytoken Deception Coverage Audit",
        "timestamp": datetime.utcnow().isoformat(),
        "coverage": coverage,
        "deployed_tokens": token_details,
        "recent_alerts": alert_details,
        "recommendation": "Deploy missing token types to improve coverage"
            if coverage["coverage_score"] < 50 else "Good coverage — review untriggered tokens",
    }


def main():
    parser = argparse.ArgumentParser(description="Canarytoken Deception Detection Agent")
    parser.add_argument("--console", required=True, help="Canary Console domain (e.g., abc123)")
    parser.add_argument("--auth-token", required=True, help="API auth token")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("ping", help="Test API connectivity")
    sub.add_parser("list", help="List all deployed tokens")
    sub.add_parser("alerts", help="Fetch recent alerts")
    p_create = sub.add_parser("create", help="Create a new token")
    p_create.add_argument("--kind", required=True, choices=list(TOKEN_KINDS.keys()))
    p_create.add_argument("--memo", required=True)
    sub.add_parser("coverage", help="Audit token coverage")
    sub.add_parser("full", help="Full deception audit")
    args = parser.parse_args()

    client = CanaryClient(args.console, args.auth_token)

    if args.command == "ping":
        result = client.ping()
    elif args.command == "list":
        result = client.list_tokens()
    elif args.command == "alerts":
        result = client.get_alerts()
    elif args.command == "create":
        result = client.create_token(args.kind, args.memo)
    elif args.command == "coverage":
        result = audit_token_coverage(client)
    elif args.command == "full" or args.command is None:
        result = full_audit(client)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
