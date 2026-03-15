#!/usr/bin/env python3
"""Agent for performing Kubernetes etcd security assessment."""

import json
import argparse
import subprocess
import re
from datetime import datetime


def check_etcd_encryption(kubeconfig=None):
    """Check if etcd encryption at rest is configured."""
    cmd = ["kubectl", "get", "apiserver", "-o", "json"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        enc_cmd = ["kubectl", "get", "pods", "-n", "kube-system", "-l", "component=kube-apiserver", "-o", "json"]
        if kubeconfig:
            enc_cmd += ["--kubeconfig", kubeconfig]
        result = subprocess.run(enc_cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        findings = []
        for pod in data.get("items", []):
            containers = pod.get("spec", {}).get("containers", [])
            for c in containers:
                args_list = c.get("command", []) + c.get("args", [])
                args_str = " ".join(args_list)
                has_encryption = "--encryption-provider-config" in args_str
                has_audit = "--audit-log-path" in args_str
                etcd_servers = re.findall(r"--etcd-servers=([^\s]+)", args_str)
                uses_tls = all("https" in s for s in etcd_servers) if etcd_servers else False
                findings.append({
                    "pod": pod.get("metadata", {}).get("name"),
                    "encryption_at_rest": has_encryption,
                    "audit_logging": has_audit,
                    "etcd_tls": uses_tls,
                    "etcd_servers": etcd_servers,
                })
        return {"checks": findings, "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        return {"error": str(e)}


def check_etcd_access(etcd_endpoint="https://127.0.0.1:2379", cert=None, key=None, cacert=None):
    """Test etcd access and check for unauthenticated access."""
    cmd = ["etcdctl", "endpoint", "health", "--endpoints", etcd_endpoint]
    if cert:
        cmd += ["--cert", cert, "--key", key, "--cacert", cacert]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        healthy = "healthy" in result.stdout.lower()
        unauth_cmd = ["etcdctl", "get", "/", "--prefix", "--limit", "1", "--endpoints", etcd_endpoint]
        unauth_result = subprocess.run(unauth_cmd, capture_output=True, text=True, timeout=10)
        unauth_access = unauth_result.returncode == 0 and unauth_result.stdout.strip()
        return {
            "endpoint": etcd_endpoint,
            "healthy": healthy,
            "unauthenticated_access": unauth_access,
            "severity": "CRITICAL" if unauth_access else "INFO",
            "finding": "ETCD_UNAUTHENTICATED_ACCESS" if unauth_access else "ETCD_AUTH_REQUIRED",
        }
    except FileNotFoundError:
        return {"error": "etcdctl not found"}
    except Exception as e:
        return {"error": str(e)}


def dump_secrets_check(kubeconfig=None):
    """Check if secrets are stored unencrypted in etcd."""
    cmd = ["kubectl", "get", "secrets", "--all-namespaces", "-o", "json"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        secrets = data.get("items", [])
        secret_types = {}
        sensitive = []
        for s in secrets:
            stype = s.get("type", "Opaque")
            secret_types[stype] = secret_types.get(stype, 0) + 1
            name = s.get("metadata", {}).get("name", "")
            ns = s.get("metadata", {}).get("namespace", "")
            if any(kw in name.lower() for kw in ["password", "token", "key", "cert", "credential", "tls"]):
                sensitive.append({"name": name, "namespace": ns, "type": stype})
        return {
            "total_secrets": len(secrets),
            "by_type": secret_types,
            "sensitive_secrets": sensitive[:20],
            "recommendation": "Enable EncryptionConfiguration for secrets at rest",
        }
    except Exception as e:
        return {"error": str(e)}


def check_etcd_tls_config():
    """Verify etcd TLS certificate configuration."""
    cmd = ["kubectl", "get", "pods", "-n", "kube-system", "-l", "component=etcd", "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        findings = []
        for pod in data.get("items", []):
            for c in pod.get("spec", {}).get("containers", []):
                args_str = " ".join(c.get("command", []) + c.get("args", []))
                peer_tls = "--peer-cert-file" in args_str and "--peer-key-file" in args_str
                client_tls = "--cert-file" in args_str and "--key-file" in args_str
                client_auth = "--client-cert-auth=true" in args_str or "--client-cert-auth true" in args_str
                findings.append({
                    "pod": pod.get("metadata", {}).get("name"),
                    "peer_tls_enabled": peer_tls,
                    "client_tls_enabled": client_tls,
                    "client_cert_auth": client_auth,
                    "issues": [
                        i for i in [
                            "NO_PEER_TLS" if not peer_tls else None,
                            "NO_CLIENT_TLS" if not client_tls else None,
                            "NO_CLIENT_CERT_AUTH" if not client_auth else None,
                        ] if i
                    ],
                })
        return {"etcd_tls_checks": findings}
    except Exception as e:
        return {"error": str(e)}


def full_assessment(kubeconfig=None, etcd_endpoint=None):
    """Run comprehensive etcd security assessment."""
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "encryption": check_etcd_encryption(kubeconfig),
        "secrets": dump_secrets_check(kubeconfig),
        "tls": check_etcd_tls_config(),
    }
    if etcd_endpoint:
        results["access"] = check_etcd_access(etcd_endpoint)
    issues = []
    enc = results["encryption"]
    if isinstance(enc, dict) and enc.get("checks"):
        for c in enc["checks"]:
            if not c.get("encryption_at_rest"):
                issues.append("ENCRYPTION_AT_REST_DISABLED")
            if not c.get("etcd_tls"):
                issues.append("ETCD_COMMUNICATION_NOT_TLS")
    results["critical_issues"] = list(set(issues))
    results["risk_level"] = "CRITICAL" if issues else "LOW"
    return results


def main():
    parser = argparse.ArgumentParser(description="Kubernetes etcd Security Assessment Agent")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("encrypt", help="Check encryption at rest")
    a = sub.add_parser("access", help="Test etcd access")
    a.add_argument("--endpoint", default="https://127.0.0.1:2379")
    a.add_argument("--cert", help="Client certificate")
    a.add_argument("--key", help="Client key")
    a.add_argument("--cacert", help="CA certificate")
    sub.add_parser("secrets", help="Check secrets storage")
    sub.add_parser("tls", help="Check TLS configuration")
    f = sub.add_parser("full", help="Full assessment")
    f.add_argument("--endpoint", help="etcd endpoint URL")
    args = parser.parse_args()
    kc = args.kubeconfig if hasattr(args, "kubeconfig") else None
    if args.command == "encrypt":
        result = check_etcd_encryption(kc)
    elif args.command == "access":
        result = check_etcd_access(args.endpoint, args.cert, args.key, args.cacert)
    elif args.command == "secrets":
        result = dump_secrets_check(kc)
    elif args.command == "tls":
        result = check_etcd_tls_config()
    elif args.command == "full":
        result = full_assessment(kc, args.endpoint if hasattr(args, "endpoint") else None)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
