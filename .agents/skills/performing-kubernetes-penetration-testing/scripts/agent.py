#!/usr/bin/env python3
"""Agent for performing Kubernetes penetration testing — authorized testing only."""

import json
import argparse
import subprocess
from datetime import datetime


def enumerate_cluster_info():
    """Enumerate basic cluster information for reconnaissance."""
    results = {}
    cmds = {
        "version": ["kubectl", "version", "--output=json"],
        "nodes": ["kubectl", "get", "nodes", "-o", "json"],
        "namespaces": ["kubectl", "get", "namespaces", "-o", "json"],
        "services": ["kubectl", "get", "services", "--all-namespaces", "-o", "json"],
    }
    for key, cmd in cmds.items():
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            data = json.loads(result.stdout) if result.returncode == 0 else {"error": result.stderr[:200]}
            if key == "nodes":
                results[key] = [{"name": n["metadata"]["name"],
                                 "roles": [l.replace("node-role.kubernetes.io/", "") for l in n["metadata"].get("labels", {}) if l.startswith("node-role")],
                                 "os": n.get("status", {}).get("nodeInfo", {}).get("osImage", ""),
                                 "kubelet": n.get("status", {}).get("nodeInfo", {}).get("kubeletVersion", "")}
                                for n in data.get("items", [])]
            elif key == "namespaces":
                results[key] = [n["metadata"]["name"] for n in data.get("items", [])]
            elif key == "services":
                results[key] = [{"name": s["metadata"]["name"], "ns": s["metadata"]["namespace"],
                                 "type": s["spec"]["type"], "ports": [p.get("port") for p in s["spec"].get("ports", [])]}
                                for s in data.get("items", [])]
            else:
                results[key] = data
        except Exception as e:
            results[key] = {"error": str(e)}
    return {"timestamp": datetime.utcnow().isoformat(), **results}


def test_service_account_permissions(namespace="default"):
    """Test what the default service account can do."""
    checks = [
        ("get_pods", ["kubectl", "auth", "can-i", "get", "pods", "-n", namespace]),
        ("list_secrets", ["kubectl", "auth", "can-i", "list", "secrets", "-n", namespace]),
        ("create_pods", ["kubectl", "auth", "can-i", "create", "pods", "-n", namespace]),
        ("exec_pods", ["kubectl", "auth", "can-i", "create", "pods/exec", "-n", namespace]),
        ("get_nodes", ["kubectl", "auth", "can-i", "get", "nodes"]),
        ("list_namespaces", ["kubectl", "auth", "can-i", "list", "namespaces"]),
        ("create_clusterroles", ["kubectl", "auth", "can-i", "create", "clusterroles"]),
        ("get_secrets_all", ["kubectl", "auth", "can-i", "get", "secrets", "--all-namespaces"]),
    ]
    results = []
    for name, cmd in checks:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            allowed = "yes" in result.stdout.lower()
            results.append({"check": name, "allowed": allowed})
        except Exception as e:
            results.append({"check": name, "error": str(e)})
    dangerous = [r for r in results if r.get("allowed") and r["check"] in ("list_secrets", "create_pods", "exec_pods", "create_clusterroles", "get_secrets_all")]
    return {
        "namespace": namespace, "permissions": results,
        "dangerous_permissions": dangerous,
        "risk": "CRITICAL" if dangerous else "LOW",
    }


def scan_exposed_dashboards():
    """Check for exposed Kubernetes dashboards and management interfaces."""
    cmd = ["kubectl", "get", "services", "--all-namespaces", "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        dashboard_patterns = ["dashboard", "grafana", "prometheus", "kibana", "jaeger", "argocd", "rancher", "lens"]
        exposed = []
        for svc in data.get("items", []):
            name = svc["metadata"]["name"].lower()
            svc_type = svc["spec"]["type"]
            if any(p in name for p in dashboard_patterns):
                ports = [{"port": p.get("port"), "nodePort": p.get("nodePort")} for p in svc["spec"].get("ports", [])]
                exposed.append({
                    "name": svc["metadata"]["name"], "namespace": svc["metadata"]["namespace"],
                    "type": svc_type, "ports": ports,
                    "externally_accessible": svc_type in ("LoadBalancer", "NodePort"),
                })
        return {"dashboards_found": len(exposed), "exposed": exposed}
    except Exception as e:
        return {"error": str(e)}


def check_pod_escape_vectors(namespace="default"):
    """Check for container escape vectors in running pods."""
    cmd = ["kubectl", "get", "pods", "-n", namespace, "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout)
        escape_vectors = []
        for pod in data.get("items", []):
            name = pod["metadata"]["name"]
            for c in pod.get("spec", {}).get("containers", []):
                vectors = []
                sc = c.get("securityContext", {})
                if sc.get("privileged"):
                    vectors.append("PRIVILEGED_MODE")
                caps = sc.get("capabilities", {}).get("add", [])
                if "SYS_ADMIN" in caps:
                    vectors.append("CAP_SYS_ADMIN")
                if "SYS_PTRACE" in caps:
                    vectors.append("CAP_SYS_PTRACE")
                for vol in pod.get("spec", {}).get("volumes", []):
                    hp = vol.get("hostPath", {}).get("path", "")
                    if hp in ("/", "/etc", "/var/run/docker.sock", "/proc", "/sys"):
                        vectors.append(f"HOST_PATH_MOUNT:{hp}")
                if pod.get("spec", {}).get("hostPID"):
                    vectors.append("HOST_PID_NAMESPACE")
                if pod.get("spec", {}).get("hostNetwork"):
                    vectors.append("HOST_NETWORK")
                if vectors:
                    escape_vectors.append({"pod": name, "container": c["name"], "vectors": vectors})
        return {
            "namespace": namespace, "pods_checked": len(data.get("items", [])),
            "pods_with_escape_vectors": len(escape_vectors),
            "details": escape_vectors,
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Penetration Testing Agent (Authorized Only)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("recon", help="Enumerate cluster info")
    sa = sub.add_parser("sa-perms", help="Test service account permissions")
    sa.add_argument("--namespace", default="default")
    sub.add_parser("dashboards", help="Find exposed dashboards")
    e = sub.add_parser("escape", help="Check container escape vectors")
    e.add_argument("--namespace", default="default")
    args = parser.parse_args()
    if args.command == "recon":
        result = enumerate_cluster_info()
    elif args.command == "sa-perms":
        result = test_service_account_permissions(args.namespace)
    elif args.command == "dashboards":
        result = scan_exposed_dashboards()
    elif args.command == "escape":
        result = check_pod_escape_vectors(args.namespace)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
