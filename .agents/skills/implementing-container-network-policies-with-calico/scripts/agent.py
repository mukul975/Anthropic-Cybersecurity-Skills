#!/usr/bin/env python3
"""Agent for implementing container network policies with Calico.

Audits Kubernetes network policies, identifies unprotected
namespaces, validates Calico policy enforcement, and generates
default-deny baseline policy manifests.
"""

import argparse
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

try:
    from kubernetes import client, config
except ImportError:
    client = None
    config = None


DEFAULT_DENY_INGRESS = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "default-deny-ingress"},
    "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
}

DEFAULT_DENY_EGRESS = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "metadata": {"name": "default-deny-egress"},
    "spec": {"podSelector": {}, "policyTypes": ["Egress"]},
}


class CalicoNetworkPolicyAgent:
    """Audits and manages Calico network policies on Kubernetes."""

    def __init__(self, kubeconfig=None, output_dir="./calico_policy_audit"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.v1 = None
        self.net_v1 = None
        if client and config:
            try:
                if kubeconfig:
                    config.load_kube_config(config_file=kubeconfig)
                else:
                    config.load_kube_config()
                self.v1 = client.CoreV1Api()
                self.net_v1 = client.NetworkingV1Api()
            except Exception:
                pass

    def _run_calicoctl(self, args):
        """Run calicoctl command and return parsed output."""
        try:
            result = subprocess.run(
                ["calicoctl"] + args, capture_output=True, text=True, timeout=30
            )
            return result.stdout, result.returncode
        except FileNotFoundError:
            return "", 1
        except subprocess.TimeoutExpired:
            return "", 1

    def list_k8s_network_policies(self):
        """List all Kubernetes NetworkPolicy resources across namespaces."""
        if not self.net_v1:
            return []
        policies = self.net_v1.list_network_policy_for_all_namespaces()
        return [{"name": p.metadata.name, "namespace": p.metadata.namespace,
                 "pod_selector": p.spec.pod_selector.match_labels or {},
                 "policy_types": p.spec.policy_types or [],
                 "ingress_rules": len(p.spec.ingress or []),
                 "egress_rules": len(p.spec.egress or [])}
                for p in policies.items]

    def list_calico_policies(self):
        """List Calico-specific NetworkPolicy and GlobalNetworkPolicy resources."""
        policies = []
        stdout, rc = self._run_calicoctl(["get", "networkpolicy", "-o", "json", "--all-namespaces"])
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                items = data.get("items", [data]) if "items" in data else [data]
                for item in items:
                    meta = item.get("metadata", {})
                    policies.append({"kind": "NetworkPolicy", "name": meta.get("name"),
                                     "namespace": meta.get("namespace")})
            except json.JSONDecodeError:
                pass

        stdout, rc = self._run_calicoctl(["get", "globalnetworkpolicy", "-o", "json"])
        if rc == 0 and stdout.strip():
            try:
                data = json.loads(stdout)
                items = data.get("items", [data]) if "items" in data else [data]
                for item in items:
                    policies.append({"kind": "GlobalNetworkPolicy",
                                     "name": item.get("metadata", {}).get("name")})
            except json.JSONDecodeError:
                pass
        return policies

    def find_unprotected_namespaces(self):
        """Identify namespaces without any network policies."""
        if not self.v1 or not self.net_v1:
            return []
        namespaces = [ns.metadata.name for ns in self.v1.list_namespace().items]
        policies = self.net_v1.list_network_policy_for_all_namespaces()
        protected = {p.metadata.namespace for p in policies.items}
        system_ns = {"kube-system", "kube-public", "kube-node-lease", "calico-system"}
        unprotected = [ns for ns in namespaces if ns not in protected and ns not in system_ns]
        for ns in unprotected:
            self.findings.append({"severity": "high", "type": "Unprotected Namespace",
                                  "detail": f"Namespace '{ns}' has no network policies"})
        return unprotected

    def generate_default_deny(self, namespace):
        """Generate default-deny policy manifests for a namespace."""
        ingress = {**DEFAULT_DENY_INGRESS, "metadata": {**DEFAULT_DENY_INGRESS["metadata"],
                                                         "namespace": namespace}}
        egress = {**DEFAULT_DENY_EGRESS, "metadata": {**DEFAULT_DENY_EGRESS["metadata"],
                                                       "namespace": namespace}}
        return {"namespace": namespace, "ingress_policy": ingress, "egress_policy": egress}

    def check_calico_node_status(self):
        """Check Calico node status using calicoctl."""
        stdout, rc = self._run_calicoctl(["node", "status"])
        if rc == 0:
            return {"status": "healthy", "output": stdout[:500]}
        return {"status": "unavailable"}

    def test_connectivity(self, src_pod, dst_pod, namespace, port=80):
        """Test pod-to-pod connectivity using kubectl exec."""
        try:
            result = subprocess.run(
                ["kubectl", "exec", src_pod, "-n", namespace, "--",
                 "wget", "--spider", "--timeout=3", f"http://{dst_pod}:{port}"],
                capture_output=True, text=True, timeout=10,
            )
            return {"src": src_pod, "dst": dst_pod, "port": port,
                    "connected": result.returncode == 0}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"src": src_pod, "dst": dst_pod, "connected": None, "error": "test failed"}

    def generate_report(self):
        k8s_policies = self.list_k8s_network_policies()
        calico_policies = self.list_calico_policies()
        unprotected = self.find_unprotected_namespaces()
        node_status = self.check_calico_node_status()
        deny_manifests = [self.generate_default_deny(ns) for ns in unprotected[:5]]

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "k8s_network_policies": {"count": len(k8s_policies), "policies": k8s_policies},
            "calico_policies": {"count": len(calico_policies), "policies": calico_policies},
            "unprotected_namespaces": unprotected,
            "calico_node_status": node_status,
            "recommended_deny_policies": deny_manifests,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "calico_policy_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Audit and manage Calico network policies on Kubernetes"
    )
    parser.add_argument("--kubeconfig", default=None,
                        help="Path to kubeconfig file")
    parser.add_argument("--output-dir", default="./calico_policy_audit",
                        help="Output directory for report")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    agent = CalicoNetworkPolicyAgent(kubeconfig=args.kubeconfig,
                                     output_dir=args.output_dir)
    agent.generate_report()


if __name__ == "__main__":
    main()
