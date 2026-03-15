---
name: securing-kubernetes-on-cloud
description: >
  This skill covers hardening managed Kubernetes clusters on EKS, AKS, and GKE by
  implementing Pod Security Standards, network policies, workload identity, RBAC
  scoping, image admission controls, and runtime security monitoring. It addresses
  cloud-specific security features including IRSA for EKS, Workload Identity for
  GKE, and Managed Identities for AKS.
domain: cybersecurity
subdomain: cloud-security
tags: [kubernetes-security, eks, aks, gke, pod-security-standards, container-runtime]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Securing Kubernetes on Cloud

## When to Use

- When deploying new managed Kubernetes clusters in production with security requirements
- When hardening existing EKS, AKS, or GKE clusters after a security audit or pentest finding
- When implementing workload identity to eliminate static cloud credentials in pods
- When enforcing pod security policies across namespaces to prevent container escapes
- When integrating runtime security monitoring for detecting container-level threats

**Do not use** for non-Kubernetes container deployments like ECS Fargate or Azure Container Instances, for application-level security within containers (see securing-serverless-functions), or for CI/CD pipeline security (see implementing-cloud-devsecops).

## Prerequisites

- Managed Kubernetes cluster provisioned on EKS, AKS, or GKE with admin access
- kubectl configured with cluster admin credentials
- Familiarity with Kubernetes RBAC, namespaces, and security contexts
- Container network interface plugin supporting network policies (Calico, Cilium)

## Workflow

### Step 1: Enforce Pod Security Standards

Apply Pod Security Admission labels at the namespace level to enforce the Restricted profile in production namespaces. Pod Security Policies were removed in Kubernetes v1.25 and replaced with Pod Security Admission.

```yaml
# Production namespace with restricted Pod Security Standard
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
---
# Staging namespace with baseline enforcement
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

```yaml
# Pod spec compliant with restricted profile
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
  namespace: production
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: company/app:v2.1@sha256:abc123...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
```

### Step 2: Configure Cloud-Native Workload Identity

Eliminate static cloud credentials in pods by binding Kubernetes service accounts to cloud IAM roles.

```bash
# EKS: IAM Roles for Service Accounts (IRSA)
eksctl create iamserviceaccount \
  --cluster production-cluster \
  --namespace production \
  --name web-app-sa \
  --attach-policy-arn arn:aws:iam::123456789012:policy/WebAppS3ReadOnly \
  --approve

# GKE: Workload Identity
gcloud iam service-accounts create web-app-sa \
  --project=my-gcp-project

gcloud iam service-accounts add-iam-policy-binding \
  web-app-sa@my-gcp-project.iam.gserviceaccount.com \
  --role roles/storage.objectViewer \
  --member "serviceAccount:my-gcp-project.svc.id.goog[production/web-app-sa]"

kubectl annotate serviceaccount web-app-sa \
  --namespace production \
  iam.gke.io/gcp-service-account=web-app-sa@my-gcp-project.iam.gserviceaccount.com

# AKS: Azure AD Workload Identity
az identity create --name web-app-identity --resource-group production-rg
az identity federated-credential create \
  --name web-app-federation \
  --identity-name web-app-identity \
  --resource-group production-rg \
  --issuer "$(az aks show -n production-cluster -g production-rg --query oidcIssuerProfile.issuerUrl -o tsv)" \
  --subject system:serviceaccount:production:web-app-sa
```

### Step 3: Implement Network Policies

Deploy network policies to restrict pod-to-pod communication following the principle of least privilege. By default, Kubernetes allows all pods to communicate with each other.

```yaml
# Default deny all ingress and egress in production namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# Allow web-app to receive traffic from ingress controller only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-web
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
---
# Allow web-app to connect to database only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-web-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### Step 4: Configure RBAC with Least Privilege

Scope Kubernetes RBAC roles to specific namespaces and resources. Avoid ClusterRoleBindings for non-administrative users.

```yaml
# Developer role scoped to specific namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer-role
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "update", "patch"]
  # Explicitly deny secrets access
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: staging
subjects:
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

### Step 5: Deploy Image Admission Controls

Use admission controllers to enforce that only signed images from trusted registries are deployed. Implement OPA/Gatekeeper or Kyverno for policy enforcement.

```yaml
# Kyverno policy: require images from approved registries
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Images must come from approved registries"
        pattern:
          spec:
            containers:
              - image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/* | gcr.io/my-gcp-project/*"
---
# Kyverno policy: require image digest (no mutable tags)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-digest
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-digest
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "Images must use digest references, not tags"
        pattern:
          spec:
            containers:
              - image: "*@sha256:*"
```

### Step 6: Enable Runtime Security Monitoring

Deploy runtime security tools to detect anomalous behavior inside containers including process execution, file system modifications, and network connections.

```bash
# Deploy Falco for runtime threat detection
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system --create-namespace \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/xxx"

# Run kube-bench for CIS Kubernetes Benchmark assessment
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml
kubectl logs -l app=kube-bench
```

## Key Concepts

| Term | Definition |
|------|------------|
| Pod Security Standards | Three profiles (Privileged, Baseline, Restricted) enforced via Pod Security Admission that control pod security context capabilities |
| Workload Identity | Cloud-native mechanism binding Kubernetes service accounts to cloud IAM roles for credential-free cloud API access (IRSA, GKE WI, AKS MI) |
| Network Policy | Kubernetes resource defining allowed ingress and egress traffic flows between pods, enforced by the CNI plugin |
| Admission Controller | Kubernetes plugin that intercepts API requests before persistence to validate or mutate resources against security policies |
| RBAC | Role-Based Access Control in Kubernetes, defining what actions (verbs) identities can perform on which resources in which namespaces |
| Seccomp Profile | Linux kernel feature restricting the system calls a container process can make, reducing the kernel attack surface |
| Service Mesh | Infrastructure layer (Istio, Linkerd) providing mutual TLS, traffic policies, and observability for service-to-service communication |

## Tools & Systems

- **Falco**: Open-source runtime security engine detecting anomalous behavior in containers using kernel-level system call monitoring
- **Kyverno**: Kubernetes-native policy engine for admission control, mutation, and generation of resources based on security policies
- **kube-bench**: CIS Kubernetes Benchmark assessment tool checking cluster configuration against security best practices
- **Trivy**: Vulnerability scanner for container images, file systems, and Kubernetes resources with SBOM generation
- **Calico/Cilium**: CNI plugins providing network policy enforcement and advanced network security features including eBPF-based monitoring

## Common Scenarios

### Scenario: Cryptominer Deployed via Compromised Container Image

**Context**: GuardDuty Extended Threat Detection generates an AttackSequence:EKS/CompromisedCluster finding. A developer pulled a public Docker image containing an embedded XMRig cryptominer that executes at container startup.

**Approach**:
1. Isolate the affected pod by applying a deny-all network policy targeting its labels
2. Capture the container image digest and scan it with Trivy to identify the embedded binary
3. Review Kubernetes audit logs to identify who deployed the compromised image and when
4. Deploy Kyverno ClusterPolicy requiring images from approved private registries only
5. Enable image digest pinning to prevent tag mutation attacks
6. Deploy Falco with rules detecting crypto mining process signatures (/usr/bin/xmrig, stratum+tcp connections)

**Pitfalls**: Deleting the pod before capturing the image digest and audit logs destroys forensic evidence. Blocking only the specific image tag allows the attacker to re-push with a different tag.

## Output Format

```
Kubernetes Security Assessment Report
=======================================
Cluster: production-cluster (EKS 1.29)
Provider: AWS (us-east-1)
Assessment Date: 2025-02-23
Tool: kube-bench v0.8.0 + manual review

CIS KUBERNETES BENCHMARK RESULTS:
  Total Controls: 124
  Passed: 98 (79%)
  Failed: 18 (15%)
  Warnings: 8 (6%)

CRITICAL FINDINGS:
  [K8S-001] 3 namespaces lack Pod Security Standards enforcement
    Namespaces: monitoring, logging, default
    Remediation: Apply restricted PSA labels

  [K8S-002] Default service account tokens auto-mounted in 12 deployments
    Risk: Credential theft if container is compromised
    Remediation: Set automountServiceAccountToken: false

  [K8S-003] No network policies in production namespace
    Risk: Unrestricted lateral movement between all pods
    Remediation: Deploy default-deny policy with explicit allow rules

HIGH FINDINGS:
  [K8S-004] 5 pods running as root with privileged security context
  [K8S-005] Images deployed using mutable tags (:latest) in 8 deployments
  [K8S-006] RBAC ClusterRoleBinding grants cluster-admin to developers group
```
