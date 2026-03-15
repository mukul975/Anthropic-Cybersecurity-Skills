# Workflows - Kubernetes Penetration Testing

## Workflow 1: External Kubernetes Pentest

```
[Scope Definition] --> [Reconnaissance] --> [Service Discovery]
        |                     |                    |
        v                     v                    v
  Define targets        DNS, OSINT,          nmap 6443,8443
  Rules of engagement   cloud metadata       10250,2379,30000+
        |                     |                    |
        +---------------------+--------------------+
                              |
                              v
                    [Automated Scanning]
                    kube-hunter --remote
                    kubescape scan
                    kube-bench (if access)
                              |
                    +---------+---------+
                    |                   |
                    v                   v
            [API Server Tests]   [Kubelet Tests]
            Anonymous auth       Unauthenticated access
            RBAC enumeration     Command execution
            Token theft          Pod listing
                    |                   |
                    +-------------------+
                              |
                              v
                    [Exploitation]
                    Deploy privileged pod
                    Extract secrets
                    Pivot to other namespaces
                              |
                              v
                    [Report and Remediate]
```

## Workflow 2: Internal/Assumed-Breach Testing

```
Step 1: Initial Pod Access
  - Deploy test pod in target namespace
  - Collect service account token
  - Enumerate permissions: kubectl auth can-i --list

Step 2: Internal Reconnaissance
  - List namespaces, pods, services
  - Discover internal services via DNS
  - Check metadata endpoints (cloud IMDS)
  - Identify NetworkPolicy gaps

Step 3: Privilege Escalation
  - Check for wildcard RBAC roles
  - Test service account token from other pods
  - Attempt to create privileged pods
  - Check for vulnerable admission controllers

Step 4: Lateral Movement
  - Access services in other namespaces
  - Extract secrets and configmaps
  - Attempt container escape
  - Access cloud provider metadata

Step 5: Impact Assessment
  - Demonstrate data access (secrets, PVCs)
  - Show cluster-wide compromise path
  - Document attack chain
```

## Workflow 3: Pentest Cleanup

```
[Testing Complete]
        |
        v
[Remove all pentest pods]
kubectl delete pods -l purpose=pentest -A
        |
        v
[Remove test RBAC resources]
kubectl delete rolebinding pentest-rb
kubectl delete serviceaccount pentest-sa
        |
        v
[Verify cleanup]
kubectl get all -l purpose=pentest -A
        |
        v
[Document findings and hand off report]
```
