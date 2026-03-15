# Workflow - Detecting Privilege Escalation in Kubernetes Pods

## Phase 1: Assess Current State
```bash
# Find privileged pods
kubectl get pods -A -o json | jq '[.items[] | select(.spec.containers[].securityContext.privileged==true) | {name:.metadata.name, ns:.metadata.namespace}]'

# Find pods running as root
kubectl get pods -A -o json | jq '[.items[] | select(.spec.securityContext.runAsUser==0 or .spec.containers[].securityContext.runAsUser==0) | {name:.metadata.name, ns:.metadata.namespace}]'

# Find hostPath mounts
kubectl get pods -A -o json | jq '[.items[] | select(.spec.volumes[]?.hostPath!=null) | {name:.metadata.name, ns:.metadata.namespace}]'
```

## Phase 2: Deploy Prevention
1. Apply Pod Security Admission labels to namespaces
2. Deploy OPA Gatekeeper constraints
3. Test with non-compliant pods (should be rejected)

## Phase 3: Deploy Detection
1. Install Falco with privilege escalation rules
2. Enable Kubernetes audit logging
3. Configure alerts to SIEM

## Phase 4: Respond to Alerts
1. Identify compromised pod
2. Check container security context
3. Review process list and capabilities
4. Isolate with network policy
5. Capture forensic data
6. Delete compromised pod
