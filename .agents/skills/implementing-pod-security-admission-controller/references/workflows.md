# Workflow - Implementing Pod Security Admission

## Phase 1: Assessment
1. List all namespaces and their current security posture
2. Run dry-run against restricted profile for each namespace
3. Document violations and required exemptions

## Phase 2: Apply Audit Mode
```bash
for ns in production staging; do
  kubectl label namespace $ns \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted
done
```

## Phase 3: Fix Violations
1. Update Deployments/StatefulSets with compliant security contexts
2. Add seccomp profiles
3. Switch containers to non-root
4. Drop ALL capabilities

## Phase 4: Enable Enforcement
```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.28
```

## Phase 5: Set Cluster Defaults
1. Create AdmissionConfiguration with baseline defaults
2. Apply to kube-apiserver
3. Exempt system namespaces

## Phase 6: Monitor
1. Watch for FailedCreate events
2. Review audit logs weekly
3. Update exemptions as needed
