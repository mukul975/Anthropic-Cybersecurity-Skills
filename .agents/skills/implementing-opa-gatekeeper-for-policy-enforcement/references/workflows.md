# Workflow - OPA Gatekeeper Policy Enforcement

## Phase 1: Install Gatekeeper

```bash
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set replicas=3 --set audit.replicas=1

kubectl -n gatekeeper-system rollout status deployment/gatekeeper-controller-manager
```

## Phase 2: Deploy ConstraintTemplates

```bash
# Clone Gatekeeper policy library
git clone https://github.com/open-policy-agent/gatekeeper-library.git

# Apply common templates
kubectl apply -f gatekeeper-library/library/pod-security-policy/privileged-containers/template.yaml
kubectl apply -f gatekeeper-library/library/pod-security-policy/host-namespaces/template.yaml
kubectl apply -f gatekeeper-library/library/pod-security-policy/allow-privilege-escalation/template.yaml
kubectl apply -f gatekeeper-library/library/general/allowedrepos/template.yaml
kubectl apply -f gatekeeper-library/library/general/requiredlabels/template.yaml
kubectl apply -f gatekeeper-library/library/general/containerlimits/template.yaml
```

## Phase 3: Deploy Constraints in Dryrun Mode

```bash
kubectl apply -f - <<EOF
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: block-privileged-dryrun
spec:
  enforcementAction: dryrun
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces:
      - kube-system
      - gatekeeper-system
EOF
```

## Phase 4: Review Audit Violations

```bash
# Check violations for each constraint
kubectl get constraints -o json | jq '.items[] | {
  name: .metadata.name,
  enforcement: .spec.enforcementAction,
  violations: (.status.violations // [] | length),
  total_violations: .status.totalViolations
}'

# Get detailed violations
kubectl get k8spsprivilegedcontainer block-privileged-dryrun -o json | jq '.status.violations[]'
```

## Phase 5: Switch to Enforcement

```bash
# After reviewing violations and remediating, switch to deny
kubectl patch k8spsprivilegedcontainer block-privileged-dryrun \
  --type=merge -p '{"spec":{"enforcementAction":"deny"}}'
```

## Phase 6: Test Enforcement

```bash
# This should be denied
kubectl run test-priv --image=nginx --overrides='{"spec":{"containers":[{"name":"test","image":"nginx","securityContext":{"privileged":true}}]}}'
# Expected: Error from server (Forbidden): admission webhook denied the request

kubectl delete pod test-priv --ignore-not-found
```

## Phase 7: Monitor and Maintain

```bash
# Regular audit check
kubectl get constraints -o wide

# Check Gatekeeper health
kubectl get pods -n gatekeeper-system
kubectl logs -n gatekeeper-system -l control-plane=controller-manager --tail=20
```
