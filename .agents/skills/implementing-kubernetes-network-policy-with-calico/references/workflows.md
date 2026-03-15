# Workflow - Implementing Kubernetes Network Policy with Calico

## Phase 1: Discovery and Planning

### Map Application Communication Flows
```bash
# Identify all namespaces
kubectl get namespaces

# List all services per namespace
kubectl get svc --all-namespaces -o wide

# Identify pod labels
kubectl get pods --all-namespaces --show-labels

# Check existing network policies
kubectl get networkpolicy --all-namespaces
```

### Document Required Traffic Flows
Create a traffic matrix documenting:
- Source pod/namespace -> Destination pod/namespace
- Protocol and port
- Business justification

## Phase 2: Install and Verify Calico

```bash
# Install Tigera operator
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/tigera-operator.yaml

# Wait for operator
kubectl wait --for=condition=Available deployment/tigera-operator -n tigera-operator --timeout=120s

# Install Calico custom resources
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml

# Verify all Calico pods are running
kubectl get pods -n calico-system -w

# Install calicoctl as a pod
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calicoctl.yaml

# Verify node status
kubectl exec -n calico-system calicoctl -- calicoctl node status
```

## Phase 3: Apply Default Deny Policies

### Step 1 - Create DNS Allow Policy First
```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to: []
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
EOF
```

### Step 2 - Apply Default Deny Ingress
```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
EOF
```

### Step 3 - Apply Default Deny Egress
```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
EOF
```

### Step 4 - Apply Allow Rules per Traffic Flow
```bash
# Allow frontend to backend
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
EOF
```

## Phase 4: Validate Policies

### Connectivity Testing
```bash
# Test allowed path (should succeed)
kubectl exec -n production deploy/frontend -- wget -qO- --timeout=5 http://backend-svc:8080/health

# Test blocked path (should timeout/fail)
kubectl exec -n production deploy/frontend -- wget -qO- --timeout=5 http://database-svc:5432

# Test cross-namespace (should fail if denied)
kubectl exec -n staging deploy/test -- wget -qO- --timeout=5 http://backend-svc.production:8080/health
```

### Monitor Denied Connections
```bash
# Check Calico logs for denied connections
kubectl logs -n calico-system -l k8s-app=calico-node --tail=50 | grep -i deny

# Enable flow logs (Calico Enterprise)
kubectl exec -n calico-system calicoctl -- calicoctl get felixconfiguration default -o yaml
```

## Phase 5: Advanced Calico Policies

### Apply Global Security Baseline
```bash
kubectl exec -n calico-system calicoctl -- calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security-baseline
spec:
  order: 100
  types:
    - Ingress
    - Egress
  egress:
    - action: Allow
      protocol: UDP
      destination:
        ports:
          - 53
    - action: Allow
      protocol: TCP
      destination:
        ports:
          - 53
  ingress:
    - action: Allow
      source:
        selector: "projectcalico.org/namespace in {'kube-system', 'monitoring'}"
EOF
```

## Phase 6: Ongoing Operations

### Regular Policy Audits
1. Review traffic flow matrix monthly
2. Validate policies match documented flows
3. Remove stale policies for decommissioned services
4. Update policies when new services are deployed

### Incident Response
1. If suspicious traffic detected, apply emergency deny policy
2. Analyze Calico flow logs for investigation
3. Identify compromised pod via workload endpoint
4. Isolate pod by applying targeted deny policy
