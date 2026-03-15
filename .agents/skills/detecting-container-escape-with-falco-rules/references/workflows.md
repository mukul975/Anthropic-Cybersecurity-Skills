# Workflow - Detecting Container Escape with Falco Rules

## Phase 1: Deploy Falco

### Install on Kubernetes
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set collectors.containerd.enabled=true

kubectl -n falco rollout status daemonset/falco --timeout=120s
```

### Verify Deployment
```bash
kubectl get pods -n falco -o wide
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=10
```

## Phase 2: Deploy Custom Escape Detection Rules

### Create ConfigMap with Custom Rules
```bash
kubectl create configmap falco-escape-rules -n falco \
  --from-file=container-escape.yaml=/path/to/container-escape.yaml

# Restart Falco to load new rules
kubectl rollout restart daemonset/falco -n falco
```

### Validate Rules Loaded
```bash
kubectl exec -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}') -- \
  falco --list | grep -i escape
```

## Phase 3: Test Detection

### Test 1 - Privileged Container
```bash
kubectl run escape-test-priv --image=alpine --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"test","image":"alpine","command":["sleep","30"],"securityContext":{"privileged":true}}]}}'

# Check alert
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5 | grep -i privileged
kubectl delete pod escape-test-priv
```

### Test 2 - Sensitive File Access
```bash
kubectl run escape-test-shadow --image=alpine --restart=Never -- cat /etc/shadow
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5 | grep -i shadow
kubectl delete pod escape-test-shadow
```

### Test 3 - Shell Spawn
```bash
kubectl exec -it deploy/some-app -- /bin/sh
# In Falco logs, should see "Terminal shell in container"
```

## Phase 4: Integrate Alerting

### Configure Falcosidekick Outputs
```yaml
# values-sidekick.yaml
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    minimumpriority: "warning"
  elasticsearch:
    hostport: "https://elasticsearch:9200"
    index: "falco"
    minimumpriority: "notice"
  prometheus:
    enabled: true
```

```bash
helm upgrade falco falcosecurity/falco -n falco \
  -f values-sidekick.yaml
```

## Phase 5: Tune and Maintain

### Handle False Positives
```yaml
# Add exceptions to rules
- rule: Terminal shell in container
  append: true
  exceptions:
    - name: known_shell_spawners
      fields: [container.image.repository]
      comps: [in]
      values:
        - [my-debug-image, kubectl-debug]
```

### Regular Maintenance
1. Update Falco rules weekly: `falcoctl artifact install falco-rules`
2. Review new maturity_stable rules after each Falco release
3. Correlate Falco alerts with Kubernetes audit logs
4. Run escape simulation exercises monthly
