# Workflow - Kubernetes CIS Benchmark with kube-bench

## Phase 1: Initial Assessment

```bash
# Deploy kube-bench as Job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl wait --for=condition=complete job/kube-bench --timeout=300s
kubectl logs job/kube-bench > baseline-report.txt
kubectl delete job kube-bench
```

## Phase 2: Analyze Results

```bash
# Count results by status
PASS=$(grep -c "\[PASS\]" baseline-report.txt)
FAIL=$(grep -c "\[FAIL\]" baseline-report.txt)
WARN=$(grep -c "\[WARN\]" baseline-report.txt)
echo "PASS: $PASS | FAIL: $FAIL | WARN: $WARN"

# Extract failed checks with remediation
grep -A 2 "\[FAIL\]" baseline-report.txt
```

## Phase 3: Remediate Failures

### Priority order:
1. Control plane authentication (Section 1.2)
2. etcd security (Section 2)
3. Worker node kubelet (Section 4)
4. RBAC and policies (Section 5)

### Apply each remediation, then re-run affected section:
```bash
kube-bench run --targets master --check 1.2.1
```

## Phase 4: Continuous Monitoring

```yaml
# kube-bench-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kube-bench-scan
  namespace: security
spec:
  schedule: "0 6 * * 1"
  jobTemplate:
    spec:
      template:
        spec:
          hostPID: true
          containers:
          - name: kube-bench
            image: aquasec/kube-bench:v0.7.3
            command: ["kube-bench", "run", "--json"]
            volumeMounts:
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
          volumes:
          - name: var-lib-kubelet
            hostPath:
              path: /var/lib/kubelet
          - name: etc-kubernetes
            hostPath:
              path: /etc/kubernetes
          restartPolicy: Never
```

## Phase 5: Track Improvement

Compare PASS/FAIL/WARN counts across scans to measure security posture improvement over time.
