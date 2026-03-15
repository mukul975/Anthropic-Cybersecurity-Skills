# Workflows - Kubesec Manifest Scanning

## Scanning Workflow

### Pre-Commit Scanning
1. Developer writes Kubernetes manifest locally
2. Pre-commit hook runs `kubesec scan` on changed YAML files
3. If score < 0 (critical issues), commit is blocked with remediation guidance
4. Developer fixes issues and retries commit

### CI/CD Pipeline Integration
1. Pull request created with manifest changes
2. CI job runs kubesec scan on all manifests in PR
3. Results posted as PR comment with score breakdown
4. Gate: PR blocked if any manifest scores below threshold
5. Merge allowed only after all manifests pass minimum score

### Admission Control
1. Developer applies manifest via kubectl or GitOps
2. ValidatingWebhook intercepts the API request
3. Kubesec webhook scans the manifest in real-time
4. If critical issues found, admission is denied with explanation
5. Clean manifests are admitted to the cluster

## Remediation Workflow

### Scoring Improvement Process
```
1. Run kubesec scan on target manifest
2. Review "advise" section for point-earning improvements
3. Review "critical" section for must-fix issues
4. Apply fixes in priority order:
   a. Remove critical issues (privileged, hostPID, hostNetwork)
   b. Add seccomp profile (+4 points)
   c. Add AppArmor annotation (+3 points)
   d. Set readOnlyRootFilesystem (+1 point)
   e. Set runAsNonRoot (+1 point)
   f. Add resource limits (+1 point each)
5. Re-scan to verify improved score
6. Commit and push hardened manifest
```

## Continuous Monitoring Workflow

### Scheduled Cluster Scanning
1. CronJob runs daily scan of all deployed resources
2. Extracts manifests from live cluster: `kubectl get deploy -o yaml`
3. Runs kubesec scan on each resource
4. Compares scores against previous scan results
5. Alerts on score regressions or new critical findings
6. Generates weekly security posture report

### Score Trending
```
Week 1: Average score 2.3  (baseline)
Week 2: Average score 3.1  (+0.8 improvement)
Week 3: Average score 4.5  (+1.4 improvement)
Week 4: Average score 5.2  (+0.7 improvement -- target: 6.0)
```
