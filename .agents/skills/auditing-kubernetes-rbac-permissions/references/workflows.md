# Workflows - RBAC Auditing

## Workflow 1: Comprehensive RBAC Audit

```
[Export all RBAC] --> [Identify cluster-admin bindings] --> [Check wildcard permissions]
       |                       |                                    |
       v                       v                                    v
  kubectl get all      Flag non-system                    Flag * verbs, * resources
  RBAC resources       cluster-admin users                Find excessive permissions
       |                       |                                    |
       +----------+------------+------------------------------------+
                  |
                  v
       [Check service account permissions]
                  |
                  v
       [Identify privilege escalation paths]
                  |
                  v
       [Generate remediation report]
```

## Workflow 2: Least Privilege Implementation

```
Step 1: Inventory current permissions per team/service
Step 2: Document actual required operations
Step 3: Create minimal Role/ClusterRole
Step 4: Test with auth can-i dry-run
Step 5: Apply new bindings
Step 6: Remove overly permissive bindings
Step 7: Validate with automated audit
```

## Workflow 3: Continuous RBAC Monitoring

```yaml
# CronJob for weekly RBAC audit
apiVersion: batch/v1
kind: CronJob
metadata:
  name: rbac-audit
spec:
  schedule: "0 2 * * 1"  # Weekly Monday 2am
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: audit
            image: bitnami/kubectl:latest
            command:
            - /bin/sh
            - -c
            - |
              kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name' > /audit/cluster-admin-bindings.txt
              kubectl get clusterroles -o json | jq '.items[] | select(.rules[]? | (.verbs | index("*")) and (.resources | index("*"))) | .metadata.name' > /audit/wildcard-roles.txt
          restartPolicy: Never
```
