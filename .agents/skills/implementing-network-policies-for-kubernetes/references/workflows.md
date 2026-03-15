# Workflows - Kubernetes Network Policies

## Workflow 1: Network Policy Deployment
```
[Identify communication paths] --> [Create default-deny] --> [Add allow rules per service]
         |                                |                           |
         v                                v                           v
  Map pod-to-pod traffic         Apply to all namespaces    Test with connectivity checks
  Document required flows        Verify DNS still works     Monitor for broken connections
```

## Workflow 2: Progressive Enforcement
```
Step 1: Deploy in audit mode (Calico: log-only)
Step 2: Monitor traffic patterns for 1 week
Step 3: Create policies matching observed traffic
Step 4: Apply default-deny in non-production
Step 5: Validate application functionality
Step 6: Roll out to production namespaces
```
