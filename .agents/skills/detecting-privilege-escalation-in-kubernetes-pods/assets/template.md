# Privilege Escalation Detection Checklist

## Prevention Controls
- [ ] Pod Security Admission set to restricted on production namespaces
- [ ] OPA Gatekeeper constraints block privileged containers
- [ ] Default security context enforced via mutation webhook
- [ ] Dangerous capabilities blocked at admission

## Detection Controls
- [ ] Falco rules deployed for privilege escalation patterns
- [ ] Kubernetes audit logging enabled
- [ ] Alerts configured for CRITICAL findings
- [ ] Regular cluster scans scheduled

## Dangerous Configurations to Block

| Configuration | Risk Level | PSA Profile |
|--------------|------------|-------------|
| privileged: true | CRITICAL | Baseline blocks |
| hostPID: true | CRITICAL | Baseline blocks |
| hostNetwork: true | HIGH | Baseline blocks |
| allowPrivilegeEscalation: true | HIGH | Restricted blocks |
| runAsUser: 0 | HIGH | Restricted blocks |
| capabilities.add: SYS_ADMIN | CRITICAL | Restricted blocks |
| hostPath volumes | HIGH | Restricted blocks |
| automountServiceAccountToken: true | MEDIUM | Manual |
