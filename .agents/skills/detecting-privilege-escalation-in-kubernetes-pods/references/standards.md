# Standards - Detecting Privilege Escalation in Kubernetes Pods

## MITRE ATT&CK for Containers

| Technique | ID | Description |
|-----------|-----|-------------|
| Escape to Host | T1611 | Container breakout via privilege escalation |
| Exploitation for Privilege Escalation | T1068 | Kernel exploit from container |
| Abuse Elevation Control | T1548 | Setuid/setgid binary exploitation |
| Valid Accounts | T1078 | Service account token theft |
| Create Account | T1136 | Modify /etc/passwd in container |

## CIS Kubernetes Benchmark v1.8
- 5.2.1-5.2.9: Pod Security Standards
- 5.7.3: Apply security context to pods

## NIST SP 800-190
- Section 4.3: Container runtime vulnerabilities
- Section 5.4: Runtime monitoring for privilege escalation

## Pod Security Standards

| Profile | Level | Key Restrictions |
|---------|-------|-----------------|
| Privileged | Unrestricted | No restrictions |
| Baseline | Minimally restrictive | No privileged, no hostPID/hostNetwork |
| Restricted | Heavily restricted | Non-root, drop all caps, no privilege escalation |
