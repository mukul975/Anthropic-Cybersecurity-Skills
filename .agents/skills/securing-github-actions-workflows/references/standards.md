# Standards Reference: Securing GitHub Actions

## NIST SSDF (SP 800-218)

### PS.1: Protect All Forms of Code
- Workflows are code and must be reviewed and protected
- Pin action dependencies to SHA digests
- Minimize GITHUB_TOKEN permissions

## CIS Software Supply Chain Security

- BD-1: Define security requirements for build processes
- BD-2: Automate security validation of build configurations
- BD-3: Pin all external dependencies to immutable references

## OWASP CI/CD Top 10 Risks

| Risk | GitHub Actions Mitigation |
|------|--------------------------|
| CICD-SEC-1: Insufficient Flow Control | Environment protection rules, CODEOWNERS |
| CICD-SEC-3: Dependency Chain Abuse | SHA pinning of actions |
| CICD-SEC-4: Poisoned Pipeline Execution | Restrict pull_request_target, input sanitization |
| CICD-SEC-6: Credential Hygiene | OIDC federation, minimal GITHUB_TOKEN scope |
| CICD-SEC-9: Artifact Integrity | Sign artifacts in workflows |

## SLSA Framework

- Level 2: Hosted build service (GitHub Actions qualifies)
- Level 3: Hardened build platform with isolation guarantees
- Workflow hardening prevents provenance falsification
