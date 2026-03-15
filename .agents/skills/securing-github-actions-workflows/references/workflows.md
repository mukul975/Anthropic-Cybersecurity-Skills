# Workflow Reference: Securing GitHub Actions

## Hardening Checklist

1. Pin all actions to SHA digests
2. Set restrictive default permissions
3. Sanitize all user-controlled inputs
4. Never use pull_request_target with PR checkout
5. Enable environment protection for production
6. Configure CODEOWNERS for workflow files
7. Enable Dependabot for github-actions
8. Audit third-party actions quarterly
9. Use OIDC instead of long-lived cloud credentials
10. Add harden-runner for network monitoring

## Permission Scoping Reference

| Permission | Use Case |
|-----------|----------|
| contents: read | Checkout code |
| contents: write | Create releases, push tags |
| security-events: write | Upload SARIF results |
| packages: write | Push container images |
| deployments: write | Create deployment status |
| id-token: write | OIDC cloud authentication |
| pull-requests: write | Comment on PRs |

## Script Injection Prevention

```yaml
# DANGEROUS patterns to avoid:
run: echo "${{ github.event.issue.title }}"
run: echo "${{ github.event.comment.body }}"
run: echo "${{ github.head_ref }}"

# SAFE alternatives:
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "${TITLE}"
```
