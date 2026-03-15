# API Reference: Securing GitHub Actions Workflows

## Security Checks

| Check | Risk | Severity |
|-------|------|----------|
| Unpinned actions (mutable tags) | Supply chain attack via tag overwrite | Medium |
| Missing permissions block | Inherits overly broad defaults | Medium |
| write-all permissions | Excessive token scope | High |
| Script injection in run steps | Code execution via PR title/body | High |
| pull_request_target trigger | Fork code runs with base permissions | High |
| Secrets in workflow logs | Credential exposure | Critical |

## Dangerous Expression Contexts

| Context | Risk |
|---------|------|
| `github.event.pull_request.title` | Attacker-controlled PR title |
| `github.event.pull_request.body` | Attacker-controlled PR body |
| `github.event.issue.title` | Attacker-controlled issue title |
| `github.event.comment.body` | Attacker-controlled comment |
| `github.head_ref` | Attacker-controlled branch name |

## SHA Pinning Format

| Format | Security |
|--------|----------|
| `actions/checkout@v4` | Insecure - mutable tag |
| `actions/checkout@b4ffde65f...` | Secure - immutable SHA |

## Permission Scopes

| Scope | Values |
|-------|--------|
| contents | read, write |
| actions | read, write |
| deployments | read, write |
| id-token | write (for OIDC) |
| security-events | write |
| pull-requests | read, write |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `yaml` | PyYAML >=6.0 | Parse workflow YAML |
| `re` | stdlib | Pattern matching |
| `json` | stdlib | Report output |
| `pathlib` | stdlib | File discovery |

## References

- GitHub Actions Security Hardening: https://docs.github.com/en/actions/security-guides
- StepSecurity Harden Runner: https://github.com/step-security/harden-runner
- actionlint: https://github.com/rhysd/actionlint
