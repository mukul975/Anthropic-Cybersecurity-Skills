# API Reference: Securing Helm Chart Deployments

## Helm Security Commands

| Command | Description |
|---------|-------------|
| `helm lint ./chart --strict` | Lint chart with strict mode |
| `helm template release ./chart` | Render templates locally |
| `helm verify chart.tgz` | Verify chart signature |
| `helm package ./chart --sign --key <key>` | Package and sign |
| `helm pull repo/chart --verify` | Pull with verification |

## Security Context Fields

| Field | Recommended | Description |
|-------|------------|-------------|
| `runAsNonRoot` | true | Prevent root execution |
| `readOnlyRootFilesystem` | true | Immutable filesystem |
| `allowPrivilegeEscalation` | false | Block privilege escalation |
| `capabilities.drop` | [ALL] | Drop all Linux capabilities |
| `seccompProfile.type` | RuntimeDefault | Syscall filtering |

## Security Checks

| Check | Severity | Risk |
|-------|----------|------|
| Privileged container | High | Full host access |
| hostNetwork enabled | High | Network namespace escape |
| hostPID enabled | High | Process namespace escape |
| :latest image tag | Medium | Non-reproducible builds |
| Missing resource limits | Medium | Resource exhaustion DoS |
| Missing readOnlyRootFilesystem | Medium | Writable filesystem |

## Template Scanning Tools

| Tool | Command |
|------|---------|
| kubesec | `kubesec scan rendered.yaml` |
| checkov | `checkov -f rendered.yaml --framework kubernetes` |
| trivy | `trivy config rendered.yaml` |
| kube-linter | `kube-linter lint rendered.yaml` |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute helm/kubesec CLI |
| `re` | stdlib | Pattern matching in rendered YAML |
| `yaml` | PyYAML >=6.0 | Parse YAML content |
| `json` | stdlib | Report generation |

## References

- Helm Security: https://helm.sh/docs/topics/provenance/
- Helm Secrets Plugin: https://github.com/jkroepke/helm-secrets
- Kubesec: https://kubesec.io/
