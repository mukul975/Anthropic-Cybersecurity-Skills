# Helm Chart Security Review Checklist

## Chart Metadata
- [ ] Chart.yaml has accurate appVersion and version
- [ ] No deprecated API versions in templates
- [ ] Chart signed with GPG key

## Security Context Defaults
- [ ] runAsNonRoot: true
- [ ] readOnlyRootFilesystem: true
- [ ] allowPrivilegeEscalation: false
- [ ] capabilities.drop: ALL
- [ ] seccompProfile: RuntimeDefault

## Resource Management
- [ ] CPU limits set
- [ ] Memory limits set
- [ ] CPU requests set
- [ ] Memory requests set

## Image Security
- [ ] Image uses digest or pinned tag (not :latest)
- [ ] imagePullPolicy: Always
- [ ] Images from trusted registries only

## Secrets Handling
- [ ] No secrets in values.yaml
- [ ] External secrets integration configured
- [ ] ServiceAccount token auto-mount disabled

## Network
- [ ] NetworkPolicy template included
- [ ] hostNetwork: false
- [ ] hostPID: false
- [ ] hostIPC: false

## RBAC
- [ ] ServiceAccount created per release
- [ ] Minimal RBAC permissions
- [ ] No cluster-admin bindings
