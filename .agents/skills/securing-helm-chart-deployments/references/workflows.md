# Workflow - Securing Helm Chart Deployments

## Phase 1: Chart Development Security
1. Set secure defaults in values.yaml (non-root, read-only fs, resource limits)
2. Add network policy templates
3. Use external secrets references
4. Lint with `helm lint --strict`

## Phase 2: CI Pipeline
1. Render templates: `helm template test ./chart -f values.yaml > rendered.yaml`
2. Lint: `helm lint ./chart --strict`
3. Scan: `kube-linter lint rendered.yaml`
4. Scan: `checkov -f rendered.yaml --framework kubernetes`
5. Sign chart: `helm package ./chart --sign`

## Phase 3: Deployment
1. Verify chart signature: `helm verify chart.tgz`
2. Deploy with production values: `helm install release ./chart -f values-prod.yaml`
3. Verify deployment: `helm test release`

## Phase 4: Post-Deployment
1. Validate security contexts: `kubectl get pods -o jsonpath='{.items[*].spec.securityContext}'`
2. Check network policies applied
3. Verify secrets sourced from external store

## Phase 5: Maintenance
1. Update chart versions in lockfile
2. Rescan after dependency updates
3. Rotate signing keys annually
