# Code Signing Templates

## GitHub Actions: Build, Sign, and Release

```yaml
name: Signed Release
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: make build-all
      - uses: sigstore/cosign-installer@v3
      - name: Sign artifacts
        run: |
          for f in dist/*.tar.gz; do
            cosign sign-blob "$f" --output-signature "${f}.sig" --output-certificate "${f}.cert" --yes
          done
          sha256sum dist/*.tar.gz > dist/checksums.sha256
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

## Verification Script

```bash
#!/bin/bash
set -euo pipefail
# verify-release.sh <artifact> <signature> <certificate>
ARTIFACT="$1"
SIGNATURE="$2"
CERTIFICATE="$3"

echo "Verifying: $ARTIFACT"
sha256sum "$ARTIFACT"

cosign verify-blob "$ARTIFACT" \
  --signature "$SIGNATURE" \
  --certificate "$CERTIFICATE" \
  --certificate-identity "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

echo "Verification: PASSED"
```
