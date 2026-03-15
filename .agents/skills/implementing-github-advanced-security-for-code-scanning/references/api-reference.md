# API Reference: Implementing GitHub Advanced Security for Code Scanning

## GitHub Code Scanning API

```bash
# List code scanning alerts
gh api /repos/OWNER/REPO/code-scanning/alerts?state=open

# Get specific alert
gh api /repos/OWNER/REPO/code-scanning/alerts/ALERT_NUMBER

# List analyses
gh api /repos/OWNER/REPO/code-scanning/analyses

# Upload SARIF
gh api /repos/OWNER/REPO/code-scanning/sarifs -X POST \
  -f commit_sha=SHA -f ref=refs/heads/main -f sarif=@results.sarif.gz
```

## Secret Scanning API

```bash
# List secret alerts
gh api /repos/OWNER/REPO/secret-scanning/alerts?state=open

# Update alert state
gh api /repos/OWNER/REPO/secret-scanning/alerts/ALERT_NUMBER -X PATCH \
  -f state=resolved -f resolution=revoked
```

## CodeQL Query Suites

| Suite | Description | False Positive Rate |
|-------|-------------|-------------------|
| `default` | High-confidence security | Low |
| `security-extended` | Broader security coverage | Medium |
| `security-and-quality` | Security + code quality | Higher |

## CodeQL Workflow (GitHub Actions)

```yaml
- uses: github/codeql-action/init@v3
  with:
    languages: ${{ matrix.language }}
    queries: +security-extended
- uses: github/codeql-action/autobuild@v3
- uses: github/codeql-action/analyze@v3
```

## Supported Languages

| Language | Build Required | Query Pack |
|----------|---------------|-----------|
| Python | No | codeql/python-queries |
| JavaScript/TypeScript | No | codeql/javascript-queries |
| Java/Kotlin | Yes | codeql/java-queries |
| C/C++ | Yes | codeql/cpp-queries |
| C# | Yes | codeql/csharp-queries |
| Go | Yes | codeql/go-queries |
| Ruby | No | codeql/ruby-queries |
| Swift | Yes | codeql/swift-queries |

### References

- GHAS Docs: https://docs.github.com/en/code-security/code-scanning
- CodeQL: https://codeql.github.com/docs/
- CodeQL Queries: https://github.com/github/codeql
- SARIF Spec: https://sarifweb.azurewebsites.net/
