---
name: building-devsecops-pipeline-with-gitlab-ci
description: Design and implement a comprehensive DevSecOps pipeline in GitLab CI/CD integrating SAST, DAST, container scanning, dependency scanning, and secret detection.
domain: cybersecurity
subdomain: devsecops
tags: [gitlab-ci, devsecops, sast, dast, container-scanning, dependency-scanning, secret-detection, cicd-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Building DevSecOps Pipeline with GitLab CI

## Overview

GitLab provides an integrated DevSecOps platform that embeds security testing directly into the CI/CD pipeline. By leveraging GitLab's built-in security scanners---SAST, DAST, container scanning, dependency scanning, secret detection, and license compliance---teams can shift security left, catching vulnerabilities during development rather than post-deployment. GitLab Duo AI assists with false positive detection for SAST vulnerabilities, helping security teams focus on genuine issues.

## Prerequisites

- GitLab Ultimate license (required for full security scanner suite)
- GitLab Runner configured (shared or self-hosted)
- `.gitlab-ci.yml` pipeline configuration familiarity
- Docker-in-Docker (DinD) or Kaniko for container builds
- Application deployed to a staging environment for DAST scanning

## Core Security Scanning Stages

### Static Application Security Testing (SAST)

SAST analyzes source code for vulnerabilities before compilation. GitLab supports 14+ languages using analyzers such as Semgrep, SpotBugs, Gosec, Bandit, and NodeJsScan. The simplest inclusion uses GitLab's managed templates.

### Dynamic Application Security Testing (DAST)

DAST tests running applications by simulating attack payloads against HTTP endpoints. It detects XSS, SQLi, CSRF, and other runtime vulnerabilities that static analysis cannot find. DAST requires a deployed, accessible target URL.

### Container Scanning

Uses Trivy to scan Docker images for known CVEs in OS packages and application dependencies. Runs after the Docker build stage to gate images before they reach a registry.

### Dependency Scanning

Inspects dependency manifests (package.json, requirements.txt, pom.xml, Gemfile.lock) for known vulnerable versions. Operates at the source code level, complementing container scanning.

### Secret Detection

Scans commits for accidentally committed credentials, API keys, tokens, and private keys using pattern matching and entropy analysis. Runs on every commit to prevent secrets from reaching the repository.

## Implementation

### Complete Pipeline Configuration

```yaml
# .gitlab-ci.yml

stages:
  - build
  - test
  - security
  - deploy-staging
  - dast
  - deploy-production

variables:
  DOCKER_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  SECURE_LOG_LEVEL: "info"

# Include GitLab managed security templates
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml
  - template: DAST.gitlab-ci.yml
  - template: Security/License-Scanning.gitlab-ci.yml

build:
  stage: build
  image: docker:24.0
  services:
    - docker:24.0-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $DOCKER_IMAGE .
    - docker push $DOCKER_IMAGE
  rules:
    - if: $CI_COMMIT_BRANCH

unit-tests:
  stage: test
  image: $DOCKER_IMAGE
  script:
    - npm ci
    - npm run test:coverage
  coverage: '/Lines\s*:\s*(\d+\.?\d*)%/'
  artifacts:
    reports:
      junit: junit-report.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

# Override SAST to run in security stage
sast:
  stage: security
  variables:
    SAST_EXCLUDED_PATHS: "spec,test,tests,tmp,node_modules"
    SEARCH_MAX_DEPTH: 10

# Override container scanning
container_scanning:
  stage: security
  variables:
    CS_IMAGE: $DOCKER_IMAGE
    CS_SEVERITY_THRESHOLD: "HIGH"

# Override dependency scanning
dependency_scanning:
  stage: security

# Override secret detection
secret_detection:
  stage: security

# License compliance scanning
license_scanning:
  stage: security

deploy-staging:
  stage: deploy-staging
  image: bitnami/kubectl:latest
  script:
    - kubectl set image deployment/app app=$DOCKER_IMAGE -n staging
    - kubectl rollout status deployment/app -n staging --timeout=300s
  environment:
    name: staging
    url: https://staging.example.com
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

# DAST runs against deployed staging
dast:
  stage: dast
  variables:
    DAST_WEBSITE: https://staging.example.com
    DAST_FULL_SCAN_ENABLED: "true"
    DAST_BROWSER_SCAN: "true"
  needs:
    - deploy-staging
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

deploy-production:
  stage: deploy-production
  image: bitnami/kubectl:latest
  script:
    - kubectl set image deployment/app app=$DOCKER_IMAGE -n production
    - kubectl rollout status deployment/app -n production --timeout=300s
  environment:
    name: production
    url: https://app.example.com
  when: manual
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Security Approval Policies

Configure scan execution policies to enforce mandatory security scans:

1. Navigate to Security & Compliance > Policies
2. Create a "Scan Execution Policy" requiring SAST and secret detection on all branches
3. Create a "Merge Request Approval Policy" requiring security team approval when critical vulnerabilities are detected

### Custom SAST Ruleset Configuration

Create `.gitlab/sast-ruleset.toml` to customize analyzer behavior:

```toml
[semgrep]
  [[semgrep.ruleset]]
    dirs = ["src"]

  [[semgrep.passthrough]]
    type = "url"
    target = "/sgrep-rules/custom-rules.yml"
    value = "https://semgrep.dev/p/owasp-top-ten"

  [[semgrep.passthrough]]
    type = "url"
    target = "/sgrep-rules/java-rules.yml"
    value = "https://semgrep.dev/p/java"
```

## Security Dashboard and Vulnerability Management

### Vulnerability Report

GitLab consolidates all scanner findings into a single Vulnerability Report accessible at Security & Compliance > Vulnerability Report. Each vulnerability includes:
- Severity rating (Critical, High, Medium, Low, Info)
- Scanner source (SAST, DAST, Container, Dependency, Secret)
- Location in source code or image layer
- Remediation guidance and suggested fixes
- Status tracking (Detected, Confirmed, Dismissed, Resolved)

### Merge Request Security Widget

Every merge request displays a security scanning widget showing:
- New vulnerabilities introduced by the MR
- Fixed vulnerabilities resolved by the MR
- Comparison against the target branch baseline

## Pipeline Optimization

- **Parallel execution**: Security scanners run concurrently in the security stage
- **Caching**: Use CI cache for dependency downloads to speed up scanning
- **Incremental scanning**: SAST can scan only changed files using `SAST_INCREMENTAL: "true"`
- **Fail conditions**: Set `allow_failure: false` on critical scanners to enforce quality gates

## Monitoring and Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| Pipeline security coverage | Percentage of projects with all scanners enabled | > 95% |
| Critical vulnerability MTTR | Time from detection to resolution for critical findings | < 48 hours |
| False positive rate | Percentage of dismissed-as-false-positive findings | < 15% |
| Secret detection block rate | Percentage of secret commits blocked by push rules | > 99% |

## References

- [GitLab Security Scanning Documentation](https://docs.gitlab.com/ee/user/application_security/)
- [GitLab SAST Analyzers](https://docs.gitlab.com/ee/user/application_security/sast/)
- [GitLab DAST Configuration](https://docs.gitlab.com/ee/user/application_security/dast/)
- [GitLab Security Policies](https://docs.gitlab.com/ee/user/application_security/policies/)
- [GitLab Vulnerability Management](https://docs.gitlab.com/ee/user/application_security/vulnerability_report/)
