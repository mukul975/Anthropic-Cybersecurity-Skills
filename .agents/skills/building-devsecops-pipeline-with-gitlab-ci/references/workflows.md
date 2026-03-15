# GitLab DevSecOps Pipeline Workflows

## Workflow 1: Merge Request Security Review

```
Developer creates merge request
           |
   Pipeline triggers security scanners in parallel:
   [SAST] [Secret Detection] [Dependency Scanning] [License Scanning]
           |
   MR Security Widget displays results:
   - New vulnerabilities introduced
   - Existing vulnerabilities fixed
   - Comparison with target branch
           |
   [No Critical/High] --> Reviewers can approve and merge
   [Critical/High found] --> MR blocked by approval policy
           |
   Security team reviews findings
           |
   [Confirmed] --> Developer remediates and re-pushes
   [False Positive] --> Dismissed with documented reason
           |
   All findings resolved --> MR eligible for merge
```

## Workflow 2: Container Image Security Gate

```
Docker image built in CI
           |
   Container scanning (Trivy) analyzes image layers
           |
   Findings categorized by severity
           |
   [Below threshold] --> Image pushed to registry with metadata
   [Above threshold] --> Pipeline fails, image not pushed
           |
   Registry stores scan results as artifact
           |
   Deployment pulls only scanned/approved images
```

## Workflow 3: DAST Against Staging Environment

```
Application deployed to staging
           |
   DAST browser scan initiated against staging URL
           |
   Authenticated scan crawls application pages
           |
   Active testing for XSS, SQLi, CSRF, etc.
           |
   Results added to vulnerability report
           |
   [Pass] --> Manual deploy-to-production gate enabled
   [Fail on critical] --> Staging deployment rolled back
           |
   Production deploy requires manual approval
```

## Workflow 4: Vulnerability Lifecycle Management

```
Scanner detects vulnerability
           |
   Status: "Detected" in vulnerability report
           |
   Security analyst triages finding
           |
   [Confirmed vulnerability]        [False positive]
           |                              |
   Status: "Confirmed"              Status: "Dismissed"
   Issue created automatically      Reason documented
           |
   Developer assigned fix
           |
   Fix merged, scanner re-runs
           |
   Vulnerability no longer detected
           |
   Status: "Resolved"
```
