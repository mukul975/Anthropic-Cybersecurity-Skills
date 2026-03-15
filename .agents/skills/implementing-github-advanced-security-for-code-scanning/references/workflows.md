# GHAS Implementation Workflows

## Workflow 1: Organization-Wide Enablement

```
1. Audit current repository inventory
   - List all repositories in the organization
   - Identify languages and build systems in use
   - Estimate active committer count for licensing
   |
2. Pilot phase (2-4 weeks)
   - Enable GHAS on 5-10 representative repositories
   - Use default setup for initial scanning
   - Collect baseline alert counts and false positive rates
   |
3. Triage pilot results
   - Review alerts by severity (Critical, High, Medium, Low)
   - Dismiss confirmed false positives with documented reasons
   - Create remediation issues for confirmed vulnerabilities
   |
4. Tune configuration
   - Adjust query suites based on false positive feedback
   - Write custom queries for organization-specific patterns
   - Configure alert dismissal policies
   |
5. Broad rollout
   - Enable default setup across remaining repositories
   - Configure organization-level security configurations
   - Set branch protection rules requiring code scanning checks
   |
6. Continuous monitoring
   - Review security overview dashboard weekly
   - Track MTTR for code scanning alerts
   - Report metrics to security leadership monthly
```

## Workflow 2: Pull Request Security Gate

```
Developer pushes code to feature branch
           |
   PR is created targeting main
           |
   CodeQL analysis triggers automatically
           |
   Dependency review checks for vulnerable dependencies
           |
   Secret scanning checks for hardcoded credentials
           |
   Results posted as PR check and inline annotations
           |
   [Pass] All checks pass --> PR is eligible for merge
   [Fail] Critical/High findings --> PR is blocked
           |
   Developer reviews findings and applies fixes
           |
   Re-push triggers re-analysis
           |
   Merge after all checks pass and reviewer approval
```

## Workflow 3: Custom CodeQL Query Development

```
1. Identify recurring vulnerability pattern not caught by default queries
   |
2. Set up CodeQL development environment
   - Install CodeQL CLI
   - Clone CodeQL standard library repository
   - Create workspace with target codebase database
   |
3. Author the query in QL language
   - Define source, sink, and taint-tracking configuration
   - Add metadata (@name, @description, @kind, @problem.severity, @security-severity, @precision, @id, @tags)
   |
4. Test the query
   - Create test cases with expected results
   - Run `codeql test run` against test database
   - Validate precision and recall
   |
5. Package the query
   - Create qlpack.yml with version and dependencies
   - Publish to GitHub Container Registry or internal package registry
   |
6. Deploy to scanning workflow
   - Reference the query pack in codeql-action/init step
   - Monitor results for the new query across repositories
```

## Workflow 4: SARIF Integration with External Tools

```
External SAST/DAST tool runs scan
           |
   Tool outputs results in SARIF 2.1.0 format
           |
   GitHub Actions uploads SARIF via codeql-action/upload-sarif
           |
   Results appear in Security tab alongside CodeQL findings
           |
   Unified triage workflow across all scanning tools
           |
   Alert deduplication based on location and rule ID
```
