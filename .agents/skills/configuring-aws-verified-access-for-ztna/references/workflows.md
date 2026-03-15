# Workflows: AWS Verified Access ZTNA Configuration

## Workflow 1: Initial Setup

```
Step 1: Create Verified Access Instance
  - Deploy instance in target AWS region
  - Tag with environment and ownership information

Step 2: Configure Trust Providers
  - Set up identity trust provider (IAM Identity Center or OIDC)
  - Set up device trust provider (CrowdStrike, Jamf, JumpCloud)
  - Attach both providers to the Verified Access instance

Step 3: Create Access Groups
  - Define groups based on application tiers or teams
  - Write group-level Cedar policies
  - Set baseline identity and device requirements

Step 4: Create Endpoints
  - Map each application to a Verified Access endpoint
  - Configure ALB or ENI attachment
  - Set application domain and certificate
  - Write endpoint-specific Cedar policies

Step 5: Configure DNS and Certificates
  - Create ACM certificate for application domain
  - Configure Route 53 CNAME to endpoint domain
  - Validate certificate and DNS resolution
```

## Workflow 2: Cedar Policy Development

```
Step 1: Define Access Requirements
  - Map user groups to application access needs
  - Define device compliance requirements
  - Identify time-based or context-based restrictions

Step 2: Write and Test Policies
  - Start with permit policies for known good access
  - Add forbid policies for explicit denials
  - Test with various identity and device contexts
  - Validate in non-production environment

Step 3: Deploy Policies
  - Apply group-level policies first
  - Add endpoint-specific policies for sensitive apps
  - Monitor access logs for false denials
  - Iterate based on user feedback

Step 4: Ongoing Maintenance
  - Review policies quarterly
  - Update device trust thresholds
  - Add new groups as teams change
  - Remove deprecated application endpoints
```

## Workflow 3: Multi-Account Deployment

```
Step 1: Design Architecture
  - Deploy Verified Access in dedicated networking account
  - Plan group sharing via AWS RAM
  - Define organizational unit boundaries

Step 2: Share Resources
  - Create RAM resource shares
  - Associate Verified Access groups
  - Share with target OUs or accounts

Step 3: Create Endpoints in Workload Accounts
  - Accept RAM shares in workload accounts
  - Create endpoints using shared groups
  - Configure application-specific settings

Step 4: Centralized Monitoring
  - Aggregate access logs to central S3 bucket
  - Configure cross-account CloudWatch dashboards
  - Set up centralized alerting for policy violations
```
