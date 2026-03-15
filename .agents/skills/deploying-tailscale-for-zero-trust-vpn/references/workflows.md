# Workflows: Deploying Tailscale for Zero Trust VPN

## Workflow 1: Initial Tailnet Deployment

```
Step 1: Plan Network Architecture
  - Identify all devices and services requiring connectivity
  - Map existing network topology and access requirements
  - Define user groups and access policies
  - Plan subnet routing for legacy network integration
  - Determine exit node placement for internet routing

Step 2: Configure Identity Provider
  - Enable SSO with organizational identity provider
  - Configure MFA enforcement policies
  - Map identity provider groups to Tailscale groups
  - Set key expiry policy (recommended: 90 days)

Step 3: Deploy Tailscale Nodes
  - Install on critical infrastructure first (servers, databases)
  - Deploy to user endpoints (laptops, mobile devices)
  - Configure subnet routers for non-Tailscale networks
  - Set up exit nodes for secure internet access
  - Enable MagicDNS for hostname resolution

Step 4: Configure ACLs
  - Start with deny-all baseline
  - Define groups matching organizational structure
  - Create tag-based policies for infrastructure
  - Test ACLs in audit mode before enforcement
  - Document all ACL rules and their business justification

Step 5: Validate and Monitor
  - Test connectivity between all required paths
  - Verify ACL enforcement blocks unauthorized access
  - Enable audit logging
  - Configure alerts for connection anomalies
```

## Workflow 2: ACL Policy Development

```
Step 1: Inventory Access Requirements
  - List all user roles and their resource needs
  - Map application dependencies (service-to-service)
  - Identify privileged access paths
  - Document temporary/exception access needs

Step 2: Design Policy Structure
  - Define groups (users, teams, roles)
  - Define tags (environments, service types, sensitivity)
  - Map access rules: group/tag -> destination:ports
  - Plan SSH access policies with session recording

Step 3: Implement and Test
  - Write ACL JSON configuration
  - Deploy in test/staging tailnet first
  - Validate each rule with test connections
  - Verify deny rules block unauthorized access
  - Review with security team before production deployment

Step 4: Maintain and Audit
  - Review ACLs quarterly for stale rules
  - Audit access logs for policy violations
  - Update groups when team membership changes
  - Remove deprecated rules and tags
```

## Workflow 3: Headscale Self-Hosted Deployment

```
Step 1: Prepare Infrastructure
  - Provision server with public IP and domain
  - Configure TLS certificate (Let's Encrypt)
  - Set up PostgreSQL or SQLite database
  - Configure firewall rules (port 443, DERP relay ports)

Step 2: Install and Configure Headscale
  - Download latest Headscale binary
  - Generate configuration file
  - Configure OIDC provider integration
  - Set up DNS records for coordination server
  - Configure DERP relay servers

Step 3: Onboard Users and Devices
  - Create users/namespaces in Headscale
  - Generate pre-auth keys for automated deployment
  - Connect client devices to Headscale server
  - Configure ACLs via Headscale policy file

Step 4: Operational Maintenance
  - Monitor Headscale server health
  - Rotate pre-auth keys regularly
  - Backup database and configuration
  - Update Headscale and client versions
  - Review and rotate DERP relay configuration
```
