# Workflows - Authenticated Scanning with OpenVAS

## Workflow 1: Initial Authenticated Scan Setup

### Steps
1. **Install and initialize GVM**
   - Install GVM packages or deploy Docker containers
   - Run `gvm-setup` to initialize database and create admin account
   - Verify all services with `gvm-check-setup`

2. **Synchronize vulnerability feeds**
   - Run `greenbone-feed-sync` for NVT, SCAP, and CERT data
   - Wait for initial sync to complete (15-30 minutes)
   - Verify feed status in GSA dashboard

3. **Create scan credentials**
   - Create SSH key pair for Linux scanning: `ssh-keygen -t ed25519 -f scan_key`
   - Deploy public key to target hosts: `ssh-copy-id -i scan_key.pub scan_user@target`
   - Create Windows service account with local admin rights for SMB scanning
   - Import credentials into GVM via GSA or gvm-cli

4. **Define scan targets**
   - Group hosts by OS type and credential type
   - Assign appropriate credentials to each target group
   - Configure alive test method (ICMP + TCP-ACK recommended)

5. **Select scan configuration**
   - Use "Full and fast" for production environments
   - Use "Full and deep" for pre-production/staging
   - Clone and customize for specific compliance requirements

6. **Execute initial scan**
   - Create scan task linking target, config, and schedule
   - Run scan during maintenance window for first execution
   - Monitor progress through GSA dashboard

7. **Validate authentication success**
   - Check report for authentication NVT results
   - Verify SSH/SMB login success indicators
   - Compare finding count against unauthenticated baseline

## Workflow 2: Recurring Authenticated Scan

### Trigger
Weekly schedule (Sunday 2:00 AM UTC).

### Steps
1. GVM automatically starts scheduled scan task
2. Scanner performs alive detection on all target hosts
3. For each responding host:
   - Authenticate using stored credentials
   - Run all applicable NVT checks
   - Collect installed package lists, registry keys, configurations
4. Results stored in PostgreSQL database
5. Compare against previous scan for delta analysis
6. Generate report in XML/CSV/PDF format
7. Export results to vulnerability management platform (DefectDojo, Jira)

## Workflow 3: Scan Result Export Pipeline

### Steps
1. Scan completes and report is generated
2. Python script fetches report via GMP protocol
3. Parse XML results and extract:
   - CVE identifiers
   - CVSS scores
   - Affected hosts and ports
   - NVT descriptions and remediation guidance
4. Transform into standardized format
5. Upload to DefectDojo via reimport API
6. Create Jira tickets for Critical/High findings
7. Update vulnerability SLA tracking database

## Workflow 4: Credential Rotation

### Trigger
Monthly or upon security policy requirement.

### Steps
1. Generate new SSH key pair or update service account password
2. Deploy new credentials to target hosts via configuration management (Ansible, Puppet)
3. Update credential objects in GVM
4. Run validation scan on subset of targets
5. Verify authentication success in validation report
6. If successful, update production scan tasks
7. Revoke old credentials from target hosts
