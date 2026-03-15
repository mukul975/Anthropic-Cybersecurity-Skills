# Workflows - AD Vulnerability Assessment

## Workflow 1: Comprehensive AD Security Assessment

### Steps
1. Run PingCastle health check to get overall AD security score
2. Review PingCastle report for stale objects, privilege issues, trust problems, and anomalies
3. Run SharpHound data collection against the domain
4. Upload SharpHound data to BloodHound CE
5. Execute critical BloodHound queries (shortest path to DA, Kerberoastable admins, delegation issues)
6. Run Purple Knight for additional security indicator checks
7. Consolidate findings from all three tools into unified report
8. Prioritize findings by risk severity and attack path impact
9. Generate remediation plan with specific PowerShell/GPO fix commands

## Workflow 2: Attack Path Remediation

### Steps
1. Identify top 5 shortest attack paths to Domain Admin from BloodHound
2. For each path, determine the weakest link (misconfigured ACL, session reuse, etc.)
3. Remediate weakest links to break attack paths
4. Re-run BloodHound collection to verify paths are eliminated
5. Document remediated paths and remaining risk

## Workflow 3: Privileged Account Hardening

### Steps
1. Export all members of privileged groups from PingCastle report
2. Validate each account has legitimate business need for privilege
3. Remove unnecessary privileged group memberships
4. Implement tiered administration model (Tier 0/1/2)
5. Enable Protected Users group for sensitive accounts
6. Configure AdminSDHolder with correct ACLs
7. Verify changes with follow-up PingCastle scan

## Workflow 4: Kerberos Security Hardening

### Steps
1. Identify all Kerberoastable accounts from BloodHound
2. Convert user-assigned SPNs to Managed Service Accounts (MSA/gMSA) where possible
3. For remaining SPNs, ensure 25+ character passwords with rotation
4. Disable DES and RC4 encryption for Kerberos
5. Enable AES-256 encryption for all accounts
6. Enable Kerberos pre-authentication for all accounts
7. Configure constrained delegation to replace unconstrained delegation
