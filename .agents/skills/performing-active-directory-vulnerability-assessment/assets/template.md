# Active Directory Security Assessment Checklist

## Pre-Assessment Preparation
- [ ] Obtain written authorization for AD security assessment
- [ ] Identify domain controllers and AD forest/domain topology
- [ ] Create dedicated scan account with Domain Admin read access
- [ ] Document assessment scope (domains, OUs, forests)
- [ ] Schedule assessment during maintenance window if using active scanning

## PingCastle Assessment
- [ ] Run PingCastle --healthcheck against all in-scope domains
- [ ] Review overall score and category breakdown
- [ ] Document all findings with points >= 10
- [ ] Export report as XML for automated processing
- [ ] Check trust relationship security
- [ ] Verify AdminSDHolder integrity

## BloodHound Assessment
- [ ] Deploy SharpHound collector
- [ ] Run full collection (All methods)
- [ ] Upload data to BloodHound CE
- [ ] Run shortest path to Domain Admin queries
- [ ] Identify Kerberoastable admin accounts
- [ ] Map unconstrained delegation hosts
- [ ] Check for AS-REP roastable accounts
- [ ] Analyze GPO abuse paths
- [ ] Document all attack paths with 3 or fewer hops

## Purple Knight Assessment
- [ ] Run Purple Knight community edition
- [ ] Review score across all five categories
- [ ] Document indicators below 75% score threshold

## Critical Findings Checklist

### Kerberos Security
- [ ] No user accounts with SPNs in admin groups (Kerberoasting)
- [ ] Kerberos pre-authentication enabled for all accounts
- [ ] No unconstrained delegation on non-DC computers
- [ ] AES-256 encryption enabled; RC4 and DES disabled
- [ ] Kerberos ticket lifetime <= 10 hours

### Privileged Accounts
- [ ] Domain Admins group has <= 5 members
- [ ] Enterprise Admins group has <= 3 members
- [ ] Schema Admins group is empty (only populated during schema changes)
- [ ] All admin accounts have password expiration enabled
- [ ] Protected Users group configured for Tier 0 accounts
- [ ] Tiered admin model implemented (Tier 0/1/2)

### Password Policy
- [ ] Minimum password length >= 14 characters
- [ ] Password history >= 24 passwords
- [ ] Account lockout threshold set (10-15 attempts)
- [ ] Fine-grained password policy for admin accounts (25+ chars)

### Infrastructure Security
- [ ] LDAP signing required on all domain controllers
- [ ] LDAP channel binding set to Required
- [ ] SMB signing required on DCs
- [ ] NTLMv2 only (LM and NTLMv1 disabled)
- [ ] All DCs running supported OS versions
- [ ] LAPS deployed for local admin passwords
