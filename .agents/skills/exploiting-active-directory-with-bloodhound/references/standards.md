# Standards and Framework References

## MITRE ATT&CK - Discovery (TA0007)

| Technique ID | Name | BloodHound Relevance |
|-------------|------|---------------------|
| T1087.002 | Account Discovery: Domain Account | Enumerates all domain users |
| T1069.001 | Permission Groups Discovery: Local Groups | Local admin group membership |
| T1069.002 | Permission Groups Discovery: Domain Groups | Domain group membership |
| T1482 | Domain Trust Discovery | Trust relationships between domains |
| T1615 | Group Policy Discovery | GPO enumeration and analysis |
| T1018 | Remote System Discovery | Computer object enumeration |
| T1033 | System Owner/User Discovery | Session data collection |
| T1016 | System Network Configuration Discovery | Network topology mapping |

## MITRE ATT&CK - Privilege Escalation Paths

| Technique ID | Name | BloodHound Attack Path |
|-------------|------|----------------------|
| T1134.001 | Access Token Manipulation | Token impersonation via session data |
| T1078.002 | Valid Accounts: Domain Accounts | Credential reuse paths |
| T1484.001 | Domain Policy Modification: Group Policy | GPO abuse for code execution |
| T1558.003 | Kerberoasting | SPN accounts to crack |
| T1558.004 | AS-REP Roasting | No pre-auth accounts |

## Active Directory ACL Abuse Paths

| ACL Right | Abuse Method | Impact |
|-----------|-------------|--------|
| GenericAll | Full control over object - reset password, modify group membership | High |
| GenericWrite | Modify object attributes - set SPN for Kerberoasting | High |
| WriteOwner | Take ownership of object, then modify DACL | High |
| WriteDACL | Modify permissions on object | High |
| ForceChangePassword | Reset user password without knowing current | High |
| AddMember | Add users to groups | Medium-High |
| ReadLAPSPassword | Read local admin passwords | High |
| ReadGMSAPassword | Read managed service account passwords | High |
| AllExtendedRights | DCSync rights, LAPS read | Critical |

## BloodHound Edge Types

| Edge | Description | Attack Potential |
|------|-------------|-----------------|
| MemberOf | Group membership | Inherited permissions |
| HasSession | Active user session on computer | Credential theft |
| AdminTo | Local admin rights | Lateral movement |
| CanRDP | RDP access rights | Remote access |
| CanPSRemote | PowerShell remoting rights | Remote code execution |
| ExecuteDCOM | DCOM execution rights | Remote execution |
| Contains | OU/GPO container relationship | GPO targeting |
| GPLink | GPO linked to OU | Policy enforcement path |
| Owns | Object ownership | Full control potential |
| AZMemberOf | Azure AD group membership | Cloud attack path |
| AZGlobalAdmin | Azure AD Global Admin | Cloud full control |

## NIST SP 800-171 - Active Directory Security

### 3.1 Access Control
- Limit information system access to authorized users
- Employ the principle of least privilege
- Control the flow of CUI per approved authorizations

### 3.5 Identification and Authentication
- Authenticate organizational users and devices
- Use multi-factor authentication
- Employ replay-resistant authentication mechanisms

## CIS Benchmark for Active Directory

### Account Configuration
- Ensure 'Account lockout threshold' is set to 5 or fewer attempts
- Ensure 'Minimum password length' is set to 14 or more characters
- Ensure Kerberos service accounts use AES encryption

### Group Policy Configuration
- Restrict access to Group Policy modification
- Audit Group Policy changes
- Limit GPO link permissions
