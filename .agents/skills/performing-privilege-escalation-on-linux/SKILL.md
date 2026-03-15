---
name: performing-privilege-escalation-on-linux
description: Linux privilege escalation involves elevating from a low-privilege user account to root access on a compromised system. Red teams exploit misconfigurations, vulnerable services, kernel exploits, and w
domain: cybersecurity
subdomain: red-teaming
tags: [red-team, adversary-simulation, mitre-attack, exploitation, post-exploitation, privilege-escalation, linux]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Privilege Escalation on Linux

## Overview

Linux privilege escalation involves elevating from a low-privilege user account to root access on a compromised system. Red teams exploit misconfigurations, vulnerable services, kernel exploits, and weak permissions to achieve root. This skill covers both manual enumeration techniques and automated tools for identifying and exploiting privilege escalation vectors.

## MITRE ATT&CK Mapping

- **T1548.001** - Abuse Elevation Control Mechanism: Setuid and Setgid
- **T1548.003** - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1068** - Exploitation for Privilege Escalation
- **T1574.006** - Hijack Execution Flow: Dynamic Linker Hijacking
- **T1053.003** - Scheduled Task/Job: Cron
- **T1543.002** - Create or Modify System Process: Systemd Service

## Key Escalation Vectors

### SUID/SGID Binaries
- Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
- Check GTFOBins for exploitation methods
- Custom SUID binaries may have vulnerabilities

### Sudo Misconfigurations
- `sudo -l` to list allowed commands
- Wildcards in sudo rules allow injection
- NOPASSWD entries for dangerous commands
- sudo versions vulnerable to CVE-2021-3156 (Baron Samedit)

### Kernel Exploits
- Dirty Cow (CVE-2016-5195) for older kernels
- Dirty Pipe (CVE-2022-0847) for kernel 5.8+
- PwnKit (CVE-2021-4034) for pkexec
- GameOver(lay) (CVE-2023-2640, CVE-2023-32629) for Ubuntu

### Cron Job Abuse
- World-writable cron scripts
- PATH hijacking in cron jobs
- Wildcard injection in cron commands

### Capabilities
- `getcap -r / 2>/dev/null` to find binaries with capabilities
- cap_setuid allows UID manipulation
- cap_dac_override bypasses file permissions

### Writable Service Files
- Systemd unit files with weak permissions
- Init scripts writable by non-root users
- Socket files in accessible locations

## Tools and Resources

| Tool | Purpose |
|------|---------|
| LinPEAS | Automated privilege escalation enumeration |
| LinEnum | Linux enumeration script |
| linux-exploit-suggester | Kernel exploit matching |
| pspy | Process monitoring without root |
| GTFOBins | SUID/sudo binary exploitation reference |
| PEASS-ng | Privilege escalation awesome scripts suite |

## Validation Criteria

- [ ] Enumeration performed using automated tools
- [ ] Privilege escalation vector identified
- [ ] Root access achieved through identified vector
- [ ] Evidence documented (screenshots, command output)
- [ ] Alternative escalation paths identified
