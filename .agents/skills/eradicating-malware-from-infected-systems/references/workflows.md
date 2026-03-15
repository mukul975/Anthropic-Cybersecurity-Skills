# Malware Eradication - Detailed Workflow

## Pre-Eradication Checklist
- [ ] Forensic images collected from all compromised systems
- [ ] All IOCs identified and documented
- [ ] All persistence mechanisms mapped
- [ ] Root cause (initial access vector) identified
- [ ] Containment verified and holding
- [ ] Eradication plan approved by Incident Commander
- [ ] Rollback plan prepared in case eradication fails

## Eradication Phases

### Phase 1: Artifact Inventory
1. Compile list of all malware files with paths and hashes
2. Map all persistence mechanisms per system
3. List all compromised accounts (user, service, admin)
4. Identify all backdoor access methods
5. Document network-level indicators (C2 IPs, domains)
6. Note any configuration changes made by attacker

### Phase 2: Coordinated Removal
Execute removal across ALL compromised systems simultaneously to prevent attacker from detecting cleanup on one system and acting on another.

**Simultaneous Actions:**
1. Remove malware files from all systems
2. Delete persistence mechanisms (registry, tasks, services, WMI)
3. Disable compromised accounts
4. Block all C2 infrastructure at network level
5. Remove unauthorized SSH keys and certificates
6. Clean up web shells from all web servers

### Phase 3: Credential Reset
**Priority Order:**
1. KRBTGT password (reset twice, 12+ hours apart)
2. Domain admin accounts
3. Service accounts
4. All accounts that logged into compromised systems
5. Application credentials and API keys
6. Machine account passwords (if targeted)

### Phase 4: Vulnerability Remediation
1. Patch the vulnerability used for initial access
2. Patch any additional vulnerabilities discovered during investigation
3. Harden configurations that were exploited
4. Update security tool signatures and rules
5. Close unnecessary ports and services

### Phase 5: Validation
1. Full AV/EDR scan on all previously compromised systems
2. YARA scan for specific malware family artifacts
3. Check all persistence locations are clean
4. Verify no unauthorized processes running
5. Confirm no unauthorized network connections
6. Validate all credentials were successfully rotated
7. Test that patches are properly applied

## Decision: Clean vs. Re-Image

### When to Clean (In-Place Remediation)
- Limited number of artifacts
- Well-understood malware family
- No rootkit or bootkit components
- Time pressure requires faster recovery
- System configuration is complex to rebuild

### When to Re-Image (Full Rebuild)
- Rootkit or bootkit detected
- Kernel-level compromise
- Domain controller compromise
- Inability to confirm complete eradication
- Simpler to rebuild than to clean
- Legal requirements demand clean systems

## Common Persistence Locations Reference

### Windows
```
Registry:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
  HKLM\SYSTEM\CurrentControlSet\Services
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options

Filesystem:
  %AppData%\Microsoft\Windows\Start Menu\Programs\Startup
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
  C:\Windows\System32\Tasks\
  C:\Windows\System32\drivers\

WMI:
  root\Subscription\__EventFilter
  root\Subscription\CommandLineEventConsumer
  root\Subscription\__FilterToConsumerBinding
```

### Linux
```
Cron:
  /etc/crontab
  /etc/cron.d/*
  /etc/cron.daily/*
  /var/spool/cron/crontabs/*

Services:
  /etc/systemd/system/*.service
  /etc/init.d/*
  /etc/rc.local

Shell:
  ~/.bashrc, ~/.profile, ~/.bash_profile
  /etc/profile.d/*
  /etc/environment

SSH:
  ~/.ssh/authorized_keys
  /etc/ssh/sshd_config

Other:
  /etc/ld.so.preload
  Kernel modules: /lib/modules/
```
