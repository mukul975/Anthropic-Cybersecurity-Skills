---
name: analyzing-linux-audit-logs-for-intrusion
description: 'Uses the Linux Audit framework (auditd) with ausearch and aureport utilities
  to detect intrusion attempts, unauthorized access, privilege escalation, and suspicious
  system activity. Covers audit rule configuration, log querying, timeline reconstruction,
  and integration with SIEM platforms. Activates for requests involving auditd analysis,
  Linux audit log investigation, ausearch queries, aureport summaries, or host-based
  intrusion detection on Linux.

  '
domain: cybersecurity
subdomain: incident-response
tags:
- auditd
- ausearch
- aureport
- linux-security
- intrusion-detection
- HIDS
- forensics
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
mitre_attack:
- T1059.004
- T1070
- T1548.003
- T1543.002
---

# Analyzing Linux Audit Logs for Intrusion

## When to Use

- Investigating suspected unauthorized access or privilege escalation on Linux hosts
- Hunting for evidence of exploitation, backdoor installation, or persistence mechanisms
- Auditing compliance with security baselines (CIS, STIG, PCI-DSS) that require system call monitoring
- Reconstructing a timeline of attacker actions during incident response
- Detecting file tampering on critical system files such as `/etc/passwd`, `/etc/shadow`, or SSH keys

**Do not use** for network-level intrusion detection; use Suricata or Zeek for network traffic analysis. Auditd operates at the kernel level on individual hosts.

## Prerequisites

- Linux system with `auditd` package installed and the audit daemon running (`systemctl status auditd`)
- Root or sudo access to configure audit rules and query logs
- Audit rules deployed via `/etc/audit/rules.d/*.rules` or loaded with `auditctl`
- Recommended: Neo23x0/auditd ruleset from GitHub for comprehensive baseline coverage
- Familiarity with Linux syscalls (`execve`, `open`, `connect`, `ptrace`, etc.)
- Log storage with sufficient retention (default location: `/var/log/audit/audit.log`)

## Workflow

### Step 1: Verify Audit Daemon Status and Configuration

Confirm the audit system is running and check the current rule set:

```bash
# Check auditd service status
systemctl status auditd

# Show current audit rules loaded in the kernel
auditctl -l

# Show audit daemon configuration
cat /etc/audit/auditd.conf | grep -E "log_file|max_log_file|num_logs|space_left_action"

# Check if the audit backlog is being exceeded (dropped events)
auditctl -s
```

If the backlog limit is being reached, increase it:

```bash
auditctl -b 8192
```

### Step 2: Deploy Intrusion-Focused Audit Rules

Add rules that target common intrusion indicators. Place these in `/etc/audit/rules.d/intrusion.rules`:

```bash
# Monitor credential files for unauthorized reads or modifications
-w /etc/passwd -p wa -k credential_access
-w /etc/shadow -p rwa -k credential_access
-w /etc/gshadow -p rwa -k credential_access
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# Monitor SSH configuration and authorized keys
-w /etc/ssh/sshd_config -p wa -k sshd_config_change
-w /root/.ssh/authorized_keys -p wa -k ssh_key_tampering

# Monitor user and group management commands
-w /usr/sbin/useradd -p x -k user_management
-w /usr/sbin/usermod -p x -k user_management
-w /usr/sbin/groupadd -p x -k user_management

# Detect process injection via ptrace
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k process_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k process_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k process_injection

# Monitor execution of programs from unusual directories
-a always,exit -F arch=b64 -S execve -F exe=/tmp -k exec_from_tmp
-a always,exit -F arch=b64 -S execve -F exe=/dev/shm -k exec_from_shm

# Detect kernel module loading (rootkit installation)
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_remove
-w /sbin/insmod -p x -k kernel_module_tool
-w /sbin/modprobe -p x -k kernel_module_tool

# Monitor network socket creation for reverse shells
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_created
-a always,exit -F arch=b64 -S connect -F a0=2 -k network_connection

# Detect cron job modifications (persistence)
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence

# Monitor log deletion or tampering
-w /var/log/ -p wa -k log_tampering
```

Reload rules after editing:

```bash
augenrules --load
auditctl -l | wc -l   # Confirm rule count
```

### Step 3: Search for Intrusion Indicators with ausearch

Use `ausearch` to query the audit log for specific events:

```bash
# Search for all failed login attempts in the last 24 hours
ausearch -m USER_LOGIN --success no -ts recent

# Search for commands executed by a specific user
ausearch -ua 1001 -m EXECVE -ts today

# Search for all file access events on /etc/shadow
ausearch -f /etc/shadow -ts this-week

# Search for privilege escalation via sudo
ausearch -m USER_CMD -ts today

# Search for kernel module loading events
ausearch -k kernel_module_load -ts this-month

# Search for processes executed from /tmp (common attack staging)
ausearch -k exec_from_tmp -ts this-week

# Search for SSH key modifications
ausearch -k ssh_key_tampering -ts this-month

# Search for a specific event by audit event ID
ausearch -a 12345

# Search events in a specific time range
ausearch -ts 03/15/2026 08:00:00 -te 03/15/2026 18:00:00

# Interpret syscall numbers and format output readably
ausearch -k credential_access -i -ts today
```

### Step 4: Generate Summary Reports with aureport

Use `aureport` to produce aggregate summaries for triage:

```bash
# Summary of all authentication events
aureport -au -ts this-week --summary

# Report of all failed events (login, access, etc.)
aureport --failed --summary -ts today

# Report of executable runs
aureport -x --summary -ts today

# Report of all anomaly events (segfaults, promiscuous mode, etc.)
aureport --anomaly -ts this-week

# Report of file access events
aureport -f --summary -ts today

# Report of all events by key (maps to your custom rule keys)
aureport -k --summary -ts this-month

# Report of all system calls
aureport -s --summary -ts today

# Report of events grouped by user
aureport -u --summary -ts this-week

# Detailed time-based event report for timeline building
aureport -ts 03/15/2026 08:00:00 -te 03/15/2026 18:00:00 --summary
```

### Step 5: Reconstruct the Attack Timeline

Combine ausearch queries to build a chronological narrative:

```bash
# Step 5a: Identify the initial access timestamp
ausearch -m USER_LOGIN -ua 0 --success yes -ts this-week -i | head -50

# Step 5b: Trace what the attacker did after gaining access
# Get all events from the compromised account within the incident window
ausearch -ua <UID> -ts "03/15/2026 14:00:00" -te "03/15/2026 18:00:00" -i \
  | aureport -f -i

# Step 5c: Extract all commands executed during the incident window
ausearch -m EXECVE -ts "03/15/2026 14:00:00" -te "03/15/2026 18:00:00" -i

# Step 5d: Check for persistence mechanisms installed
ausearch -k cron_persistence -ts "03/15/2026 14:00:00" -i
ausearch -k ssh_key_tampering -ts "03/15/2026 14:00:00" -i

# Step 5e: Check for lateral movement (outbound connections)
ausearch -k network_connection -ts "03/15/2026 14:00:00" -i
```

### Step 6: Forward Audit Logs to SIEM

Configure `audisp-remote` or `auditbeat` to ship logs to a central SIEM for correlation:

```bash
# Option A: Using audisp-remote plugin
# Edit /etc/audit/plugins.d/au-remote.conf
active = yes
direction = out
path = /sbin/audisp-remote
type = always

# Configure remote target in /etc/audit/audisp-remote.conf
remote_server = siem.internal.corp
port = 6514
transport = tcp

# Option B: Using Elastic Auditbeat
# Install auditbeat and configure /etc/auditbeat/auditbeat.yml
# Auditbeat reads directly from the kernel audit framework
```

## Key Concepts

| Term | Definition |
|------|------------|
| **auditd** | The Linux Audit daemon that receives audit events from the kernel and writes them to `/var/log/audit/audit.log` |
| **auditctl** | Command-line utility to control the audit system: add/remove rules, check status, set backlog size |
| **ausearch** | Query tool that searches audit logs by message type, user, file, key, time range, or event ID |
| **aureport** | Reporting tool that generates aggregate summaries of audit events for triage and compliance |
| **audit rule key (-k)** | A user-defined label attached to an audit rule, enabling fast filtering of related events with ausearch and aureport |
| **syscall auditing** | Kernel-level monitoring of system calls (execve, open, connect, ptrace) that captures process and file activity |
| **augenrules** | Utility that merges all files in `/etc/audit/rules.d/` into `/etc/audit/audit.rules` and loads them into the kernel |

## Verification

- [ ] auditd is running and rules are loaded (`auditctl -l` returns expected rule count)
- [ ] No audit backlog overflow (`auditctl -s` shows `backlog: 0` or low value, lost: 0)
- [ ] ausearch returns events for each custom key (`ausearch -k <key> -ts today` returns results)
- [ ] aureport generates non-empty summaries for authentication, executable, and file events
- [ ] Timeline reconstruction produces a coherent chronological sequence of attacker actions
- [ ] Critical file watches trigger alerts on test modifications (`touch /etc/shadow` generates an event)
- [ ] Logs are forwarding to central SIEM (verify with a test event and confirm receipt)
- [ ] Audit rules persist across reboot (rules in `/etc/audit/rules.d/`, not only via `auditctl`)
