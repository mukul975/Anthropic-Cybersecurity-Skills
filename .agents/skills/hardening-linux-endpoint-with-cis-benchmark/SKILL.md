---
name: hardening-linux-endpoint-with-cis-benchmark
description: >
  Hardens Linux endpoints using CIS Benchmark recommendations for Ubuntu, RHEL, and CentOS
  to reduce attack surface, enforce security baselines, and meet compliance requirements. Use
  when deploying new Linux servers, remediating audit findings, or establishing security
  baselines for Linux infrastructure. Activates for requests involving Linux hardening, CIS
  benchmarks for Linux, server security baselines, or Linux configuration compliance.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, hardening, linux-security, CIS-benchmark, Ubuntu, RHEL]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Hardening Linux Endpoint with CIS Benchmark

## When to Use

Use this skill when:
- Hardening Linux servers (Ubuntu, RHEL, CentOS, Debian) against CIS benchmarks
- Automating Linux security baselines using Ansible, OpenSCAP, or shell scripts
- Meeting compliance requirements (PCI DSS, HIPAA, SOC 2) for Linux endpoints
- Remediating findings from vulnerability scans or security audits

**Do not use** for Windows hardening (use hardening-windows-endpoint-with-cis-benchmark).

## Prerequisites

- Root or sudo access on target Linux endpoints
- CIS Benchmark PDF for target distribution (from cisecurity.org)
- OpenSCAP or CIS-CAT for automated assessment
- Ansible for enterprise-scale remediation (optional)

## Workflow

### Step 1: Filesystem Configuration (Section 1)

```bash
# 1.1.1 Disable unused filesystems
cat >> /etc/modprobe.d/CIS.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

# 1.1.2 Ensure /tmp is a separate partition with nodev,nosuid,noexec
# /etc/fstab entry:
# tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0
systemctl unmask tmp.mount
systemctl enable tmp.mount

# 1.1.8 Ensure nodev option on /dev/shm
mount -o remount,nodev,nosuid,noexec /dev/shm
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab

# 1.4 Secure boot settings
chown root:root /boot/grub/grub.cfg
chmod 600 /boot/grub/grub.cfg
# Set GRUB password
grub-mkpasswd-pbkdf2  # Generate hash, add to /etc/grub.d/40_custom
```

### Step 2: Services and Network (Sections 2-3)

```bash
# 2.1 Disable unnecessary services
systemctl disable --now avahi-daemon
systemctl disable --now cups
systemctl disable --now rpcbind
systemctl disable --now xinetd

# 2.2 Ensure NTP is configured
apt install chrony -y  # or systemd-timesyncd
systemctl enable --now chrony

# 3.1 Network parameters (host only, not router)
cat >> /etc/sysctl.d/99-cis.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
sysctl --system

# 3.4 Configure firewall (UFW or firewalld)
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
```

### Step 3: Access Control (Sections 4-5)

```bash
# 5.2 SSH Server Configuration (/etc/ssh/sshd_config)
sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
cat >> /etc/ssh/sshd_config << 'EOF'
LogLevel VERBOSE
MaxAuthTries 4
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
X11Forwarding no
MaxStartups 10:30:60
LoginGraceTime 60
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
EOF
systemctl restart sshd

# 5.3 Password policy (PAM)
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1

# 5.4 User account settings
# /etc/login.defs
PASS_MAX_DAYS 365
PASS_MIN_DAYS 1
PASS_WARN_AGE 7

# Lock inactive accounts
useradd -D -f 30
```

### Step 4: Audit and Logging (Section 4)

```bash
# Install and configure auditd
apt install auditd audispd-plugins -y
systemctl enable --now auditd

# /etc/audit/rules.d/cis.rules
cat > /etc/audit/rules.d/cis.rules << 'EOF'
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S unlink -S rmdir -S rename -k delete
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-e 2
EOF
augenrules --load

# Configure rsyslog for remote logging
echo "*.* @@syslog-server.corp.com:514" >> /etc/rsyslog.d/50-remote.conf
systemctl restart rsyslog
```

### Step 5: Assess with OpenSCAP

```bash
# Install OpenSCAP
apt install openscap-scanner scap-security-guide -y

# Run CIS benchmark assessment
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results /tmp/cis_results.xml \
  --report /tmp/cis_report.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# View HTML report in browser for detailed results
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **OpenSCAP** | Open-source SCAP (Security Content Automation Protocol) scanner for automated compliance |
| **auditd** | Linux audit framework for monitoring system calls and file access |
| **PAM** | Pluggable Authentication Modules; configurable authentication framework for Linux |
| **sysctl** | Linux kernel parameter configuration for network and system security tuning |
| **AIDE** | Advanced Intrusion Detection Environment; file integrity checker for Linux |

## Tools & Systems

- **OpenSCAP**: Automated CIS benchmark assessment for Linux
- **Ansible Lockdown**: Ansible roles for automated CIS benchmark remediation
- **Lynis**: Open-source security auditing tool for Linux/Unix systems
- **AIDE**: File integrity monitoring for Linux endpoints
- **auditd**: Linux audit framework for system call monitoring

## Common Pitfalls

- **Applying server benchmarks to workstations**: CIS provides separate benchmarks for server and workstation profiles. Server benchmarks disable desktop services.
- **Breaking SSH access**: Misconfiguring sshd_config (especially PermitRootLogin, PasswordAuthentication) can lock out administrators. Always test SSH configuration changes from a second session.
- **Not testing firewall rules**: Enabling UFW without allowing SSH first will disconnect remote sessions permanently.
- **Kernel parameter changes without testing**: Some sysctl settings can break application networking. Test in staging first.
