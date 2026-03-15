# API Reference: Linux CIS Benchmark Hardening

## CIS Benchmark Sections

| Section | Topic |
|---------|-------|
| 1 | Initial Setup (filesystem, updates, secure boot) |
| 2 | Services (inetd, special purpose) |
| 3 | Network Configuration (parameters, firewall) |
| 4 | Logging and Auditing (auditd, rsyslog) |
| 5 | Access, Authentication, Authorization (SSH, PAM) |
| 6 | System Maintenance (file permissions) |

## Key sysctl Parameters

### Network Hardening
```bash
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.tcp_syncookies=1
```

### Persistent Configuration
```bash
# /etc/sysctl.d/99-hardening.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
```

## SSH Hardening (/etc/ssh/sshd_config)

| Parameter | Recommended Value |
|-----------|-------------------|
| PermitRootLogin | no |
| PasswordAuthentication | no |
| Protocol | 2 |
| MaxAuthTries | 4 |
| ClientAliveInterval | 300 |
| ClientAliveCountMax | 3 |
| X11Forwarding | no |
| AllowTcpForwarding | no |

## Service Management

### Disable unnecessary services
```bash
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable rpcbind
systemctl mask service_name
```

### Check enabled services
```bash
systemctl list-unit-files --type=service --state=enabled
```

## Audit Rules (/etc/audit/rules.d/)

### Monitor critical files
```bash
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
```

### Monitor system calls
```bash
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S mount -k mounts
```

## File Permissions

| File | Owner | Permissions |
|------|-------|-------------|
| `/etc/passwd` | root:root | 644 |
| `/etc/shadow` | root:shadow | 000 or 640 |
| `/etc/group` | root:root | 644 |
| `/etc/gshadow` | root:shadow | 000 or 640 |

## Automated Tools

### OpenSCAP
```bash
oscap xccdf eval --profile cis \
    --results results.xml \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

### Lynis
```bash
lynis audit system --cronjob --quiet
```
