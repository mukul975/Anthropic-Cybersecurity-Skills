# AIDE File Integrity Monitoring API Reference

## AIDE CLI Commands

```bash
# Initialize baseline database
aide --init --config=/etc/aide/aide.conf

# Copy new database as baseline
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run integrity check against baseline
aide --check --config=/etc/aide/aide.conf

# Update baseline with current state
aide --update --config=/etc/aide/aide.conf

# Compare two databases
aide --compare --config=/etc/aide/aide.conf

# Validate configuration syntax
aide --config-check --config=/etc/aide/aide.conf
```

## Configuration File Syntax (aide.conf)

```
# Database locations
database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new

# Report output
report_url=stdout
report_url=file:/var/log/aide/aide.log

# Gzip compression
gzip_dbout=yes

# Rule definitions
# p=permissions i=inode n=links u=user g=group s=size
# b=block_count m=mtime c=ctime sha256=SHA-256 hash
NORMAL = p+i+n+u+g+s+b+m+c+sha256
PERMS = p+i+u+g
LOG = p+u+g+i

# Monitor paths
/bin NORMAL
/sbin NORMAL
/etc PERMS
/boot NORMAL

# Exclusions (prefix with !)
!/var/log/.*
!/proc
!/sys
!/tmp
```

## Available Check Attributes

| Attribute | Description |
|-----------|-------------|
| `p` | File permissions |
| `i` | Inode number |
| `n` | Number of hard links |
| `u` | User ownership |
| `g` | Group ownership |
| `s` | File size |
| `b` | Block count |
| `m` | Modification time |
| `c` | Change time (ctime) |
| `sha256` | SHA-256 hash |
| `sha512` | SHA-512 hash |
| `md5` | MD5 hash |
| `xattrs` | Extended attributes |
| `acl` | Access control lists |
| `selinux` | SELinux context |

## Cron Automation

```bash
# Daily integrity check at 5 AM
0 5 * * * root /usr/bin/aide --check --config=/etc/aide/aide.conf \
  | mail -s "AIDE Report" security@company.com

# Weekly baseline update
0 3 * * 0 root /usr/bin/aide --update --config=/etc/aide/aide.conf \
  && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

## Installation

```bash
# Debian/Ubuntu
apt install aide

# RHEL/CentOS
yum install aide

# Initialize after install
aideinit       # Debian wrapper
aide --init    # Direct command
```
