# API Reference: Analyzing Linux Kernel Rootkits

## Volatility3 Linux Plugins

```bash
# Check syscall table for hooks
vol -f memory.lime linux.check_syscall.Check_syscall

# List loaded kernel modules
vol -f memory.lime linux.lsmod.Lsmod

# Detect hidden kernel modules
vol -f memory.lime linux.hidden_modules.Hidden_modules

# Check IDT for hooks
vol -f memory.lime linux.check_idt.Check_idt

# List processes (detect hidden)
vol -f memory.lime linux.pslist.PsList
vol -f memory.lime linux.pstree.PsTree

# Check for modified cred structures
vol -f memory.lime linux.check_creds.Check_creds

# Network connections
vol -f memory.lime linux.sockstat.Sockstat

# JSON output
vol -f memory.lime linux.check_syscall.Check_syscall -r json > syscalls.json
```

## Memory Acquisition Tools

| Tool | Command | Use Case |
|------|---------|----------|
| LiME | `insmod lime.ko "path=/tmp/mem.lime format=lime"` | Linux kernel module |
| AVML | `avml /tmp/memory.raw` | Azure/cloud instances |
| /proc/kcore | `dd if=/proc/kcore of=mem.raw` | Quick (partial) dump |

## Volatility3 Symbol Tables (ISF)

```bash
# Generate ISF from running kernel
vol -f memory.lime banners.Banners
# Download matching ISF from:
# https://github.com/volatilityfoundation/volatility3#symbol-tables
```

## rkhunter Commands

```bash
# Full system scan
rkhunter --check --skip-keypress --report-warnings-only

# Update signatures
rkhunter --update

# Check specific tests
rkhunter --check --enable rootkits,trojans,os_specific

# Output to log file
rkhunter --check --logfile /var/log/rkhunter.log
```

## Known Linux Rootkits Detected

| Rootkit | Technique | Volatility Plugin |
|---------|-----------|-------------------|
| Diamorphine | Hidden module + syscall hook | check_syscall, hidden_modules |
| Reptile | Syscall hook + port knocking | check_syscall |
| KBeast | Syscall hook + /proc hiding | check_syscall, hidden_modules |
| Adore-ng | VFS hook + hidden files | lsmod, check_syscall |
| Jynx2 | LD_PRELOAD userspace | pslist (parent check) |

## Cross-View Detection

```bash
# Compare /proc/modules vs /sys/module
diff <(cat /proc/modules | awk '{print $1}' | sort) \
     <(ls /sys/module/ | sort)

# Check for hidden processes
diff <(ls /proc/ | grep -E '^[0-9]+$' | sort -n) \
     <(ps -eo pid --no-headers | sort -n)
```

### References

- Volatility3 Linux Plugins: https://volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.html
- LiME: https://github.com/504ensicsLabs/LiME
- rkhunter: http://rkhunter.sourceforge.net/
- MITRE T1014 Rootkit: https://attack.mitre.org/techniques/T1014/
