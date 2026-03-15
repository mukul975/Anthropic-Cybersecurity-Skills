# Rootkit Detection API Reference

## Volatility 3 - Rootkit Analysis Plugins

```bash
# Process enumeration - compare for hidden processes
vol3 -f memory.dmp windows.pslist     # EPROCESS linked list (rootkit-manipulable)
vol3 -f memory.dmp windows.psscan     # Pool tag scanning (rootkit-resistant)

# SSDT hook detection
vol3 -f memory.dmp windows.ssdt

# Kernel module listing
vol3 -f memory.dmp windows.modules
vol3 -f memory.dmp windows.modscan    # Scan for hidden modules

# Driver IRP hook detection
vol3 -f memory.dmp windows.driverirp

# Callback enumeration
vol3 -f memory.dmp windows.callbacks

# IDT (Interrupt Descriptor Table) check
vol3 -f memory.dmp windows.idt

# Injected code detection
vol3 -f memory.dmp windows.malfind
```

## Cross-View Detection Method

```
Step 1: Enumerate with pslist (uses EPROCESS ActiveProcessLinks)
Step 2: Enumerate with psscan (scans pool tags in physical memory)
Step 3: Compare PID sets
Step 4: PIDs in psscan but NOT in pslist = hidden by DKOM rootkit
```

## Linux Rootkit Detection Tools

```bash
# rkhunter
rkhunter --update                       # Update signatures
rkhunter --check --skip-keypress        # Full scan
rkhunter --check --report-warnings-only # Warnings only

# chkrootkit
chkrootkit                              # Full scan
chkrootkit -q                           # Quiet (only infected)

# Unhide (process and port hiding detection)
unhide proc     # Compare /proc, ps, syscall enumeration
unhide sys      # System call brute force
unhide-tcp      # Hidden TCP/UDP ports
```

## Rootkit Types

| Type | Hides In | Detection Method |
|------|----------|-----------------|
| User-mode | LD_PRELOAD, IAT hooks | Cross-view, strace |
| Kernel-mode | DKOM, SSDT hooks | Memory forensics |
| Bootkits | MBR/VBR/UEFI | Firmware integrity |
| Hypervisor | Below OS | Timing analysis |

## DKOM (Direct Kernel Object Manipulation)

```
Rootkit unlinking technique:
EPROCESS(prev).Flink -> EPROCESS(hidden).Flink  (skip hidden)
EPROCESS(next).Blink -> EPROCESS(hidden).Blink  (skip hidden)

Process disappears from pslist but remains in physical memory (psscan finds it)
```

## Memory Acquisition

```bash
# Windows - WinPmem
winpmem_mini_x64.exe memdump.raw

# Linux - LiME
insmod lime.ko "path=/tmp/memory.lime format=lime"

# Linux - /proc/kcore
dd if=/proc/kcore of=/evidence/memory.raw bs=1M
```
