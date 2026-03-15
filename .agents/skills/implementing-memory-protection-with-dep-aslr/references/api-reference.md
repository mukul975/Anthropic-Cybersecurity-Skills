# API Reference: Implementing Memory Protection with DEP and ASLR

## Windows PowerShell Commands

```powershell
# Check system-wide mitigations
Get-ProcessMitigation -System
# Check specific process
Get-ProcessMitigation -Name chrome.exe
# Set system-wide DEP
Set-ProcessMitigation -System -Enable DEP
# Import XML policy
Set-ProcessMitigation -PolicyFilePath policy.xml
# Export current policy
Get-ProcessMitigation -RegistryConfigFilePath export.xml
```

## Memory Protection Mechanisms

| Mechanism | OS | Description |
|-----------|-----|------------|
| DEP/NX | Windows/Linux | Prevent code execution from data pages |
| ASLR | Windows/Linux | Randomize memory layout |
| CFG | Windows | Control Flow Guard |
| SEHOP | Windows | SEH Overwrite Protection |
| Stack Canary | Linux | Detect stack buffer overflow |
| PIE | Linux | Position-Independent Executable |
| RELRO | Linux | Read-Only Relocations |
| FORTIFY_SOURCE | Linux | Buffer overflow checks |

## Linux ASLR Check

```bash
# Check ASLR level (0=off, 1=conservative, 2=full)
cat /proc/sys/kernel/randomize_va_space
# Enable full ASLR
echo 2 > /proc/sys/kernel/randomize_va_space
```

## ELF Binary Check (checksec)

```bash
checksec --file=/usr/bin/target
# Or with readelf
readelf -l binary | grep GNU_STACK
readelf -d binary | grep BIND_NOW
```

## GCC Compilation Flags

| Flag | Protection |
|------|-----------|
| `-fstack-protector-strong` | Stack canary |
| `-D_FORTIFY_SOURCE=2` | Buffer overflow checks |
| `-pie -fPIE` | Position-independent |
| `-Wl,-z,relro,-z,now` | Full RELRO |
| `-Wl,-z,noexecstack` | NX stack |

### References

- Windows Exploit Protection: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exploit-protection
- checksec: https://github.com/slimm609/checksec.sh
- ASLR: https://en.wikipedia.org/wiki/Address_space_layout_randomization
