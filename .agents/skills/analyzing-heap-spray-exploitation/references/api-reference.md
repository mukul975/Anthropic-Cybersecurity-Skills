# API Reference: Analyzing Heap Spray Exploitation

## Volatility3 Plugins for Heap Spray Analysis

| Plugin | Command | Purpose |
|--------|---------|---------|
| malfind | `vol -f dump.raw windows.malfind` | Find injected executable memory regions |
| vadinfo | `vol -f dump.raw windows.vadinfo` | Virtual Address Descriptor details |
| memmap | `vol -f dump.raw windows.memmap --pid PID --dump` | Dump process memory to files |
| pslist | `vol -f dump.raw windows.pslist` | List running processes |
| handles | `vol -f dump.raw windows.handles --pid PID` | List process handles |

## Common Heap Spray NOP Sled Patterns

| Pattern | Hex | Description |
|---------|-----|-------------|
| x86 NOP | 0x90909090 | Classic NOP instruction |
| 0x0C landing | 0x0C0C0C0C | Common heap spray address target |
| 0x0D landing | 0x0D0D0D0D | Alternative spray address |
| 0x0A landing | 0x0A0A0A0A | Alternative spray address |
| 0x41 fill | 0x41414141 | "AAAA" padding fill |

## Shellcode Signatures

| Bytes | Mnemonic | Context |
|-------|----------|---------|
| FC E8 | CLD; CALL | Common shellcode prologue |
| 60 E8 | PUSHAD; CALL | Register-saving shellcode start |
| 31 C0 50 68 | XOR EAX; PUSH; PUSH | Stack setup for API call |
| E8 FF FF FF FF | CALL $+5 | Self-locating shellcode (GetPC) |

## Detection Thresholds

| Indicator | Threshold | Meaning |
|-----------|-----------|---------|
| Large allocation | >= 1 MB per region | Suspicious heap allocation |
| Total spray size | >= 50 MB per process | Strong heap spray indicator |
| NOP sled count | >= 20 repeated bytes | NOP sled detected |
| RWX permissions | PAGE_EXECUTE_READWRITE | Injected executable code |

## Install Volatility3

```bash
pip install volatility3
# Or from source:
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3 && pip install -e .
```

## References

- Volatility3 GitHub: https://github.com/volatilityfoundation/volatility3
- Volatility3 malfind: https://volatility3.readthedocs.io/en/latest/
- Heap Spray Techniques: https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/
- DFRWS 2025 Workshop: https://webdiis.unizar.es/~ricardo/dfrws-eu-25-workshop/
