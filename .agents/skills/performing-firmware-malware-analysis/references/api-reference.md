# API Reference: Firmware Malware Analysis

## binwalk CLI

| Command | Description |
|---------|-------------|
| `binwalk <firmware>` | Scan and display embedded file signatures |
| `binwalk -e <firmware>` | Extract identified components |
| `binwalk -eM <firmware>` | Recursive extraction with signature scanning |
| `binwalk -E <firmware>` | Entropy analysis for encrypted/compressed regions |
| `binwalk -A <firmware>` | Scan for executable opcode signatures |

## binwalk Python API

```python
import binwalk
for module in binwalk.scan("firmware.bin", signature=True, extract=True):
    for result in module.results:
        print(f"0x{result.offset:X}  {result.description}")
```

## chipsec CLI (UEFI Analysis)

| Command | Description |
|---------|-------------|
| `python chipsec_main.py -m common.bios_wp` | Check BIOS write protection |
| `python chipsec_main.py -m common.spi_lock` | Check SPI flash lock status |
| `python chipsec_main.py -m common.secureboot` | Verify Secure Boot configuration |
| `python chipsec_util.py spi dump <output>` | Dump UEFI firmware from SPI flash |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute binwalk, file, and strings commands |
| `hashlib` | stdlib | SHA-256 hashing for firmware integrity |
| `re` | stdlib | Pattern matching for IOC extraction |

## References

- binwalk: https://github.com/ReFirmLabs/binwalk
- Firmadyne: https://github.com/firmadyne/firmadyne
- UEFITool: https://github.com/LongSoft/UEFITool
- chipsec: https://github.com/chipsec/chipsec
- EMBA firmware analyzer: https://github.com/e-m-b-a/emba
