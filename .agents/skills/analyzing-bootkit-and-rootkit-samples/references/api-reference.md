# API Reference: Bootkit and Rootkit Analysis Tools

## dd - Boot Sector Extraction

### Syntax
```bash
dd if=/dev/sda of=mbr.bin bs=512 count=1          # MBR
dd if=/dev/sda of=first_track.bin bs=512 count=63  # First track
dd if=/dev/sda1 of=vbr.bin bs=512 count=1          # VBR
```

## ndisasm - 16-bit Disassembly

### Syntax
```bash
ndisasm -b16 mbr.bin > mbr_disasm.txt
ndisasm -b16 -o 0x7C00 mbr.bin   # Set origin to MBR load address
```

### Key Flags
| Flag | Description |
|------|-------------|
| `-b16` | 16-bit real-mode disassembly |
| `-b32` | 32-bit protected-mode |
| `-o` | Origin address offset |

## UEFITool - Firmware Analysis

### CLI Syntax
```bash
UEFIExtract firmware.rom all             # Extract all modules
UEFIExtract firmware.rom <GUID> body     # Extract specific module body
```

### Output
Extracts firmware volumes into a directory tree with each DXE driver, PEI module, and option ROM as separate files identified by GUID.

## chipsec - Hardware Security Assessment

### Syntax
```bash
python chipsec_main.py -m common.secureboot.variables  # Check Secure Boot
python chipsec_main.py -m common.bios_wp               # SPI write protection
python chipsec_main.py -m common.spi_lock               # SPI lock status
python chipsec_util.py spi dump firmware.rom            # Dump SPI flash
```

### Key Modules
| Module | Purpose |
|--------|---------|
| `common.secureboot.variables` | Verify Secure Boot configuration |
| `common.bios_wp` | Check BIOS write protection |
| `common.spi_lock` | Verify SPI flash lock bits |
| `common.smm` | SMM protection verification |

## Volatility 3 - Rootkit Detection Plugins

### Syntax
```bash
vol3 -f memory.dmp <plugin>
```

### Rootkit Detection Plugins
| Plugin | Purpose |
|--------|---------|
| `windows.ssdt` | System Service Descriptor Table hooks |
| `windows.callbacks` | Kernel callback registrations |
| `windows.driverscan` | Scan for driver objects |
| `windows.modules` | List loaded kernel modules |
| `windows.psscan` | Pool-tag scan for processes (finds hidden) |
| `windows.pslist` | Active process list (DKOM-affected) |
| `windows.idt` | Interrupt Descriptor Table hooks |

### Output Format
```
Offset  Order  Module         Section  Owner
------- -----  ------         -------  -----
0x...   0      ntoskrnl.exe   .text    ntoskrnl.exe
0x...   73     UNKNOWN        -        rootkit.sys   ← suspicious
```

## flashrom - SPI Flash Dumping

### Syntax
```bash
flashrom -p internal -r firmware.rom     # Read/dump
flashrom -p internal -w clean.rom        # Write/reflash
flashrom -p internal --verify clean.rom  # Verify flash contents
```

## YARA - Firmware Pattern Scanning

### Syntax
```bash
yara -r uefi_malware.yar firmware.rom
yara -s -r rules.yar firmware.rom   # Show matching strings
```
