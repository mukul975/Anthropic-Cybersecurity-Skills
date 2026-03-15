# API Reference: Linux ELF Malware Analysis Tools

## readelf - ELF Binary Inspection

### Syntax
```bash
readelf -h <binary>    # ELF header
readelf -S <binary>    # Section headers
readelf -l <binary>    # Program headers (segments)
readelf -s <binary>    # Symbol table
readelf -d <binary>    # Dynamic section
readelf -r <binary>    # Relocation entries
readelf -n <binary>    # Notes section
```

### Key ELF Header Fields
| Field | Description |
|-------|-------------|
| `Class` | 32-bit or 64-bit |
| `Machine` | Architecture (x86-64, ARM, MIPS) |
| `Type` | EXEC (executable), DYN (shared object) |
| `Entry point` | Code execution start address |

## pyelftools - Python ELF Parsing

### Usage
```python
from elftools.elf.elffile import ELFFile

with open("binary", "rb") as f:
    elf = ELFFile(f)
    elf.elfclass          # 32 or 64
    elf.little_endian     # True/False
    elf.header.e_machine  # Architecture
    elf.header.e_entry    # Entry point
    elf.num_sections()    # Section count
    elf.get_section_by_name(".symtab")  # Symbol table
```

## strings - String Extraction

### Syntax
```bash
strings <binary>                  # ASCII strings (default min 4)
strings -n 8 <binary>            # Minimum 8 characters
strings -e l <binary>            # 16-bit little-endian (Unicode)
strings -t x <binary>            # Print offset in hex
```

## strace - System Call Tracing

### Syntax
```bash
strace -f ./binary                    # Follow forks
strace -e trace=network ./binary      # Network calls only
strace -e trace=file ./binary         # File operations only
strace -e trace=process ./binary      # Process operations
strace -o output.txt ./binary         # Log to file
strace -c ./binary                    # Summary statistics
```

### Key System Calls
| Call | Category |
|------|----------|
| `socket`, `connect`, `bind` | Network |
| `fork`, `execve`, `clone` | Process |
| `open`, `read`, `write`, `unlink` | File I/O |
| `ptrace` | Anti-debug/injection |

## ltrace - Library Call Tracing

### Syntax
```bash
ltrace -f ./binary                # Follow child processes
ltrace -e malloc+free ./binary    # Specific functions
ltrace -o output.txt ./binary     # Log to file
```

## GDB - GNU Debugger

### Syntax
```bash
gdb ./binary
(gdb) break main
(gdb) break *0x400580       # Break at address
(gdb) run
(gdb) info registers
(gdb) x/20s $rdi            # Examine string at RDI
(gdb) x/10i $rip            # Disassemble at RIP
(gdb) bt                    # Backtrace
```

## UPX - Packer Detection/Unpacking

### Syntax
```bash
upx -t <binary>    # Test if packed
upx -d <binary>    # Decompress/unpack
upx -l <binary>    # List compression details
```

## objdump - Disassembly

### Syntax
```bash
objdump -d <binary>              # Disassemble .text
objdump -D <binary>              # Disassemble all sections
objdump -M intel -d <binary>     # Intel syntax
objdump -t <binary>              # Symbol table
```

## nm - Symbol Listing

### Syntax
```bash
nm <binary>        # List symbols
nm -D <binary>     # Dynamic symbols only
nm -u <binary>     # Undefined (imported) symbols
```
