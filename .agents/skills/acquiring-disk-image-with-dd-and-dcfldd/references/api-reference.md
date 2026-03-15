# API Reference: dd and dcfldd Disk Imaging

## dd - Standard Unix Disk Duplication

### Basic Syntax
```bash
dd if=<source> of=<destination> [options]
```

### Key Options
| Flag | Description | Example |
|------|-------------|---------|
| `if=` | Input file (source device) | `if=/dev/sdb` |
| `of=` | Output file (destination image) | `of=evidence.dd` |
| `bs=` | Block size for read/write | `bs=4096` (forensic standard) |
| `count=` | Number of blocks to copy | `count=1024` |
| `skip=` | Skip N blocks from input start | `skip=2048` |
| `conv=` | Conversion options | `conv=noerror,sync` |
| `status=` | Transfer statistics level | `status=progress` |

### conv= Values
- `noerror` - Continue on read errors (do not abort)
- `sync` - Pad input blocks with zeros on error (preserves offset alignment)
- `notrunc` - Do not truncate output file

### Output Format
```
500107862016 bytes (500 GB, 466 GiB) copied, 8132.45 s, 61.5 MB/s
976773168+0 records in
976773168+0 records out
```

## dcfldd - DoD Forensic dd

### Basic Syntax
```bash
dcfldd if=<source> of=<destination> [options]
```

### Extended Options
| Flag | Description | Example |
|------|-------------|---------|
| `hash=` | Hash algorithm(s) | `hash=sha256,md5` |
| `hashlog=` | File for hash output | `hashlog=hashes.txt` |
| `hashwindow=` | Hash every N bytes | `hashwindow=1G` |
| `hashconv=` | Hash before or after conversion | `hashconv=after` |
| `errlog=` | Error log file | `errlog=errors.log` |
| `split=` | Split output into chunks | `split=2G` |
| `splitformat=` | Suffix format for split files | `splitformat=aa` |
| `vf=` | Verification file | `vf=evidence.dd` |
| `verifylog=` | Verification result log | `verifylog=verify.log` |

### Output Format
```
Total (sha256): a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5...
1024+0 records in
1024+0 records out
```

## sha256sum - Hash Verification

### Syntax
```bash
sha256sum <file_or_device>
sha256sum -c <checksum_file>
```

### Output Format
```
a3f2b8c9d4e5f6...  /dev/sdb
a3f2b8c9d4e5f6...  evidence.dd
```

## blockdev - Write Protection

### Syntax
```bash
blockdev --setro <device>   # Set read-only
blockdev --setrw <device>   # Set read-write
blockdev --getro <device>   # Check: 1=RO, 0=RW
blockdev --getsize64 <device>  # Size in bytes
```

## lsblk - Block Device Enumeration

### Syntax
```bash
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,RO
lsblk -J   # JSON output
lsblk -p   # Full device paths
```

## hdparm - Drive Identification

### Syntax
```bash
hdparm -I <device>   # Detailed drive info
hdparm -i <device>   # Summary identification
```
