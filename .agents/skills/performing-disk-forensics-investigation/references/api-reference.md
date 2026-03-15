# API Reference: Performing Disk Forensics Investigation

## pytsk3 Library (The Sleuth Kit Python Bindings)

| Class/Method | Description |
|--------------|-------------|
| `pytsk3.Img_Info(path)` | Open disk image (raw, E01, AFF) |
| `pytsk3.FS_Info(img_info)` | Parse file system from image |
| `fs.open_dir(path)` | Open directory for listing |
| `fs.open_file(path)` | Open file for reading content |
| `entry.info.meta` | Access file metadata (timestamps, size, flags) |
| `TSK_FS_META_FLAG_UNALLOC` | Flag indicating deleted/unallocated file |

## File Metadata Fields

| Field | Description |
|-------|-------------|
| `meta.crtime` | File creation time (NTFS) |
| `meta.mtime` | Last modification time |
| `meta.atime` | Last access time |
| `meta.ctime` | Metadata change time |
| `meta.size` | File size in bytes |
| `meta.addr` | Inode/MFT entry number |
| `meta.flags` | Allocation flags |

## NTFS MFT Structure

| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 bytes | Signature ("FILE") |
| 0x16 | 2 bytes | Flags (in-use, directory) |
| 0x1C | 4 bytes | Real size of MFT entry |

## Key Libraries

- **pytsk3** (`pip install pytsk3`): Python bindings for The Sleuth Kit
- **dfvfs** (`pip install dfvfs`): Digital Forensics Virtual File System
- **hashlib** (stdlib): Image integrity verification (MD5, SHA-256)
- **struct** (stdlib): Parse binary MFT entry headers

## CLI Tools (Reference)

| Tool | Description |
|------|-------------|
| `fls -r image.dd` | Recursively list files (TSK) |
| `icat image.dd inode` | Extract file by inode number |
| `mmls image.dd` | List disk partitions |
| `fsstat image.dd` | File system statistics |

## Configuration

| Variable | Description |
|----------|-------------|
| Image path | Path to forensic disk image (dd, E01, AFF) |
| MFT export | Exported $MFT file for NTFS-specific analysis |

## References

- [The Sleuth Kit](https://www.sleuthkit.org/)
- [pytsk3 Documentation](https://github.com/py4n6/pytsk)
- [Autopsy Digital Forensics](https://www.autopsy.com/)
- [SANS Forensics Poster](https://www.sans.org/posters/windows-forensic-analysis/)
