# API Reference: File Carving with Foremost

## Foremost CLI

| Command | Description |
|---------|-------------|
| `foremost -t <types> -i <image> -o <output>` | Carve files of specified types from image |
| `foremost -c <config> -i <image> -o <output>` | Carve using custom configuration file |
| `foremost -v -t all -i <image> -o <output>` | Verbose carving of all supported types |

## Foremost Options

| Flag | Description |
|------|-------------|
| `-t` | File types to carve (jpg, png, pdf, doc, all) |
| `-i` | Input disk image path |
| `-o` | Output directory for carved files |
| `-c` | Custom foremost.conf path |
| `-v` | Verbose mode with progress details |

## Scalpel CLI

| Command | Description |
|---------|-------------|
| `scalpel -c <config> -o <output> <image>` | High-performance carving with config |

## foremost.conf Format

```
# extension  case_sensitive  max_size  header  footer
jpg    y    200000    \xff\xd8\xff    \xff\xd9
pdf    y    5000000   %PDF           %%EOF
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute foremost/scalpel commands |
| `hashlib` | stdlib | SHA-256 hashing for evidence integrity |
| `pathlib` | stdlib | File system traversal of carved output |

## References

- Foremost source: https://foremost.sourceforge.net/
- Scalpel repository: https://github.com/sleuthkit/scalpel
- Sleuth Kit (blkls, mmls): https://sleuthkit.org/
- File signature database: https://www.garykessler.net/library/file_sigs.html
