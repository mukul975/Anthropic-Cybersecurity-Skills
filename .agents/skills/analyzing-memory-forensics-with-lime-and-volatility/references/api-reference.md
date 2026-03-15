# API Reference: Analyzing Memory Forensics with LiME and Volatility

## LiME (Linux Memory Extractor)

```bash
# Build LiME module
cd LiME/src && make

# Acquire memory (lime format - includes metadata)
insmod lime-$(uname -r).ko "path=/evidence/mem.lime format=lime"

# Acquire memory (raw format)
insmod lime-$(uname -r).ko "path=/evidence/mem.raw format=raw"

# Acquire over network
insmod lime.ko "path=tcp:4444 format=lime"
# On forensic workstation: nc target 4444 > mem.lime
```

## Volatility 3 Linux Plugins

| Plugin | Description |
|--------|-------------|
| `linux.pslist` | List processes via task_struct |
| `linux.psscan` | Brute-force scan for task_struct |
| `linux.bash` | Recovered bash command history |
| `linux.sockstat` | Network connections |
| `linux.lsmod` | Loaded kernel modules |
| `linux.malfind` | Detect injected code |
| `linux.check_afinfo` | Detect network hooking |
| `linux.tty_check` | Detect TTY hooking |
| `linux.proc.Maps` | Process memory maps |

## Volatility 3 CLI

```bash
vol3 -f memory.lime linux.pslist
vol3 -f memory.lime linux.bash
vol3 -f memory.lime linux.sockstat
vol3 -f memory.lime linux.malfind
vol3 -f memory.lime linux.lsmod
vol3 -f memory.lime linux.check_afinfo
```

## Hidden Process Detection

```bash
# Compare pslist (linked list) vs psscan (brute force)
vol3 -f mem.lime linux.pslist > pslist.txt
vol3 -f mem.lime linux.psscan > psscan.txt
diff pslist.txt psscan.txt
```

### References

- LiME: https://github.com/504ensicsLabs/LiME
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Volatility 3 docs: https://volatility3.readthedocs.io/
