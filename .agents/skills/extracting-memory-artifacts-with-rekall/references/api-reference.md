# API Reference: Extracting Memory Artifacts with Rekall

## Rekall Session

```python
from rekall import session

s = session.Session(
    filename="/path/to/memory.raw",
    autodetect=["rsds"],
    profile_path=["https://github.com/google/rekall-profiles/raw/master"]
)
```

## Key Plugins

| Plugin | Purpose | Usage |
|--------|---------|-------|
| `pslist` | List active processes via EPROCESS | `s.plugins.pslist()` |
| `psscan` | Brute-force scan for EPROCESS | `s.plugins.psscan()` |
| `malfind` | Detect injected code (VAD) | `s.plugins.malfind()` |
| `netscan` | List network connections | `s.plugins.netscan()` |
| `dlllist` | List loaded DLLs | `s.plugins.dlllist(pids=[pid])` |
| `vadinfo` | VAD tree analysis | `s.plugins.vadinfo(pids=[pid])` |
| `modules` | List kernel modules | `s.plugins.modules()` |
| `handles` | List open handles | `s.plugins.handles(pids=[pid])` |
| `filescan` | Scan for FILE_OBJECT | `s.plugins.filescan()` |

## Hidden Process Detection

```python
pslist_pids = set(p.pid for p in s.plugins.pslist())
psscan_pids = set(p.pid for p in s.plugins.psscan())
hidden = psscan_pids - pslist_pids
```

## Malfind Output Fields

- `pid`: Process ID
- `name`: Process name
- `address`: VAD start address
- `protection`: Memory protection (PAGE_EXECUTE_READWRITE = suspicious)
- `tag`: Pool tag

## Command Line

```bash
rekall -f memory.raw pslist
rekall -f memory.raw malfind
rekall -f memory.raw netscan
rekall -f memory.raw dlllist --pid 1234
```

### References

- Rekall: https://github.com/google/rekall
- Rekall docs: https://rekall.readthedocs.io/
- Rekall profiles: https://github.com/google/rekall-profiles
