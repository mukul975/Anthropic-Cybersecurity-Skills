# AFL++ Fuzzing — API Reference

## Installation

```bash
apt install afl++                    # Ubuntu/Debian
# Or build from source:
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus && make all
```

## AFL++ CLI Tools

| Tool | Description |
|------|-------------|
| `afl-cc` / `afl-clang-fast` | Compile-time instrumentation compiler wrapper |
| `afl-fuzz` | Main fuzzer — coverage-guided mutation engine |
| `afl-cmin` | Corpus minimization — remove redundant seeds |
| `afl-tmin` | Test case minimization — shrink individual inputs |
| `afl-whatsup` | Multi-instance campaign status summary |
| `afl-plot` | Generate fuzzing progress plots |
| `afl-showmap` | Display coverage map for a single input |

## afl-fuzz Key Flags

| Flag | Description |
|------|-------------|
| `-i <dir>` | Input seed corpus directory |
| `-o <dir>` | Output directory for findings |
| `-m <MB>` | Memory limit (use `none` for ASAN) |
| `-t <ms>` | Execution timeout per test case |
| `-x <dict>` | Optional fuzzing dictionary |
| `-p <sched>` | Power schedule: fast, coe, explore, rare, mmopt |
| `-l <level>` | CMPLOG instrumentation level (2=transforms, 3=all) |
| `-c <bin>` | CMPLOG binary for input-to-state |
| `-M <name>` | Main fuzzer instance (parallel mode) |
| `-S <name>` | Secondary fuzzer instance (parallel mode) |
| `-Q` | QEMU mode (binary-only fuzzing) |
| `-U` | Unicorn mode |

## fuzzer_stats File Fields

| Field | Description |
|-------|-------------|
| `execs_done` | Total executions completed |
| `execs_per_sec` | Current execution speed |
| `corpus_count` | Total paths in corpus |
| `saved_crashes` | Unique crashes discovered |
| `saved_hangs` | Unique hangs discovered |
| `stability` | Execution stability percentage |
| `bitmap_cvg` | Code coverage bitmap density |

## Crash Triage Tools

| Tool | Purpose |
|------|---------|
| `casr-afl` | CASR crash severity analysis for AFL++ |
| `afl-tmin` | Minimize crash inputs |
| `gdb --batch -ex run` | Reproduce crash under debugger |

## External References

- [AFL++ Documentation](https://aflplus.plus/docs/)
- [AFL++ GitHub](https://github.com/AFLplusplus/AFLplusplus)
- [CASR Crash Triage](https://github.com/ispras/casr)
