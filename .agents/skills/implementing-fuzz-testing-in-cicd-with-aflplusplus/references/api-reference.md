# API Reference — Implementing Fuzz Testing in CI/CD with AFL++

## Libraries Used
- **subprocess**: Execute AFL++ toolchain commands (afl-clang-fast, afl-fuzz, afl-cmin)
- **pathlib**: File system operations for corpus and crash management

## CLI Interface

```
python agent.py compile --source target.c --output target_fuzz [--compiler afl-clang-fast]
python agent.py fuzz --binary ./target_fuzz --input seeds/ --output findings/ [--duration 300]
python agent.py triage --binary ./target_fuzz --crashes-dir findings/default/crashes/
python agent.py stats --stats-file findings/default/fuzzer_stats
```

## Core Functions

### `compile_target(source_file, output_binary, compiler)`
Compiles target with AFL++ instrumentation. Sets `AFL_HARDEN=1` for memory sanitizers.

### `run_fuzzer(binary, input_dir, output_dir, duration_seconds, memory_limit)`
Runs `afl-fuzz` with headless mode (`AFL_NO_UI=1`), time-limited (`-V` flag).

**Environment Variables Set:**
| Variable | Value | Purpose |
|----------|-------|---------|
| `AFL_SKIP_CPUFREQ` | 1 | Skip CPU frequency check (CI/CD) |
| `AFL_NO_UI` | 1 | Headless mode for CI environments |
| `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` | 1 | Continue on crash dir issues |

### `parse_fuzzer_stats(stats_file)`
Parses AFL++ `fuzzer_stats` file. Key metrics: `execs_per_sec`, `paths_total`, `saved_crashes`, `bitmap_cvg`.

### `triage_crashes(binary, crashes_dir)`
Re-runs crash inputs through the binary and classifies by signal (SIGSEGV, SIGABRT, etc.).

### `minimize_corpus(binary, input_dir, output_dir, timeout)`
Runs `afl-cmin` to remove redundant seeds from the corpus.

## AFL++ Commands Used

| Command | Purpose |
|---------|---------|
| `afl-clang-fast` | Compile with LLVM-based instrumentation |
| `afl-fuzz -i <in> -o <out> -- <binary>` | Main fuzzing loop |
| `afl-cmin -i <in> -o <out> -- <binary>` | Corpus minimization |
| `afl-tmin -i <crash> -o <min> -- <binary>` | Test case minimization |

## Dependencies
AFL++ must be installed: `apt install aflplusplus` or build from source.
```
pip install  # No Python packages needed beyond stdlib
```
