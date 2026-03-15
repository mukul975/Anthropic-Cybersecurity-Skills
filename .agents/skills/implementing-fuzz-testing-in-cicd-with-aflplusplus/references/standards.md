# Standards Reference for Fuzz Testing

## NIST SP 800-53 Rev 5 Controls

| Control | Description | Fuzzing Alignment |
|---------|-------------|-------------------|
| SA-11(5) | Penetration Testing | Fuzz testing discovers vulnerabilities through automated input mutation |
| SA-11(8) | Dynamic Code Analysis | AFL++ provides runtime analysis with instrumented binaries |
| SI-10 | Information Input Validation | Fuzzing validates input handling robustness |
| SI-17 | Fail-Safe Procedures | Crash detection ensures failures are handled safely |

## OWASP Testing Guide v4.2

- **WSTG-INPV-07**: Testing for Input Validation --- AFL++ systematically tests boundary conditions
- **WSTG-ERRH-01**: Error Handling --- Crash analysis reveals improper error handling

## CWE Categories Commonly Found by Fuzzing

| CWE | Name | AFL++ Detection Method |
|-----|------|----------------------|
| CWE-120 | Buffer Overflow | ASan crash on out-of-bounds write |
| CWE-125 | Out-of-Bounds Read | ASan crash on invalid read |
| CWE-416 | Use After Free | ASan detects freed memory access |
| CWE-476 | NULL Pointer Dereference | SIGSEGV on null deref |
| CWE-190 | Integer Overflow | UBSan detects arithmetic overflow |
| CWE-787 | Out-of-Bounds Write | ASan detects heap/stack buffer overflow |
| CWE-400 | Uncontrolled Resource Consumption | Timeout detection for hangs |

## Fuzzing Maturity Levels

| Level | Description | CI Integration |
|-------|-------------|----------------|
| 1 Basic | Manual ad-hoc fuzzing | None |
| 2 Structured | Harness-based with corpus management | PR-triggered short runs |
| 3 Continuous | Nightly campaigns with crash tracking | Nightly + corpus caching |
| 4 Optimized | Multi-tool (AFL++, libFuzzer), crash dedup, coverage tracking | Full CI/CD integration with gating |
