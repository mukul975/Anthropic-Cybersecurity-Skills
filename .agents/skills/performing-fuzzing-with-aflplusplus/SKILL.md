---
name: performing-fuzzing-with-aflplusplus
description: >
  Perform coverage-guided fuzzing of compiled binaries using AFL++ (American Fuzzy Lop Plus Plus)
  to discover memory corruption, crashes, and security vulnerabilities. The tester instruments
  target binaries with afl-cc/afl-clang-fast, manages input corpora with afl-cmin and afl-tmin,
  runs parallel fuzzing campaigns with afl-fuzz, and triages crashes using CASR or GDB scripts.
  Activates for requests involving binary fuzzing, crash discovery, coverage-guided testing, or
  AFL++ fuzzing campaigns.
domain: cybersecurity
subdomain: application-security
tags: [fuzzing, aflplusplus, coverage-guided, crash-triage, binary-analysis, security-testing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Fuzzing with AFL++

## Overview

AFL++ is a community-maintained fork of American Fuzzy Lop (AFL) that provides coverage-guided
fuzzing for compiled binaries. It instruments targets at compile time or via QEMU/Unicorn mode
for binary-only fuzzing, then mutates input corpora to discover new code paths. AFL++ includes
advanced scheduling (MOpt, rare), custom mutators, CMPLOG for input-to-state comparison solving,
and persistent mode for high-throughput fuzzing.

## Prerequisites

- AFL++ installed (`apt install afl++` or build from source)
- Target binary source code (for compile-time instrumentation) or QEMU mode for binary-only
- Initial seed corpus of valid inputs for the target format
- Linux system with /proc/sys/kernel/core_pattern configured

## Steps

1. Instrument the target binary with `afl-cc` or `afl-clang-fast`
2. Prepare seed corpus directory with minimal valid inputs
3. Minimize corpus with `afl-cmin` to remove redundant seeds
4. Run `afl-fuzz` with appropriate flags (-i input -o output)
5. Monitor fuzzing progress via afl-whatsup and UI stats
6. Triage crashes with `afl-tmin` minimization and CASR/GDB analysis
7. Report unique crashes with reproduction steps

## Expected Output

```
+++ Findings +++
  unique crashes: 12
  unique hangs: 3
  last crash: 00:02:15 ago
+++ Coverage +++
  map density: 4.23% / 8.41%
  paths found: 1847
  exec speed: 2145/sec
```
