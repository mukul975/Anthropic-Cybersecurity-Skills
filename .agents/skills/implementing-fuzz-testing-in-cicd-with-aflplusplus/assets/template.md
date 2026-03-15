# Fuzz Testing Implementation Template

## Target Application

| Field | Value |
|-------|-------|
| Application Name | |
| Target Function | |
| Language | [ ] C [ ] C++ [ ] Other |
| Input Type | [ ] File [ ] Network [ ] Stdin |

## Fuzzing Configuration

| Parameter | Value |
|-----------|-------|
| Instrumentation | [ ] afl-clang-fast [ ] afl-gcc-fast [ ] QEMU |
| Sanitizer | [ ] ASan [ ] UBSan [ ] MSan [ ] TSan |
| Mode | [ ] Persistent [ ] Fork |
| CmpLog | [ ] Enabled [ ] Disabled |
| Timeout per exec | ms |
| CI run duration | minutes |
| Nightly duration | hours |

## Corpus Management

| Item | Location |
|------|----------|
| Seed corpus | |
| Minimized corpus | |
| CI cache key | |

## Crash Tracking

| Crash ID | CWE | Severity | Crash File | Stack Trace Summary | Fix Status |
|----------|-----|----------|------------|---------------------|------------|
| | | | | | |
