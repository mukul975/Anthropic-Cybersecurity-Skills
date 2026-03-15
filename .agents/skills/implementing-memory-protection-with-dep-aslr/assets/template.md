# Memory Protection Configuration Template

## System-Level Mitigations
| Mitigation | Status | Notes |
|-----------|--------|-------|
| DEP | AlwaysOn / OptOut | |
| ASLR (BottomUp) | Enabled | |
| ASLR (HighEntropy) | Enabled | |
| SEHOP | Enabled | |
| ForceRelocateImages | Enabled | |

## Per-Application Mitigations
| Application | DEP | ASLR | CFG | SEHOP |
|------------|-----|------|-----|-------|
| WINWORD.EXE | On | On | On | On |
| EXCEL.EXE | On | On | On | On |

## Sign-Off
| Role | Name | Date |
|------|------|------|
| Security | | |
