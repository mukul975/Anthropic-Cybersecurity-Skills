# Go Binary Analysis Standards

## Go Binary Structure
| Component | Description | Location |
|-----------|-------------|----------|
| pclntab | PC-to-function mapping table | .gopclntab or .text |
| moduledata | Runtime metadata structure | .noptrdata |
| itab | Interface method tables | .rodata |
| buildinfo | Go version and module info | .go.buildinfo |
| typelinks | Type descriptor table | .rodata |

## pclntab Magic Bytes by Go Version
| Magic | Go Version |
|-------|-----------|
| 0xFBFFFFFF | 1.2 - 1.15 |
| 0xFAFFFFFF | 1.16 - 1.17 |
| 0xF1FFFFFF | 1.18 - 1.19 |
| 0xF0FFFFFF | 1.20+ |

## Common Go Malware Families
- Sliver C2 implant
- Geacon (Go Cobalt Strike beacon)
- GoBruteforcer
- Kaiji botnet
- Chaos botnet (Go-based)

## References
- [Go Runtime Source](https://github.com/golang/go/tree/master/src/runtime)
- [Go Internal ABI](https://go.dev/s/regcallabi)
