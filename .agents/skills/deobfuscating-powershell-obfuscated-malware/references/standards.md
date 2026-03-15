# Standards and Frameworks Reference

## PowerShell Obfuscation Taxonomy

### Layer Classification
| Layer | Technique | Example |
|-------|-----------|---------|
| L1 | Base64 EncodedCommand | `powershell -enc SQBFAFgA...` |
| L2 | String Concatenation | `$a='Inv'+'oke'+'-Ex'+'pression'` |
| L3 | Character Code Array | `[char[]](73,69,88)-join''` |
| L4 | Tick-Mark Insertion | `` I`nv`oke-Exp`ress`ion `` |
| L5 | Environment Variable | `$env:COMSPEC[4,15,25]-join''` |
| L6 | SecureString | `ConvertTo-SecureString ... -Key` |
| L7 | Compression + Base64 | `IO.Compression.DeflateStream` |
| L8 | XOR Encoding | `$bytes | %{ $_ -bxor 0x42 }` |
| L9 | Replace Chain | `.Replace('abc','I').Replace(...)` |
| L10 | Format String | `("{2}{0}{1}" -f 'ke-','Ex','Invo')` |

### MITRE ATT&CK Mappings
| Technique | ID | Description |
|-----------|-----|------------|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Malicious PowerShell execution |
| Obfuscated Files or Information | T1027 | Encoding/encryption of scripts |
| Deobfuscate/Decode Files | T1140 | Runtime deobfuscation |
| Ingress Tool Transfer | T1105 | Downloading payloads via PS |
| System Binary Proxy Execution | T1218 | Using trusted binaries |

## PowerShell AST Node Types for Analysis

### Key Expression Nodes
- `CommandExpression`: Direct command invocations
- `InvokeMemberExpression`: Method calls on objects
- `BinaryExpression`: String concatenation operators
- `ArrayExpression`: Character array construction
- `SubExpression`: Nested expression evaluation
- `ExpandableStringExpression`: String interpolation

## References
- [PowerShell Language Specification](https://docs.microsoft.com/en-us/powershell/scripting/lang-spec/chapter-01)
- [Invoke-Obfuscation Framework](https://github.com/danielbohannon/Invoke-Obfuscation)
- [AMSI Interface Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/)
