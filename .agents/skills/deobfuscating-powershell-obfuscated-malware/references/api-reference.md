# PowerShell Deobfuscation — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| re | stdlib | Regex pattern matching for obfuscation detection |
| base64 | stdlib | Base64 decoding of encoded commands |
| pySigma | `pip install pySigma` | Sigma rule generation for detections |

## Common Obfuscation Techniques

| Technique | Pattern | Example |
|-----------|---------|---------|
| Base64 Encoding | `-EncodedCommand <b64>` | `powershell -enc SQBFAFgA...` |
| String Concatenation | `'str1'+'str2'` | `'Inv'+'oke'+'-Exp'+'ression'` |
| Character Codes | `[char]73+[char]69` | `[char]73` = I, `[char]69` = E |
| Backtick Escape | `` `I`E`X `` | Backtick breaks keyword detection |
| Variable Substitution | `$env:COMSPEC` | Use env vars as execution paths |
| Compression | `IO.Compression.DeflateStream` | Compressed + Base64 payload |

## Detection Event IDs

| Source | Event ID | Description |
|--------|----------|-------------|
| PowerShell | 4104 | Script block logging (deobfuscated content) |
| Sysmon | 1 | Process creation with command line |
| Defender | 1116 | Malware detection |

## External References

- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [PSDecode](https://github.com/R3MRUM/PSDecode)
- [PowerShell ScriptBlock Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging)
