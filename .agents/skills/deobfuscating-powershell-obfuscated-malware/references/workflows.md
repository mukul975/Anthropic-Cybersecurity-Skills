# PowerShell Deobfuscation Workflows

## Workflow 1: Automated Multi-Layer Deobfuscation

```
[Obfuscated Script] --> [Identify Techniques] --> [Remove Tick Marks]
                                                        |
                                                        v
                                              [Resolve Concatenation]
                                                        |
                                                        v
                                              [Decode Base64 Layers]
                                                        |
                                                        v
                                              [IEX -> Write-Output]
                                                        |
                                                        v
                                              [Extract Final Payload]
```

## Workflow 2: AST-Based Analysis

```
[Script Input] --> [Parse AST] --> [Walk Expression Nodes] --> [Evaluate Expressions]
                                                                       |
                                                                       v
                                                             [Reconstruct Commands]
                                                                       |
                                                                       v
                                                             [Extract IOCs]
```

## Workflow 3: Dynamic Sandbox Deobfuscation

```
[Obfuscated Script] --> [Execute in Sandbox] --> [Capture ScriptBlock Logs]
                                                          |
                                                          v
                                                 [Event ID 4104 Analysis]
                                                          |
                                                          v
                                                 [Reconstruct Execution Chain]
```

### Steps:
1. **Enable Logging**: Enable PowerShell ScriptBlock logging (Event ID 4104)
2. **Execute**: Run obfuscated script in isolated sandbox
3. **Collect**: Gather all ScriptBlock log entries
4. **Reconstruct**: Assemble deobfuscated script from logged blocks
5. **Extract**: Pull IOCs from the reconstructed clear-text script
