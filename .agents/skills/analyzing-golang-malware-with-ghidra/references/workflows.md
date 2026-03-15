# Go Malware Analysis Workflows

## Workflow 1: Stripped Binary Recovery
```
[Stripped Go Binary] --> [Find pclntab] --> [Recover Function Names]
                                                    |
                                                    v
                                           [Apply GoResolver] --> [Deobfuscate Names]
                                                                        |
                                                                        v
                                                               [Categorize Functions]
```

## Workflow 2: Full Ghidra Analysis
```
[Go Binary] --> [Import to Ghidra] --> [Run Go Analysis Scripts]
                                              |
                                              v
                                    [Fix String References]
                                              |
                                              v
                                    [Identify main Package]
                                              |
                                              v
                                    [Analyze C2/Network Logic]
```

## Workflow 3: Dependency-Based Capability Assessment
```
[Go Binary] --> [Extract Module Info] --> [List Dependencies]
                                                |
                                                v
                                       [Map to Capabilities]
                                                |
                                                v
                                       [Prioritize Analysis]
```
