# Memory Forensics Workflows

## Workflow 1: Malware Triage
```
[Memory Dump] --> [pslist/psscan] --> [malfind] --> [dlllist] --> [netscan]
                                          |
                                          v
                                  [Dump Injected Code] --> [YARA Scan]
```

## Workflow 2: Rootkit Detection
```
[Memory Dump] --> [pslist vs psscan] --> [Hidden Processes]
                                               |
                                               v
                                      [SSDT Hook Detection]
                                               |
                                               v
                                      [Inline Hook Analysis]
```
