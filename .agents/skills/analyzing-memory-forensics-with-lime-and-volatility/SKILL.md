---
name: analyzing-memory-forensics-with-lime-and-volatility
description: >
  Performs Linux memory acquisition using LiME (Linux Memory Extractor) kernel module
  and analysis with Volatility 3 framework. Extracts process lists, network connections,
  bash history, loaded kernel modules, and injected code from Linux memory images.
  Use when performing incident response on compromised Linux systems.
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, memory, forensics, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Memory Forensics with LiME and Volatility

## Instructions

Acquire Linux memory using LiME kernel module, then analyze with Volatility 3
to extract forensic artifacts from the memory image.

```bash
# LiME acquisition
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Volatility 3 analysis
vol3 -f /evidence/memory.lime linux.pslist
vol3 -f /evidence/memory.lime linux.bash
vol3 -f /evidence/memory.lime linux.sockstat
```

```python
import volatility3
from volatility3.framework import contexts, automagic
from volatility3.plugins.linux import pslist, bash, sockstat

# Programmatic Volatility 3 usage
context = contexts.Context()
automagics = automagic.available(context)
```

Key analysis steps:
1. Acquire memory with LiME (format=lime or format=raw)
2. List processes with linux.pslist, compare with linux.psscan
3. Extract bash command history with linux.bash
4. List network connections with linux.sockstat
5. Check loaded kernel modules with linux.lsmod for rootkits

## Examples

```bash
# Full forensic workflow
vol3 -f memory.lime linux.pslist | grep -v "\[kthread\]"
vol3 -f memory.lime linux.bash
vol3 -f memory.lime linux.malfind
vol3 -f memory.lime linux.lsmod
```
