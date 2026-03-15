---
name: detecting-container-escape-attempts
description: Container escape is a critical attack technique where an adversary breaks out of container isolation to access the host system or other containers. Detection involves monitoring for escape indicators 
domain: cybersecurity
subdomain: container-security
tags: [containers, kubernetes, docker, security, runtime-security, escape-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Detecting Container Escape Attempts

## Overview

Container escape is a critical attack technique where an adversary breaks out of container isolation to access the host system or other containers. Detection involves monitoring for escape indicators such as namespace manipulation, capability abuse, kernel exploits, mounted sensitive paths, and anomalous syscall patterns using runtime security tools like Falco, Sysdig, and custom seccomp/audit rules.

## Prerequisites

- Linux host with kernel 5.10+ (eBPF support)
- Falco 0.37+ installed (kernel module or eBPF probe)
- Docker Engine or containerd runtime
- auditd configured
- Root access for eBPF/kernel module loading

## Core Concepts

### Common Container Escape Vectors

| Vector | Technique | MITRE ID |
|--------|-----------|----------|
| Privileged containers | Mount host filesystem, load kernel modules | T1611 |
| Docker socket mount | Create privileged container from within | T1610 |
| Kernel exploits | CVE-2022-0185 (fsconfig), Dirty Pipe, runc CVEs | T1068 |
| Capability abuse | CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN | T1548 |
| Sensitive mounts | /proc/sysrq-trigger, /proc/kcore, cgroup release_agent | T1611 |
| Namespace escape | nsenter, unshare to host namespaces | T1611 |
| Symlink/bind mount | Escape through /proc/self/root | T1611 |

### Detection Layers

1. **Syscall monitoring** - eBPF/kernel module captures syscalls in real-time
2. **File integrity** - Detect modification of escape-enabling paths
3. **Process monitoring** - Track process creation, namespace changes
4. **Network monitoring** - Detect container-to-host connections
5. **Audit logging** - Linux auditd for capability and mount operations

## Implementation Steps

### Step 1: Deploy Falco for Runtime Detection

```yaml
# falco-values.yaml for Helm deployment
falco:
  driver:
    kind: ebpf   # or modern_ebpf for kernel 5.8+
  rules_files:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/falco_rules.local.yaml
    - /etc/falco/rules.d
  json_output: true
  json_include_output_property: true
  http_output:
    enabled: true
    url: "http://falcosidekick:2801"
  grpc:
    enabled: true
  priority: warning
```

```bash
# Install Falco via Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --namespace falco-system --create-namespace \
  -f falco-values.yaml
```

### Step 2: Custom Falco Rules for Escape Detection

```yaml
# /etc/falco/rules.d/container_escape.yaml

# Detect container escape via privileged container
- rule: Container Escape via Privileged Mode
  desc: Detect attempts to escape container using privileged capabilities
  condition: >
    spawned_process and container and
    (proc.name in (nsenter, unshare, mount, umount, modprobe, insmod) or
     (proc.name = chroot and proc.args contains "/host"))
  output: >
    Container escape attempt via privileged operation
    (user=%user.name container=%container.name image=%container.image.repository
     command=%proc.cmdline pid=%proc.pid %container.info)
  priority: CRITICAL
  tags: [container, escape, T1611]

# Detect Docker socket access from container
- rule: Container Access to Docker Socket
  desc: Detect container reading/writing to Docker socket
  condition: >
    (open_read or open_write) and container and
    fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (user=%user.name container=%container.name image=%container.image.repository
     fd=%fd.name command=%proc.cmdline %container.info)
  priority: CRITICAL
  tags: [container, escape, docker_socket]

# Detect sensitive proc filesystem access
- rule: Container Access to Sensitive Proc Paths
  desc: Detect container accessing host-sensitive proc paths
  condition: >
    open_read and container and
    (fd.name startswith /proc/sysrq-trigger or
     fd.name startswith /proc/kcore or
     fd.name startswith /proc/kmsg or
     fd.name startswith /proc/kallsyms or
     fd.name startswith /sys/kernel)
  output: >
    Sensitive proc/sys access from container
    (user=%user.name container=%container.name path=%fd.name
     command=%proc.cmdline %container.info)
  priority: CRITICAL
  tags: [container, escape, proc_access]

# Detect cgroup escape technique
- rule: Container Cgroup Escape Attempt
  desc: Detect writing to cgroup release_agent (escape technique)
  condition: >
    open_write and container and
    (fd.name contains release_agent or
     fd.name contains notify_on_release)
  output: >
    Cgroup escape attempt detected
    (user=%user.name container=%container.name path=%fd.name
     command=%proc.cmdline %container.info)
  priority: CRITICAL
  tags: [container, escape, cgroup]

# Detect kernel module loading from container
- rule: Container Loading Kernel Module
  desc: Detect container attempting to load kernel modules
  condition: >
    spawned_process and container and
    (proc.name in (modprobe, insmod, rmmod) or
     (evt.type = init_module or evt.type = finit_module))
  output: >
    Kernel module load attempt from container
    (user=%user.name container=%container.name command=%proc.cmdline
     %container.info)
  priority: CRITICAL
  tags: [container, escape, kernel_module]

# Detect namespace manipulation
- rule: Container Namespace Manipulation
  desc: Detect setns/unshare syscalls from container
  condition: >
    container and (evt.type = setns or evt.type = unshare) and
    not proc.name in (containerd-shim, runc)
  output: >
    Namespace manipulation from container
    (user=%user.name container=%container.name syscall=%evt.type
     command=%proc.cmdline %container.info)
  priority: CRITICAL
  tags: [container, escape, namespace]

# Detect mount operations from container
- rule: Container Mount Sensitive Filesystem
  desc: Detect container mounting host filesystems
  condition: >
    spawned_process and container and proc.name = mount and
    (proc.args contains "/dev/" or proc.args contains "proc" or
     proc.args contains "sysfs")
  output: >
    Sensitive mount operation from container
    (user=%user.name container=%container.name command=%proc.cmdline
     %container.info)
  priority: HIGH
  tags: [container, escape, mount]
```

### Step 3: Configure Seccomp Profile for Escape Prevention

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "archMap": [
    { "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] }
  ],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "ioctl", "access",
        "pipe", "select", "sched_yield", "dup", "dup2",
        "nanosleep", "getpid", "socket", "connect", "accept",
        "sendto", "recvfrom", "bind", "listen", "getsockname",
        "getpeername", "socketpair", "setsockopt", "getsockopt",
        "clone", "fork", "vfork", "execve", "exit", "wait4",
        "kill", "getuid", "getgid", "geteuid", "getegid",
        "epoll_create", "epoll_wait", "epoll_ctl", "epoll_create1",
        "futex", "set_tid_address", "set_robust_list",
        "openat", "newfstatat", "readlinkat", "fchownat",
        "clock_gettime", "clock_getres", "clock_nanosleep",
        "getrandom", "memfd_create", "statx", "rseq"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["unshare", "setns", "mount", "umount2", "pivot_root",
                "init_module", "finit_module", "delete_module",
                "kexec_load", "kexec_file_load", "ptrace",
                "reboot", "swapon", "swapoff", "sethostname",
                "setdomainname", "keyctl", "bpf"],
      "action": "SCMP_ACT_LOG",
      "comment": "Log escape-relevant syscalls for detection"
    }
  ]
}
```

### Step 4: Audit Rules for Container Escape

```bash
# /etc/audit/rules.d/container-escape.rules

# Monitor namespace operations
-a always,exit -F arch=b64 -S setns -S unshare -k container_escape
-a always,exit -F arch=b64 -S mount -S umount2 -k container_mount
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_module
-a always,exit -F arch=b64 -S ptrace -k process_trace

# Monitor sensitive paths
-w /var/run/docker.sock -p rwxa -k docker_socket
-w /proc/sysrq-trigger -p w -k sysrq
-w /proc/kcore -p r -k kcore_read

# Monitor container runtime
-w /usr/bin/runc -p x -k container_runtime
-w /usr/bin/containerd -p x -k container_runtime
-w /usr/bin/docker -p x -k container_runtime
```

### Step 5: Real-Time Alert Pipeline

```yaml
# Falcosidekick configuration for alert routing
config:
  slack:
    webhookurl: "https://hooks.slack.com/services/xxx"
    minimumpriority: "critical"
    messageformat: |
      *Container Escape Alert*
      Rule: {{ .Rule }}
      Priority: {{ .Priority }}
      Output: {{ .Output }}

  elasticsearch:
    hostport: "https://elasticsearch:9200"
    index: "falco-alerts"
    minimumpriority: "warning"

  pagerduty:
    routingkey: "xxxx"
    minimumpriority: "critical"
```

## Validation Commands

```bash
# Test Falco rules with event generator
kubectl run falco-event-generator \
  --image=falcosecurity/event-generator \
  --restart=Never \
  -- run syscall --action PtraceAttachContainer

# Check Falco alerts
kubectl logs -n falco-system -l app.kubernetes.io/name=falco --tail=50

# Verify seccomp profile is loaded
docker inspect --format '{{.HostConfig.SecurityOpt}}' <container-id>

# Check audit logs for escape-related events
ausearch -k container_escape --interpret
```

## References

- [Falco Runtime Security](https://falco.org/docs/)
- [Container Escape Techniques - HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)
- [MITRE ATT&CK T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [Sysdig Container Security](https://sysdig.com/products/secure/)
