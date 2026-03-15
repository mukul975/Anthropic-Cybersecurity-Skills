# Workflows - Container Escape Detection

## Workflow 1: Real-Time Detection Pipeline

```
[Container Syscall] --> [eBPF/Kernel Module] --> [Falco Engine]
        |                                             |
        v                                             v
  Syscall captured                          Rule evaluation
  (setns, mount,                                  |
   ptrace, etc.)                    +-------------+-------------+
                                    |                           |
                                    v                           v
                              Match found                No match
                                    |                     (normal)
                                    v
                          [Alert Generated]
                                    |
                          +---------+---------+
                          |         |         |
                          v         v         v
                       Slack    SIEM     PagerDuty
                       Alert    Log      Incident
```

## Workflow 2: Escape Attempt Investigation

```
Step 1: Triage alert
  - Identify container, image, namespace
  - Check if container is privileged
  - Determine escape vector attempted

Step 2: Immediate containment
  - kubectl delete pod <pod-name> -n <namespace> (if active escape)
  - kubectl cordon <node> (if node compromised)
  - Network isolate the node

Step 3: Forensic collection
  - Capture container filesystem: docker export <id> > container.tar
  - Collect Falco events for timeline
  - Dump process tree: ps auxf
  - Check for new processes on host
  - Audit logs: ausearch -k container_escape

Step 4: Root cause analysis
  - Was the container privileged?
  - What capabilities were granted?
  - Was Docker socket mounted?
  - Which vulnerability was exploited?

Step 5: Remediation
  - Patch kernel/runtime vulnerability
  - Remove excessive capabilities
  - Apply PSS restricted profile
  - Update seccomp profiles
```

## Workflow 3: Proactive Escape Surface Audit

```
[Inventory all containers] --> [Check for escape risk factors]
                                        |
                            +-----------+-----------+
                            |           |           |
                            v           v           v
                     Privileged?   Docker sock?  Host NS?
                     CAP_SYS_ADMIN? mounted?     hostPID?
                            |           |           |
                            +-----------+-----------+
                                        |
                                        v
                            [Risk Score per container]
                                        |
                              +---------+---------+
                              |                   |
                              v                   v
                        HIGH risk            LOW risk
                        Remediate            Monitor
                        immediately          continuously
```
