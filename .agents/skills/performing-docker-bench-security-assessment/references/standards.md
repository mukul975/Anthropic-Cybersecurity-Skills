# Standards - Docker Bench Security Assessment

## CIS Docker Benchmark v1.8.0 Sections
| Section | Area | Checks |
|---------|------|--------|
| 1 | Host Configuration | Partition, users, audit rules |
| 2 | Docker Daemon | ICC, TLS, logging, seccomp, privileges |
| 3 | Docker Daemon Config Files | File permissions and ownership |
| 4 | Container Images | Non-root user, scanning, trusted images |
| 5 | Container Runtime | Capabilities, rootfs, resources, privileges |
| 6 | Docker Security Operations | Monitoring, CVE scanning |

## Scoring
- PASS: Check meets CIS recommendation
- FAIL: Check does not meet recommendation (remediation required)
- WARN: Check requires manual verification
- INFO: Informational, no scoring impact
