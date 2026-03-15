# API Reference — Performing Docker Bench Security Assessment

## Libraries Used
- **subprocess**: Run docker-bench-security container and docker inspect commands
- **json**: Parse docker inspect JSON output

## CLI Interface

```
python agent.py bench        # Run full docker-bench-security
python agent.py containers   # Check running container configurations
```

## Core Functions

### `run_docker_bench()`
Runs the docker/docker-bench-security container with host access for CIS benchmark checks.

### `parse_bench_output(output)`
Parses [WARN], [PASS], [NOTE] lines into structured findings with sections.

### `check_container_configs()`
Inspects all running containers for CIS Docker Benchmark violations.

### CIS Checks Performed on Containers

| Check | CIS ID | Severity |
|-------|--------|----------|
| Privileged mode | 5.4 | CRITICAL |
| Host PID namespace | 5.15 | HIGH |
| Host network namespace | 5.13 | HIGH |
| Dangerous capabilities | 5.3 | HIGH |
| Running as root | 4.1 | MEDIUM |
| Sensitive host mounts | 5.5 | HIGH |

## Dependencies
Docker must be installed and accessible. No Python packages required beyond stdlib.
