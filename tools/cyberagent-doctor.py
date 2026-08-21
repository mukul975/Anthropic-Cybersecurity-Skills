#!/usr/bin/env python3
"""Run the cyberagent verification stack from one command.

Default mode is CI-safe and local-only. Use ``--live`` when provider-backed
Gemini checks should run too.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_ENV = REPO_ROOT / "data" / ".env"
DEFAULT_BACKEND = "gemini"
QUICK_DUMMY_GEMINI_KEY = "ci-local-verification-only"


@dataclass(frozen=True)
class Check:
    name: str
    command: list[str]
    live: bool = False
    env: dict[str, str] | None = None


@dataclass
class Result:
    name: str
    command: list[str]
    exit_code: int
    elapsed_seconds: float


def load_env_file() -> dict[str, str]:
    env: dict[str, str] = {}
    if not DATA_ENV.exists():
        return env
    for line in DATA_ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env.setdefault(key.strip(), value.strip())
    return env


def select_python(explicit_python: str | None) -> str:
    if explicit_python:
        return explicit_python

    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists() and os.access(venv_python, os.X_OK):
        return str(venv_python)

    return sys.executable


def check_plan(python: str) -> list[Check]:
    return [
        Check(
            name="repo hygiene",
            command=[python, "tools/verify-repo-hygiene.py"],
        ),
        Check(
            name="runtime guardrails",
            command=[python, "tools/verify-runtime-guardrails.py"],
        ),
        Check(
            name="agent e2e quick",
            command=[python, "tools/verify-agent-e2e.py", "--mode", "quick", "--json"],
            env={"AGENT_BACKEND": DEFAULT_BACKEND, "GEMINI_API_KEY": QUICK_DUMMY_GEMINI_KEY},
        ),
        Check(
            name="skill validation",
            command=[python, "tools/validate-skill.py", "--all"],
        ),
        Check(
            name="agent e2e full exact-load-skill",
            command=[python, "tools/verify-agent-e2e.py", "--mode", "full", "--json"],
            live=True,
            env={"AGENT_BACKEND": DEFAULT_BACKEND},
        ),
        Check(
            name="agent e2e full search-then-load",
            command=[
                python,
                "tools/verify-agent-e2e.py",
                "--mode",
                "full",
                "--scenario",
                "search-then-load",
                "--json",
            ],
            live=True,
            env={"AGENT_BACKEND": DEFAULT_BACKEND},
        ),
    ]


def merged_env(base_env: dict[str, str], check: Check, live: bool) -> dict[str, str]:
    env = os.environ.copy()
    for key, value in base_env.items():
        env.setdefault(key, value)

    if check.env:
        for key, value in check.env.items():
            if live and key.endswith("_API_KEY"):
                env.setdefault(key, value)
            else:
                env[key] = value

    return env


def run_check(check: Check, env: dict[str, str], timeout: int, verbose: bool) -> Result:
    print(f"\n==> {check.name}")
    print("$ " + " ".join(check.command))
    sys.stdout.flush()
    started = time.monotonic()
    proc = subprocess.run(
        check.command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    elapsed = time.monotonic() - started
    status = "PASS" if proc.returncode == 0 else "FAIL"
    if verbose or proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout.rstrip())
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
    print(f"{status} {check.name} ({elapsed:.1f}s)")
    return Result(
        name=check.name,
        command=check.command,
        exit_code=proc.returncode,
        elapsed_seconds=elapsed,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run cyberagent verification checks")
    parser.add_argument("--live", action="store_true", help="include live Gemini/provider E2E checks")
    parser.add_argument("--python", default=None, help="Python executable to use for child checks")
    parser.add_argument("--timeout", type=int, default=600, help="timeout per check in seconds")
    parser.add_argument("--verbose", action="store_true", help="print child check output even when checks pass")
    args = parser.parse_args()

    python = select_python(args.python)
    checks = [check for check in check_plan(python) if args.live or not check.live]
    base_env = load_env_file() if args.live else {}

    print("Cyberagent doctor")
    print(f"repo: {REPO_ROOT}")
    print(f"python: {python}")
    print(f"mode: {'live' if args.live else 'local'}")

    results: list[Result] = []
    for check in checks:
        env = merged_env(base_env, check, args.live)
        try:
            result = run_check(check, env, args.timeout, args.verbose)
        except subprocess.TimeoutExpired:
            print(f"FAIL {check.name}: timed out after {args.timeout}s")
            return 1
        results.append(result)
        if result.exit_code != 0:
            break

    print("\nSummary")
    for result in results:
        status = "PASS" if result.exit_code == 0 else "FAIL"
        print(f"{status} {result.name} ({result.elapsed_seconds:.1f}s)")

    ok = len(results) == len(checks) and all(result.exit_code == 0 for result in results)
    print(f"RESULT {'pass' if ok else 'fail'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
