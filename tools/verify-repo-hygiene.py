#!/usr/bin/env python3
"""Verify commit-surface hygiene for the local cyberagent repo."""

from __future__ import annotations

import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_TRACKED_PREFIXES = (
    "data/",
    ".venv/",
    ".playwright-mcp/",
    "security-lab/",
    "havoc-c2-lab/",
    "control-room/",
)

FORBIDDEN_TRACKED_EXACT = {
    "CLAUDE_CLEANUP_BRIEF.md",
}

REQUIRED_IGNORED_PATHS = (
    "data/.env",
    ".venv",
    ".playwright-mcp",
    "security-lab",
    "havoc-c2-lab",
    "control-room",
    "CLAUDE_CLEANUP_BRIEF.md",
    "cyberagent/skills/personas/gunner.md",
)

SECRET_PATTERNS = (
    ("anthropic-api-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{20,}")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("hardcoded-password", re.compile(r"(?i)\bpassword\s*=\s*['\"][^'\"]{8,}['\"]")),
)

PLACEHOLDER_MARKERS = (
    "sk-ant-...",
    "<token>",
    "TOKEN",
    "USER_TOKEN",
    "ACCESS_TOKEN",
    "invalid_token",
    "wrongpassword",
    "example",
    "placeholder",
    "PEM format",
)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def run_git(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=check,
    )


def tracked_files() -> list[str]:
    proc = run_git(["ls-files"])
    return [line for line in proc.stdout.splitlines() if line]


def check_forbidden_tracked(paths: list[str]) -> Check:
    bad = [
        path
        for path in paths
        if path in FORBIDDEN_TRACKED_EXACT
        or any(path.startswith(prefix) for prefix in FORBIDDEN_TRACKED_PREFIXES)
        or path.endswith((".env", ".pyc", ".DS_Store"))
        or path.endswith(("sessions.db", "embeddings.npy"))
    ]
    return Check("forbidden-tracked-paths", not bad, ", ".join(bad[:20]) or "none")


def check_required_ignores() -> Check:
    missing: list[str] = []
    for path in REQUIRED_IGNORED_PATHS:
        proc = run_git(["check-ignore", path], check=False)
        if proc.returncode != 0:
            missing.append(path)
    return Check("required-ignore-rules", not missing, ", ".join(missing) or "all required paths ignored")


def line_is_placeholder(line: str) -> bool:
    return any(marker in line for marker in PLACEHOLDER_MARKERS)


def check_secret_patterns(paths: list[str]) -> Check:
    findings: list[str] = []
    for rel_path in paths:
        path = REPO_ROOT / rel_path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except UnicodeDecodeError:
            continue
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if line_is_placeholder(line):
                continue
            for label, pattern in SECRET_PATTERNS:
                if rel_path.startswith("skills/") and label in {"hardcoded-password", "private-key-block"}:
                    continue
                if pattern.search(line):
                    findings.append(f"{rel_path}:{line_no}:{label}")
                    break
    return Check("high-confidence-secret-patterns", not findings, ", ".join(findings[:20]) or "none")


def check_env_mode() -> Check:
    env_path = REPO_ROOT / "data" / ".env"
    if not env_path.exists():
        return Check("data-env-mode", True, "data/.env absent")
    mode = stat.S_IMODE(env_path.stat().st_mode)
    return Check("data-env-mode", mode == 0o600, oct(mode))


def main() -> int:
    paths = tracked_files()
    checks = [
        check_forbidden_tracked(paths),
        check_required_ignores(),
        check_secret_patterns(paths),
        check_env_mode(),
    ]
    ok = all(check.ok for check in checks)
    for check in checks:
        status = "PASS" if check.ok else "FAIL"
        print(f"{status} {check.name}: {check.detail}")
    print(f"RESULT {'pass' if ok else 'fail'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
