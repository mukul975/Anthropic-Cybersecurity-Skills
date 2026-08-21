#!/usr/bin/env python3
"""Verify runtime safety guardrails without requiring a live LLM backend."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    suffix = f": {detail}" if detail else ""
    print(f"{status} {name}{suffix}")
    return ok


def expect_runtime_error(name: str, func, expected: str) -> bool:
    try:
        func()
    except RuntimeError as exc:
        return check(name, expected in str(exc), str(exc))
    return check(name, False, "expected RuntimeError")


def main() -> int:
    sys.path.insert(0, str(REPO_ROOT))

    from cyberagent.config import validate_api_security_config
    from cyberagent.tools import _list_dir, _read_file

    results = [
        check(
            "repo-file-read-allowed",
            _read_file("README.md").startswith("<p align=\"center\">"),
        ),
        check(
            "repo-dir-list-allowed",
            _list_dir("cyberagent").startswith("Contents of"),
        ),
        check(
            "home-file-read-denied",
            _read_file("/Users/stephengodman/.ssh/config").startswith("Access denied"),
        ),
        expect_runtime_error(
            "lan-bind-requires-token",
            lambda: validate_api_security_config(host="0.0.0.0", token=""),
            "Refusing to bind beyond localhost",
        ),
        expect_runtime_error(
            "wildcard-cors-with-credentials-denied",
            lambda: _run_config_check({"API_CORS_ORIGINS": "*", "API_CORS_ALLOW_CREDENTIALS": "1"}),
            "Refusing wildcard CORS with credentials enabled",
        ),
    ]

    proc = subprocess.run(
        [sys.executable, "-c", "from cyberagent.tools import _read_file; print(_read_file('/etc/hosts').splitlines()[0])"],
        cwd=REPO_ROOT,
        env={**os.environ, "ALLOW_LOCAL_FILE_TOOLS": "1"},
        text=True,
        capture_output=True,
        check=False,
    )
    results.append(check("file-tool-override-allows-system-file", proc.returncode == 0 and not proc.stdout.startswith("Access denied")))

    ok = all(results)
    print(f"RESULT {'pass' if ok else 'fail'}")
    return 0 if ok else 1


def _run_config_check(env_updates: dict[str, str]) -> None:
    code = (
        "from cyberagent.config import validate_api_security_config; "
        "validate_api_security_config()"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env={**os.environ, **env_updates},
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode == 0:
        return
    text = (proc.stderr or proc.stdout).strip()
    raise RuntimeError(text.splitlines()[-1] if text else f"exit {proc.returncode}")


if __name__ == "__main__":
    raise SystemExit(main())
