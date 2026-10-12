#!/usr/bin/env python3
"""Compile every helper script so a broken one cannot ship.

SCOPE.md requires that every script in the catalogue runs: "Real commands,
real flags, real tool names, real paths. No placeholders." Nothing in CI
checked that, so a script that does not even parse could merge -- and one
did (process.py in building-vulnerability-dashboard-with-defectdojo declared
`global` after the name was used, a hard SyntaxError that made the file
impossible to import or run).

This is the cheapest possible guard against that class of rot: it compiles
every `scripts/*.py` with the builtin compile() -- which runs both the parser
and the symbol-table pass (so it catches not just bad syntax but errors like
"name assigned before global declaration", the exact DefectDojo bug) without
importing the module, running any code, or writing a .pyc file -- and, when a
PowerShell parser (pwsh) is available, syntax-checks every `scripts/*.ps1`
too. It does NOT execute scripts, resolve imports, or judge behaviour; it
only proves the source is compilable.

Pure stdlib; no third-party dependency.

Usage:
    python tools/check-scripts.py                 # check every skill
    python tools/check-scripts.py --all           # same, explicit
    python tools/check-scripts.py skills/foo/      # one skill directory
    python tools/check-scripts.py --json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import warnings

try:
    from skill_frontmatter import iter_skill_dirs
except ModuleNotFoundError:  # allow `python tools/check-scripts.py` from repo root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from skill_frontmatter import iter_skill_dirs

RED, GREEN, YELLOW, DIM, RESET = (
    "\033[91m",
    "\033[92m",
    "\033[93m",
    "\033[2m",
    "\033[0m",
)


def _script_files(skill_dir: str):
    """Yield paths of helper scripts under <skill_dir>/scripts/, sorted."""
    scripts_dir = os.path.join(skill_dir, "scripts")
    if not os.path.isdir(scripts_dir):
        return
    for name in sorted(os.listdir(scripts_dir)):
        path = os.path.join(scripts_dir, name)
        if os.path.isfile(path) and name.endswith((".py", ".ps1")):
            yield path


def check_python(path: str) -> str | None:
    """Return an error string if the .py file does not compile, else None.

    Uses compile() rather than ast.parse() so the symbol-table pass runs:
    that is what catches errors like "name assigned before global
    declaration". Compiling to a code object neither executes the module nor
    writes a .pyc file.
    """
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    try:
        # A SyntaxWarning (e.g. an invalid escape sequence) is a style issue,
        # not a compile failure; this gate only cares that the source loads.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            compile(source, path, "exec", dont_inherit=True)
    except SyntaxError as exc:
        where = f"line {exc.lineno}" if exc.lineno else "unknown line"
        return f"{where}: {exc.msg}"
    return None


def check_powershell(path: str, pwsh: str) -> str | None:
    """Return an error string if pwsh cannot parse the .ps1 file, else None."""
    # Tokenize+parse with the PowerShell parser; no script body is executed.
    cmd = (
        "$ErrorActionPreference='Stop';"
        "$tokens=$null;$errors=$null;"
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}',[ref]$tokens,[ref]$errors)|Out-Null;"
        "if($errors){$errors|ForEach-Object{$_.Message};exit 1}"
    )
    proc = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        msg = (proc.stdout or proc.stderr or "parse error").strip().splitlines()
        return msg[0] if msg else "parse error"
    return None


def collect_skill_dirs(targets: list[str]) -> list[tuple[str, str]]:
    """Resolve CLI targets to (slug, skill_dir) pairs."""
    if not targets:
        return list(iter_skill_dirs())
    pairs = []
    for t in targets:
        t = t.rstrip("/")
        slug = os.path.basename(t)
        if not os.path.isdir(t):
            print(f"{RED}FAIL{RESET} no such skill directory: {t}", file=sys.stderr)
            sys.exit(2)
        pairs.append((slug, t))
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile-check every scripts/*.py (and *.ps1 when pwsh exists)."
    )
    parser.add_argument("targets", nargs="*", help="skill directories; default is all")
    parser.add_argument("--all", action="store_true", help="check every skill (default)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    pwsh = shutil.which("pwsh")
    pairs = collect_skill_dirs([] if args.all else args.targets)

    failures: list[tuple[str, str]] = []
    checked_py = checked_ps1 = skipped_ps1 = 0

    for _slug, skill_dir in pairs:
        for path in _script_files(skill_dir):
            if path.endswith(".py"):
                checked_py += 1
                err = check_python(path)
            else:  # .ps1
                if not pwsh:
                    skipped_ps1 += 1
                    continue
                checked_ps1 += 1
                err = check_powershell(path, pwsh)
            if err:
                failures.append((path, err))

    if args.json:
        print(
            json.dumps(
                {
                    "checked_python": checked_py,
                    "checked_powershell": checked_ps1,
                    "skipped_powershell": skipped_ps1,
                    "failures": [{"path": p, "error": e} for p, e in failures],
                },
                indent=2,
            )
        )
        return 1 if failures else 0

    for path, err in failures:
        print(f"{RED}FAIL{RESET} {path}: {YELLOW}{err}{RESET}")

    checked = checked_py + checked_ps1
    if skipped_ps1:
        print(
            f"{DIM}note: pwsh not found; skipped {skipped_ps1} "
            f"PowerShell script(s){RESET}"
        )
    print("=" * 50)
    status = f"{GREEN}OK{RESET}" if not failures else f"{RED}{len(failures)} FAILED{RESET}"
    print(f"Scripts checked: {checked}  ({checked_py} py, {checked_ps1} ps1)  {status}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
