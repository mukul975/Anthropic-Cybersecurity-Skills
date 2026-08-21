#!/usr/bin/env python3
"""Show whether local commits are ready to publish to GitHub.

This helper is read-only. It never pushes, stages, commits, or fetches.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = "origin/main"
DEFAULT_REMOTE = "origin"


@dataclass(frozen=True)
class GitResult:
    code: int
    stdout: str
    stderr: str


def git(args: list[str], check: bool = False) -> GitResult:
    proc = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return GitResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())


def rev_parse(ref: str) -> str | None:
    result = git(["rev-parse", "--abbrev-ref", ref])
    return result.stdout if result.code == 0 and result.stdout else None


def commit_count(revision_range: str) -> int | None:
    result = git(["rev-list", "--count", revision_range])
    if result.code != 0:
        return None
    try:
        return int(result.stdout)
    except ValueError:
        return None


def ahead_behind(upstream: str) -> tuple[int, int] | None:
    result = git(["rev-list", "--left-right", "--count", f"{upstream}...HEAD"])
    if result.code != 0:
        return None
    parts = result.stdout.split()
    if len(parts) != 2:
        return None
    try:
        behind = int(parts[0])
        ahead = int(parts[1])
    except ValueError:
        return None
    return ahead, behind


def current_state(base: str, remote: str) -> dict:
    inside = git(["rev-parse", "--is-inside-work-tree"]).stdout == "true"
    if not inside:
        raise RuntimeError(f"{REPO_ROOT} is not inside a git repository")

    branch = git(["branch", "--show-current"], check=True).stdout
    status = git(["status", "--porcelain"], check=True).stdout.splitlines()
    upstream = rev_parse("@{upstream}")
    remote_url = git(["remote", "get-url", "--push", remote]).stdout or None
    base_exists = git(["rev-parse", "--verify", "--quiet", base]).code == 0

    state = {
        "branch": branch,
        "remote": remote,
        "remote_url": remote_url,
        "base": base if base_exists else None,
        "upstream": upstream,
        "working_tree_clean": not status,
        "changed_paths": status,
        "ahead": None,
        "behind": None,
        "local_commits_vs_base": None,
        "suggested_push": None,
        "ready_to_push": False,
    }

    if upstream:
        counts = ahead_behind(upstream)
        if counts:
            state["ahead"], state["behind"] = counts
    elif base_exists:
        state["local_commits_vs_base"] = commit_count(f"{base}..HEAD")

    if branch:
        state["suggested_push"] = (
            f"git push {remote} {branch}"
            if upstream
            else f"git push -u {remote} {branch}"
        )

    has_local_work = bool(state["ahead"]) or bool(state["local_commits_vs_base"])
    state["ready_to_push"] = bool(state["working_tree_clean"] and branch and has_local_work)
    return state


def print_text(state: dict) -> None:
    print("Publish status")
    print(f"branch: {state['branch'] or '(detached)'}")
    print(f"remote: {state['remote']} ({state['remote_url'] or 'missing push URL'})")
    print(f"working tree: {'clean' if state['working_tree_clean'] else 'dirty'}")

    if state["upstream"]:
        print(f"upstream: {state['upstream']}")
        print(f"ahead: {state['ahead'] if state['ahead'] is not None else 'unknown'}")
        print(f"behind: {state['behind'] if state['behind'] is not None else 'unknown'}")
    else:
        print("upstream: none")
        if state["base"]:
            print(f"local commits vs {state['base']}: {state['local_commits_vs_base']}")
        else:
            print("local commits vs base: unknown")

    if not state["working_tree_clean"]:
        print("\nNot ready to push yet: there are uncommitted file changes.")
        for path in state["changed_paths"][:20]:
            print(f"  {path}")
        if len(state["changed_paths"]) > 20:
            print(f"  ... {len(state['changed_paths']) - 20} more")
        return

    if state["ready_to_push"]:
        print("\nReady to publish this branch.")
        print(f"next command: {state['suggested_push']}")
        if not state["upstream"]:
            print("note: -u sets the GitHub tracking branch so future status is clearer.")
    else:
        print("\nNothing obvious to publish from this branch.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Show Git publish readiness")
    parser.add_argument("--base", default=DEFAULT_BASE, help="base branch used when no upstream exists")
    parser.add_argument("--remote", default=DEFAULT_REMOTE, help="remote name to publish to")
    parser.add_argument("--json", action="store_true", help="print machine-readable state")
    args = parser.parse_args()

    state = current_state(args.base, args.remote)
    if args.json:
        print(json.dumps(state, indent=2))
    else:
        print_text(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
