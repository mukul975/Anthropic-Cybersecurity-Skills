#!/usr/bin/env python3
"""Regenerate the contributor avatar wall in README.md from the GitHub API.

Writes between the markers:

    <!-- contributors:start -->
    ...generated...
    <!-- contributors:end -->

Run by .github/workflows/sync-generated.yml on every push to main and weekly.

Avatars are served from github.com/<login>.png rather than a third-party
contributor-image service. That is deliberate: a README image is fetched on
every page view, so an external host would be an uncontrolled dependency in the
most-viewed file in the repository. GitHub's own avatar endpoint has neither
problem, and GitHub proxies it through camo like any other image.

Usage:
    python tools/update-contributors.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

REPO = os.environ.get("GITHUB_REPOSITORY", "mukul975/Anthropic-Cybersecurity-Skills")
MAINTAINER = REPO.split("/")[0]
README = "README.md"

START = "<!-- contributors:start -->"
END = "<!-- contributors:end -->"

# How many recent commits to scan for people /contributors has not caught up
# with yet. Its cache lags about a day; 200 commits is far more than a day.
RECENT_COMMITS_PAGES = 2
PER_PAGE = 100

AVATAR_PX = 72


def _get(path: str):
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}/{path}", headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "update-contributors",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def _is_human(account: dict | None) -> bool:
    """True for a real user account. GitHub Apps are type Bot and named *[bot]."""
    if not account or not account.get("login"):
        return False
    return account.get("type") != "Bot" and not account["login"].endswith("[bot]")


def fetch_contributors() -> list[tuple[str, int]]:
    """(login, contributions) for every human contributor, most first.

    Two endpoints, because one of them is cached. /contributors has lifetime
    counts but can lag a merge by up to a day. /commits is live. Counting a
    person's recent commits too means a new contributor shows up on the first
    run after their merge. For anyone in both, the larger count wins, which
    is the lifetime count once /contributors catches up.

    Commits authored with an unlinkable email (a machine hostname such as
    user@HOST.localdomain) have no `author` object and are skipped. They never
    appear in GitHub's own contributor graph either, so the wall matches it.
    """
    counts: dict[str, int] = {}

    page = 1
    while True:
        batch = _get(f"contributors?per_page={PER_PAGE}&page={page}")
        for person in batch:
            if _is_human(person):
                counts[person["login"]] = person["contributions"]
        if len(batch) < PER_PAGE:
            break
        page += 1

    recent: dict[str, int] = {}
    for page in range(1, RECENT_COMMITS_PAGES + 1):
        for commit in _get(f"commits?per_page={PER_PAGE}&page={page}"):
            author = commit.get("author")
            if _is_human(author):
                recent[author["login"]] = recent.get(author["login"], 0) + 1
    for login, count in recent.items():
        counts[login] = max(counts.get(login, 0), count)

    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))


def render(people: list[tuple[str, int]]) -> str:
    lines = ['<p align="center">']
    for login, count in people:
        plural = "" if count == 1 else "s"
        title = f"{login} — maintainer" if login == MAINTAINER else f"{login} — {count} contribution{plural}"
        lines.append(
            f'<a href="https://github.com/{login}" title="{title}">'
            f'<img src="https://github.com/{login}.png?size=100" '
            f'width="{AVATAR_PX}" height="{AVATAR_PX}" alt="@{login}"></a>'
        )
    lines.append("</p>")
    lines.append("")
    lines.append(
        f'<p align="center"><sub>{len(people)} contributors, ordered by contribution count · '
        f'see the full <a href="https://github.com/{REPO}/graphs/contributors">contributor graph</a>'
        "</sub></p>"
    )
    return "\n".join(lines)


def splice(readme: str, block: str) -> str:
    if START not in readme or END not in readme:
        raise SystemExit(
            f"ERROR: {README} is missing the {START} / {END} markers. "
            "Add them around the contributor wall."
        )
    head, rest = readme.split(START, 1)
    _, tail = rest.split(END, 1)
    return f"{head}{START}\n{block}\n{END}{tail}"


def main() -> int:
    if not os.path.isfile(README):
        print(f"ERROR: {README} not found. Run from the repository root.")
        return 1

    people = fetch_contributors()
    if not people:
        print("ERROR: the API returned no contributors; refusing to blank the section.")
        return 1

    with open(README, encoding="utf-8") as handle:
        current = handle.read()
    updated = splice(current, render(people))

    if updated == current:
        print(f"OK: contributor wall is current ({len(people)} contributors)")
        return 0

    with open(README, "w", encoding="utf-8", newline="") as handle:
        handle.write(updated)
    print(f"Updated contributor wall: {len(people)} contributors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
