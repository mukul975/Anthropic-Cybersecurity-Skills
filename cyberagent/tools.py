"""
cyberagent/tools.py — Claude tool definitions and dispatch.

Tools available to Claude:
  search_skills       — semantic search across 754 skills
  load_skill          — load full skill content (SKILL.md + references)
  list_skill_domains  — list all subdomains with counts
  execute_skill_script — run skills/<slug>/scripts/agent.py (requires ENABLE_EXECUTION=1)
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import (
    ALLOW_LOCAL_FILE_TOOLS,
    DROPZONE_DIR,
    FILE_TOOL_EXTRA_ROOTS,
    REPO_ROOT,
    SKILLS_DIR,
    ENABLE_EXECUTION,
    SCRIPT_TIMEOUT,
)
from .retrieval import get_index
from .skill_loader import load_skill, skill_summary

log = logging.getLogger(__name__)

DEFAULT_FILE_ROOTS = [REPO_ROOT, DROPZONE_DIR]


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_file_tool_path(path: str) -> tuple[Path | None, str | None]:
    raw = Path(path).expanduser()
    candidate = raw if raw.is_absolute() else REPO_ROOT / raw
    try:
        resolved = candidate.resolve(strict=False)
    except RuntimeError as exc:
        return None, f"Error resolving path: {exc}"

    if ALLOW_LOCAL_FILE_TOOLS:
        return resolved, None

    allowed_roots = [root.expanduser().resolve(strict=False) for root in DEFAULT_FILE_ROOTS + FILE_TOOL_EXTRA_ROOTS]
    if any(_is_relative_to(resolved, root) or resolved == root for root in allowed_roots):
        return resolved, None

    roots = ", ".join(str(root) for root in allowed_roots)
    return None, (
        f"Access denied: {path} is outside allowed file-tool roots. "
        f"Allowed roots: {roots}. Set ALLOW_LOCAL_FILE_TOOLS=1 for a deliberate local override."
    )


# ---------------------------------------------------------------------------
# Tool schemas (Claude tool_use format)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "name": "search_skills",
        "description": (
            "Search the cybersecurity skills library for skills relevant to the user's request. "
            "Returns a ranked list of skill slugs and descriptions. Use this when you need to "
            "find which skills apply to the current question before loading their full content."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language description of what you're looking for.",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (1-8). Default 4.",
                    "default": 4,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "load_skill",
        "description": (
            "Load the full content of a specific skill including its workflow, API reference, "
            "and output templates. Use this after search_skills to get the complete procedure "
            "for a skill you want to apply."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "slug": {
                    "type": "string",
                    "description": "Exact skill slug (e.g. 'performing-memory-forensics-with-volatility3').",
                },
                "query": {
                    "type": "string",
                    "description": "The original user query (used to determine which reference files to include).",
                    "default": "",
                },
            },
            "required": ["slug"],
        },
    },
    {
        "name": "list_skill_domains",
        "description": (
            "List all cybersecurity skill domains/subdomains with their skill counts. "
            "Use this when the user asks 'what can you do?' or 'what skills do you have in X area?'"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Optional: filter domains by substring match (e.g. 'cloud', 'forensic').",
                    "default": "",
                },
            },
        },
    },
    {
        "name": "execute_skill_script",
        "description": (
            "Execute a skill's agent script to perform an actual security task. "
            "IMPORTANT: Only use this when the user explicitly asks to run/execute something "
            "AND has provided written authorization confirmation. "
            "Requires ENABLE_EXECUTION=1 environment variable. "
            "Returns the script's stdout/stderr output."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "slug": {
                    "type": "string",
                    "description": "Skill slug to execute.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Command-line arguments to pass to the script.",
                    "default": [],
                },
            },
            "required": ["slug"],
        },
    },
    {
        "name": "read_file",
        "description": "Read the contents of a local file. Use this for auditing code or inspecting system logs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the file to read.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_dir",
        "description": "List the contents of a local directory. Use this to find files for auditing.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the directory to list.",
                    "default": ".",
                }
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def dispatch(tool_name: str, tool_input: dict) -> str:
    """
    Route a Claude tool_use call to the appropriate function.
    Returns a string result (always — Claude expects text).
    """
    try:
        if tool_name == "search_skills":
            return _search_skills(**tool_input)
        if tool_name == "load_skill":
            return _load_skill(**tool_input)
        if tool_name == "list_skill_domains":
            return _list_domains(**tool_input)
        if tool_name == "execute_skill_script":
            return _execute_script(**tool_input)
        if tool_name == "read_file":
            return _read_file(**tool_input)
        if tool_name == "list_dir":
            return _list_dir(**tool_input)
        return f"Unknown tool: {tool_name}"
    except Exception as e:
        log.exception("Tool dispatch error for %s", tool_name)
        return f"Tool error: {e}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _search_skills(query: str, top_k: int = 4) -> str:
    idx = get_index()
    top_k = max(1, min(top_k, 8))
    results = idx.search(query, top_k=top_k)
    if not results:
        return "No matching skills found."
    lines = ["Found skills:"]
    for i, s in enumerate(results, 1):
        lines.append(
            f"  {i}. {s['slug']}\n"
            f"     Domain: {s.get('subdomain', '?')}\n"
            f"     {s.get('description', '')[:120]}..."
        )
    return "\n".join(lines)


def _load_skill(slug: str, query: str = "") -> str:
    idx = get_index()
    skill = idx.get_by_slug(slug)
    if not skill:
        # Try fuzzy: find closest slug
        matches = idx.search(slug, top_k=3)
        if matches:
            suggestion = matches[0]["slug"]
            return (
                f"Skill '{slug}' not found. Did you mean '{suggestion}'? "
                f"Try load_skill with slug='{suggestion}'."
            )
        return f"Skill '{slug}' not found and no close matches."
    return load_skill(skill, query)


def _list_domains(filter: str = "") -> str:
    idx = get_index()
    domains = idx.all_subdomains()
    if filter:
        domains = {k: v for k, v in domains.items() if filter.lower() in k}
    if not domains:
        return f"No domains matching '{filter}'."
    lines = [f"Available skill domains ({sum(domains.values())} total skills):"]
    for domain, count in domains.items():
        lines.append(f"  {domain:<35} {count:>3} skills")
    return "\n".join(lines)


def _execute_script(slug: str, args: list[str] | None = None) -> str:
    if not ENABLE_EXECUTION:
        return (
            "Script execution is disabled. "
            "Set ENABLE_EXECUTION=1 to allow running skill scripts. "
            "I can still walk you through the commands to run manually."
        )

    args = args or []
    script_path = SKILLS_DIR / slug / "scripts" / "agent.py"
    if not script_path.exists():
        return f"No executable script found for skill '{slug}' at {script_path}."

    # Basic arg validation — no shell metacharacters
    for arg in args:
        if any(c in arg for c in (";", "|", "&", "`", "$", ">", "<")):
            return f"Invalid argument (contains shell metacharacters): {arg!r}"

    cmd = [sys.executable, str(script_path)] + args
    log.info("Executing: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT,
        )
        output = result.stdout + (("\n--- stderr ---\n" + result.stderr) if result.stderr else "")
        # Truncate to avoid overwhelming context
        if len(output) > 8000:
            output = output[:8000] + f"\n... [truncated — {len(output)} chars total]"
        return output if output.strip() else "(script produced no output)"
    except subprocess.TimeoutExpired:
        return f"Script timed out after {SCRIPT_TIMEOUT}s."
    except Exception as e:
        return f"Execution error: {e}"


def _read_file(path: str) -> str:
    try:
        p, error = _resolve_file_tool_path(path)
        if error:
            return error
        assert p is not None
        if not p.exists():
            return f"Error: File not found: {path}"
        if not p.is_file():
            return f"Error: Path is not a file: {path}"
        content = p.read_text()
        if len(content) > 15000:
            return content[:15000] + "\n... [truncated]"
        return content
    except Exception as e:
        return f"Error reading file: {e}"


def _list_dir(path: str = ".") -> str:
    try:
        p, error = _resolve_file_tool_path(path)
        if error:
            return error
        assert p is not None
        if not p.exists():
            return f"Error: Directory not found: {path}"
        if not p.is_dir():
            return f"Error: Path is not a directory: {path}"
        items = list(p.iterdir())
        lines = [f"Contents of {path}:"]
        for item in sorted(items, key=lambda x: (not x.is_dir(), x.name.lower())):
            prefix = "[DIR] " if item.is_dir() else "[FILE]"
            lines.append(f"  {prefix} {item.name}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing directory: {e}"
