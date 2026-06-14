#!/usr/bin/env python3
"""
run_mcp.py — MCP server exposing the cybersecurity skills library as tools.

Adds three tools to any MCP-compatible agent:
  search_cybersecurity_skills(query, top_k)  — semantic skill search
  load_cybersecurity_skill(slug)             — full skill content
  list_skill_domains(filter)                 — domain catalog with counts

To add to Gemini CLI, append to ~/.gemini/settings.json:
    {
      "mcpServers": {
        "cybersecurity-skills": {
          "command": "python3",
          "args": ["/Users/stephengodman/AI/agent-frameworks/Anthropic-Cybersecurity-Skills/run_mcp.py"]
        }
      }
    }

Then in any Gemini CLI session, these tools are available natively.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("ERROR: mcp not installed. Run: pip3 install mcp --break-system-packages", file=sys.stderr)
    sys.exit(1)

from cyberagent.retrieval import get_index
from cyberagent.skill_loader import load_skill

# Pre-warm index
_idx = get_index()

mcp = FastMCP(
    "cybersecurity-skills",
    instructions=(
        "Provides access to 754 structured cybersecurity skills mapped to "
        "MITRE ATT&CK, NIST CSF 2.0, ATLAS, D3FEND, and NIST AI RMF. "
        "Use search_cybersecurity_skills to find relevant skills, then "
        "load_cybersecurity_skill to get the full workflow and tool reference."
    ),
)


@mcp.tool()
def search_cybersecurity_skills(query: str, top_k: int = 5) -> str:
    """
    Search the 754-skill cybersecurity library by semantic similarity.

    Args:
        query:  Natural language description of the security task or question.
        top_k:  Number of results to return (1–10). Default 5.

    Returns:
        Ranked list of matching skills with slug, domain, and description.
    """
    top_k = max(1, min(top_k, 10))
    results = _idx.search(query, top_k=top_k)
    if not results:
        return f"No skills found matching: {query!r}"

    lines = [f"Top {len(results)} skills for: '{query}'\n"]
    for i, s in enumerate(results, 1):
        tags = ", ".join(s.get("tags", [])[:4])
        desc = s.get("description", "")[:120]
        lines.append(
            f"{i}. {s['slug']}\n"
            f"   Domain: {s.get('subdomain', '?')}\n"
            f"   Tags:   {tags}\n"
            f"   {desc}...\n"
        )
    return "\n".join(lines)


@mcp.tool()
def load_cybersecurity_skill(slug: str) -> str:
    """
    Load the full content of a specific cybersecurity skill.

    Includes the skill's complete workflow, tool commands with exact flags,
    API reference, output templates, and MITRE/NIST framework mappings.

    Args:
        slug: Exact skill slug (e.g. 'performing-memory-forensics-with-volatility3').
              Use search_cybersecurity_skills first to find the correct slug.

    Returns:
        Full skill documentation as Markdown.
    """
    skill = _idx.get_by_slug(slug)
    if not skill:
        # Try fuzzy
        matches = _idx.search(slug, top_k=3)
        if matches:
            suggestions = ", ".join(m["slug"] for m in matches[:3])
            return f"Skill '{slug}' not found. Closest matches: {suggestions}"
        return f"Skill '{slug}' not found."
    return load_skill(skill)


@mcp.tool()
def list_skill_domains(filter: str = "") -> str:
    """
    List all cybersecurity skill domains with their skill counts.

    Use this to discover what areas the skill library covers before searching.

    Args:
        filter: Optional substring to filter domain names (e.g. 'cloud', 'forensic').

    Returns:
        Table of domains and skill counts.
    """
    domains = _idx.all_subdomains()
    if filter:
        domains = {k: v for k, v in domains.items() if filter.lower() in k}
    if not domains:
        return f"No domains matching '{filter}'."

    lines = [f"Cybersecurity skill domains ({sum(domains.values())} skills total):\n"]
    for domain, count in domains.items():
        lines.append(f"  {domain:<38} {count:>3} skills")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
