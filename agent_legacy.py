#!/usr/bin/env python3
"""
Cybersecurity Skills Agent
--------------------------
A conversational AI agent backed by 754 structured cybersecurity skills.
Dynamically retrieves relevant SKILL.md files and answers as a senior analyst.

Usage:
    python3 agent.py                          # interactive REPL
    python3 agent.py -q "how do I triage XSS" # single query
    ANTHROPIC_API_KEY=sk-... python3 agent.py

Env vars:
    ANTHROPIC_API_KEY   — required
    SKILLS_DIR          — path to skills/ directory (default: auto-detect)
    AGENT_MODEL         — claude model to use (default: claude-sonnet-4-5)
    MAX_SKILLS          — max skills to load per query (default: 4)
    VERBOSE             — set to 1 to show which skills are loaded
"""

import os
import sys
import re
import json
import glob
import argparse
import textwrap
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SKILLS_DIR = SCRIPT_DIR / "skills"
MODEL = os.environ.get("AGENT_MODEL", "claude-sonnet-4-5")
MAX_SKILLS = int(os.environ.get("MAX_SKILLS", "4"))
VERBOSE = os.environ.get("VERBOSE", "0") == "1"

SYSTEM_PROMPT = """\
You are a senior cybersecurity analyst and operator with deep expertise across:
penetration testing, threat hunting, incident response, digital forensics, \
cloud security, malware analysis, red teaming, threat intelligence, \
SOC operations, vulnerability management, and OT/ICS security.

You have access to a structured library of 754 cybersecurity skills mapped \
to MITRE ATT&CK v18, NIST CSF 2.0, MITRE ATLAS v5.4, MITRE D3FEND v1.3, \
and NIST AI RMF 1.0. When relevant skill procedures are provided to you in \
the <SKILLS> block, use them as your authoritative operational guide.

Operating rules:
- Lead with action. Give exact commands, tool syntax, and step-by-step \
procedures — not vague guidance.
- When a skill workflow exists, follow it precisely. Cite the skill name.
- Flag legal/ethical constraints when relevant (authorization requirements, \
responsible disclosure, etc.).
- Format output clearly: use numbered steps, code blocks for commands, \
tables for comparisons.
- If the user's request is outside the loaded skills, answer from your \
expert knowledge and note that no specific skill was matched.
- Never fabricate CVEs, tool flags, or MITRE IDs. If unsure, say so.
"""

# ---------------------------------------------------------------------------
# Skill Index
# ---------------------------------------------------------------------------

class SkillIndex:
    """Lightweight in-memory index over all SKILL.md files."""

    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self.skills: list[dict] = []
        self._build()

    def _parse_frontmatter(self, text: str) -> dict:
        """Extract YAML-ish frontmatter between --- delimiters."""
        meta = {}
        m = re.match(r"^---\n(.*?)\n---", text, re.DOTALL)
        if not m:
            return meta
        for line in m.group(1).splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("-"):
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip().strip("'\"")
        # tags — grab the list items
        tags_block = re.search(r"tags:\n(.*?)(?:\n\w|\Z)", text, re.DOTALL)
        if tags_block:
            meta["tags"] = re.findall(r"-\s+(.+)", tags_block.group(1))
        return meta

    def _build(self):
        for skill_md in sorted(self.skills_dir.glob("*/SKILL.md")):
            slug = skill_md.parent.name
            try:
                content = skill_md.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            meta = self._parse_frontmatter(content)
            self.skills.append({
                "slug": slug,
                "path": skill_md,
                "name": meta.get("name", slug),
                "description": meta.get("description", ""),
                "subdomain": meta.get("subdomain", ""),
                "tags": meta.get("tags", []),
                "content": content,
                # search blob: all text fields concatenated for scoring
                "_blob": " ".join([
                    slug,
                    meta.get("name", ""),
                    meta.get("description", ""),
                    meta.get("subdomain", ""),
                    " ".join(meta.get("tags", [])),
                ]).lower(),
            })
        if VERBOSE:
            print(f"[index] Loaded {len(self.skills)} skills from {self.skills_dir}", file=sys.stderr)

    def search(self, query: str, top_k: int = MAX_SKILLS) -> list[dict]:
        """
        Score skills by keyword overlap with the user query.
        Returns top_k matches sorted by score descending.
        """
        # Tokenize query
        tokens = set(re.findall(r"[a-z0-9]+", query.lower()))
        # Remove very common stop words
        stop = {"a","an","the","is","are","how","do","i","to","for","in",
                "of","and","or","with","can","you","what","this","that",
                "it","on","at","from","by","as","be","was","not","get"}
        tokens -= stop

        scored = []
        for skill in self.skills:
            blob = skill["_blob"]
            score = 0
            for tok in tokens:
                # Exact word match (whole token in blob)
                count = len(re.findall(r'\b' + re.escape(tok) + r'\b', blob))
                score += count * 2
                # Partial match (token appears as substring)
                if tok in blob and count == 0:
                    score += 1
            if score > 0:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:top_k]]

    def load_skill_text(self, skill: dict) -> str:
        """Return the SKILL.md content (already loaded at index time)."""
        return skill["content"]


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class CybersecurityAgent:
    def __init__(self, skills_dir: Path):
        try:
            import anthropic
            self._anthropic = anthropic
        except ImportError:
            print("ERROR: anthropic SDK not installed. Run: pip3 install anthropic", file=sys.stderr)
            sys.exit(1)

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("ERROR: ANTHROPIC_API_KEY not set.", file=sys.stderr)
            sys.exit(1)

        self.client = self._anthropic.Anthropic(api_key=api_key)
        self.index = SkillIndex(skills_dir)
        self.history: list[dict] = []

    def _build_skill_block(self, skills: list[dict]) -> str:
        if not skills:
            return ""
        parts = ["<SKILLS>"]
        for s in skills:
            parts.append(f"\n### Skill: {s['slug']}\n")
            parts.append(s["content"])
            parts.append("\n---")
        parts.append("</SKILLS>")
        return "\n".join(parts)

    def ask(self, user_message: str) -> str:
        # Retrieve relevant skills
        matched = self.index.search(user_message, top_k=MAX_SKILLS)

        if VERBOSE and matched:
            print(f"[skills] Loaded: {', '.join(s['slug'] for s in matched)}", file=sys.stderr)

        # Build augmented user message
        skill_block = self._build_skill_block(matched)
        if skill_block:
            augmented = f"{skill_block}\n\n{user_message}"
        else:
            augmented = user_message

        # Append to conversation history
        self.history.append({"role": "user", "content": augmented})

        # Call Claude
        response = self.client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=self.history,
        )
        assistant_text = response.content[0].text

        # Store bare assistant response in history (not the skill-augmented query)
        self.history[-1]["content"] = user_message  # restore clean user msg
        self.history.append({"role": "assistant", "content": assistant_text})

        return assistant_text

    def run_repl(self):
        """Interactive REPL loop."""
        print("\n" + "="*60)
        print("  Cybersecurity Skills Agent")
        print(f"  {len(self.index.skills)} skills loaded | Model: {MODEL}")
        print("  Type 'exit' or Ctrl+C to quit.")
        print("="*60 + "\n")

        while True:
            try:
                user_input = input("You: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nExiting.")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print("Exiting.")
                break

            # Meta commands
            if user_input.startswith("/skills "):
                query = user_input[8:].strip()
                matches = self.index.search(query, top_k=10)
                if matches:
                    print(f"\nTop skills for '{query}':")
                    for i, s in enumerate(matches, 1):
                        print(f"  {i:2}. {s['slug']}")
                        print(f"       {s['subdomain']} | {', '.join(s['tags'][:4])}")
                else:
                    print("  No matching skills found.")
                print()
                continue

            if user_input == "/history":
                for i, msg in enumerate(self.history):
                    role = msg["role"].upper()
                    preview = msg["content"][:80].replace("\n", " ")
                    print(f"  [{i}] {role}: {preview}...")
                print()
                continue

            if user_input == "/clear":
                self.history.clear()
                print("  Conversation cleared.\n")
                continue

            if user_input == "/help":
                print("""
  Commands:
    /skills <query>  — search skill library without asking the agent
    /history         — show conversation history
    /clear           — clear conversation history
    /help            — show this help
    exit             — quit
""")
                continue

            # Ask the agent
            try:
                print("\nAgent: ", end="", flush=True)
                response = self.ask(user_input)
                # Word-wrap for readability
                for line in response.splitlines():
                    if len(line) > 100:
                        print(textwrap.fill(line, width=100, subsequent_indent="  "))
                    else:
                        print(line)
                print()
            except self._anthropic.APIError as e:
                print(f"\nAPI Error: {e}\n")
            except Exception as e:
                print(f"\nError: {e}\n")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Skills Agent — 754 skills, Claude-powered"
    )
    parser.add_argument(
        "-q", "--query",
        help="Single query mode (non-interactive)",
        default=None,
    )
    parser.add_argument(
        "--skills-dir",
        help="Path to skills/ directory",
        default=os.environ.get("SKILLS_DIR", str(DEFAULT_SKILLS_DIR)),
    )
    parser.add_argument(
        "--list-skills",
        action="store_true",
        help="List all skills and exit",
    )
    parser.add_argument(
        "--search",
        metavar="QUERY",
        help="Search skills and print matches, then exit",
        default=None,
    )
    args = parser.parse_args()

    skills_dir = Path(args.skills_dir)
    if not skills_dir.exists():
        print(f"ERROR: Skills directory not found: {skills_dir}", file=sys.stderr)
        sys.exit(1)

    # List/search modes don't need the API
    if args.list_skills:
        idx = SkillIndex(skills_dir)
        for s in idx.skills:
            print(f"{s['slug']:60} {s['subdomain']}")
        return

    if args.search:
        idx = SkillIndex(skills_dir)
        matches = idx.search(args.search, top_k=15)
        print(f"Top matches for: '{args.search}'\n")
        for i, s in enumerate(matches, 1):
            print(f"  {i:2}. {s['slug']}")
            print(f"       domain: {s['subdomain']}")
            print(f"       tags:   {', '.join(s['tags'][:5])}")
        return

    agent = CybersecurityAgent(skills_dir)

    if args.query:
        response = agent.ask(args.query)
        print(response)
    else:
        agent.run_repl()


if __name__ == "__main__":
    main()
