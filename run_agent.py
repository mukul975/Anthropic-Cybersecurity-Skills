#!/usr/bin/env python3
"""
run_agent.py — Rich CLI REPL for the Cybersecurity Skills Agent.

Usage:
    python3 run_agent.py                      # start new session
    python3 run_agent.py --resume <id>        # resume a session
    python3 run_agent.py -q "query"           # single query, no REPL
    python3 run_agent.py --search "query"     # search skills, no LLM call
    python3 run_agent.py --list-skills        # list all skills
    VERBOSE=1 python3 run_agent.py            # show which skills are loaded

Session commands inside REPL:
    /skills <query>          search skill library
    /skill <slug>            show full skill content
    /session new [name]      start new named session
    /session list            list recent sessions
    /session load <id>       resume a session
    /history                 show conversation turns
    /clear                   clear in-memory history
    /verbose                 toggle skill debug output
    /help                    show commands
    exit / quit              exit
"""

import argparse
import logging
import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_VERBOSITY", "error")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

ENV_FILE = REPO_ROOT / "data" / ".env"


def _load_env_file():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


_load_env_file()

from cyberagent.config import ANTHROPIC_API_KEY
from cyberagent.retrieval import get_index
from cyberagent.skill_loader import load_skill
from cyberagent.session import new_session, list_sessions, get_session
from cyberagent.agent import CybersecurityAgent

VERBOSE = os.environ.get("VERBOSE", "0") == "1"

# ── Rich setup ─────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.table import Table
    from rich import print as rprint
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.WARNING,
    format="%(levelname)s %(name)s: %(message)s",
)


def print_response(text: str):
    if RICH:
        console.print(Panel(Markdown(text), border_style="cyan", padding=(1, 2)))
    else:
        print("\nAgent:", text, "\n")


def print_info(text: str):
    if RICH:
        console.print(f"[dim]{text}[/dim]")
    else:
        print(text)


def print_warn(text: str):
    if RICH:
        console.print(f"[yellow]{text}[/yellow]")
    else:
        print("WARN:", text)


def print_header(session_id: str, session_name: str, skill_count: int, semantic: bool, backend_label: str):
    if RICH:
        mode = "🔍 semantic" if semantic else "🔤 keyword"
        console.print(
            Panel(
                f"[bold cyan]Cybersecurity Skills Agent[/bold cyan]\n"
                f"[dim]{skill_count} skills loaded · {mode} search · Backend: {backend_label}[/dim]\n"
                f"[dim]Session: [green]{session_id}[/green] · {session_name}[/dim]\n"
                f"[dim]Type [bold]/help[/bold] for commands · [bold]exit[/bold] to quit[/dim]",
                border_style="blue",
            )
        )
    else:
        print(f"\n{'='*60}")
        print(f"  Cybersecurity Skills Agent")
        print(f"  {skill_count} skills · Backend: {backend_label} · Session: {session_id}")
        print(f"  Type /help for commands · exit to quit")
        print(f"{'='*60}\n")


# ── Command handlers ────────────────────────────────────────────────────────

def cmd_search(query: str):
    idx = get_index()
    results = idx.search(query, top_k=12)
    if not results:
        print_info("No matching skills found.")
        return
    if RICH:
        t = Table(title=f"Skills matching: '{query}'", show_lines=False)
        t.add_column("#", style="dim", width=3)
        t.add_column("Slug", style="cyan")
        t.add_column("Domain", style="green", width=28)
        t.add_column("Tags", style="dim")
        for i, s in enumerate(results, 1):
            tags = ", ".join(s.get("tags", [])[:3])
            t.add_row(str(i), s["slug"], s.get("subdomain", "?"), tags)
        console.print(t)
    else:
        for i, s in enumerate(results, 1):
            print(f"  {i:2}. {s['slug']}")
            print(f"       {s.get('subdomain', '?')} | {', '.join(s.get('tags', [])[:3])}")


def cmd_show_skill(slug: str, query: str = ""):
    idx = get_index()
    skill = idx.get_by_slug(slug)
    if not skill:
        # fuzzy fallback
        matches = idx.search(slug, top_k=3)
        if matches:
            print_warn(f"Skill '{slug}' not found. Closest: {matches[0]['slug']}")
        else:
            print_warn(f"Skill '{slug}' not found.")
        return
    content = load_skill(skill, query)
    if RICH:
        console.print(Panel(Markdown(content), title=slug, border_style="green"))
    else:
        print(content)


def cmd_session_list():
    sessions = list_sessions(limit=10)
    if not sessions:
        print_info("No saved sessions.")
        return
    if RICH:
        t = Table(title="Recent Sessions", show_lines=False)
        t.add_column("ID", style="cyan", width=10)
        t.add_column("Name", style="green")
        t.add_column("Last Active", style="dim")
        for s in sessions:
            t.add_row(s["id"], s["name"], s["last_active"][:19])
        console.print(t)
    else:
        for s in sessions:
            print(f"  {s['id']}  {s['name']}  {s['last_active'][:19]}")


def cmd_help():
    help_text = """
**Session commands:**
  /session new [name]   Start a new named session
  /session list         List recent sessions
  /session load <id>    Resume a saved session

**Skill commands:**
  /skills <query>       Search the skill library
  /skill <slug>         Show full skill content

**Conversation:**
  /history              Show conversation turns count
  /clear                Clear in-memory history (session DB kept)
  /verbose              Toggle debug output

**General:**
  /help                 This message
  exit / quit           Exit
"""
    if RICH:
        console.print(Panel(Markdown(help_text), border_style="dim"))
    else:
        print(help_text)


# ── REPL ────────────────────────────────────────────────────────────────────

def repl(agent: CybersecurityAgent, session_name: str):
    idx = get_index()
    print_header(
        agent.session_id,
        session_name,
        idx.count,
        idx.semantic_enabled,
        f"{agent.backend}/{agent.model}",
    )

    while True:
        try:
            if RICH:
                user_input = console.input("[bold green]You:[/bold green] ").strip()
            else:
                user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            break

        # ── Meta commands ──
        if user_input.startswith("/skills "):
            cmd_search(user_input[8:].strip())
            continue
        if user_input.startswith("/skill "):
            cmd_show_skill(user_input[7:].strip())
            continue
        if user_input == "/session list":
            cmd_session_list()
            continue
        if user_input.startswith("/session new"):
            parts = user_input.split(None, 2)
            name = parts[2] if len(parts) > 2 else None
            new_id = new_session(name)
            print_info(f"New session: {new_id}")
            continue
        if user_input.startswith("/session load "):
            sid = user_input[14:].strip()
            sess = get_session(sid)
            if sess:
                print_info(f"Switching to session {sid} — restart run_agent.py with --resume {sid}")
            else:
                print_warn(f"Session '{sid}' not found.")
            continue
        if user_input == "/history":
            print_info(f"  {agent.history_length} messages in current conversation.")
            continue
        if user_input == "/clear":
            agent.clear_history()
            print_info("  Conversation cleared.")
            continue
        if user_input == "/verbose":
            agent.verbose = not agent.verbose
            print_info(f"  Verbose: {'on' if agent.verbose else 'off'}")
            continue
        if user_input == "/help":
            cmd_help()
            continue

        # ── Agent query ──
        try:
            if RICH:
                with console.status("[cyan]Thinking...[/cyan]", spinner="dots"):
                    response = agent.chat(user_input)
            else:
                print("Agent: ", end="", flush=True)
                response = agent.chat(user_input)
            print_response(response)
        except Exception as e:
            print_warn(f"Error: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Skills Agent CLI")
    parser.add_argument("-q", "--query", help="Single query (non-interactive)", default=None)
    parser.add_argument("--resume", metavar="SESSION_ID", help="Resume a saved session", default=None)
    parser.add_argument("--search", metavar="QUERY", help="Search skills and exit", default=None)
    parser.add_argument("--list-skills", action="store_true", help="List all skills and exit")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # No-LLM modes (run before API key check)
    if args.list_skills:
        idx = get_index()
        for s in idx.skills:
            print(f"{s['slug']:<60} {s.get('subdomain', '')}")
        return

    if args.search:
        cmd_search(args.search)
        return

    from cyberagent.config import ANTHROPIC_API_KEY, GEMINI_API_KEY
    if not ANTHROPIC_API_KEY and not GEMINI_API_KEY:
        print("ERROR: Neither ANTHROPIC_API_KEY nor GEMINI_API_KEY are set.", file=sys.stderr)
        sys.exit(1)

    # Session setup
    if args.resume:
        sess = get_session(args.resume)
        if not sess:
            print(f"Session '{args.resume}' not found.", file=sys.stderr)
            sys.exit(1)
        session_id = args.resume
        session_name = sess["name"]
    else:
        session_id = new_session()
        session_name = f"New session"

    agent = CybersecurityAgent(
        session_id=session_id,
        verbose=args.verbose or VERBOSE,
    )

    if args.query:
        response = agent.chat(args.query)
        print(response)
        return

    repl(agent, session_name)


if __name__ == "__main__":
    main()
