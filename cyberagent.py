#!/usr/bin/env python3
"""
# cyberagent.py — Inspector Gadget (Anthropic Cybersecurity Skills)
# =====================================================
# 
# Single-file entry point. Run this once and it handles everything:
#   - Installs missing dependencies
#   - Builds the semantic skill index (first run ~45s)
#   - Prompts for your API key if not set
#   - Drops into an interactive cybersecurity analyst REPL
# 
# Usage:
#     python3 cyberagent.py
#     python3 cyberagent.py --search "lateral movement detection"
    python3 cyberagent.py --resume <session-id>
    ANTHROPIC_API_KEY=sk-ant-... python3 cyberagent.py
"""

import subprocess
import sys
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DATA_DIR  = REPO_ROOT / "data"
ENV_FILE  = DATA_DIR / ".env"

# ── Step 1: Ensure dependencies ────────────────────────────────────────────

REQUIRED = {
    "anthropic":             "anthropic>=0.50.0",
    "google.genai":          "google-genai>=1.0.0",
    "sentence_transformers": "sentence-transformers>=3.0.0",
    "numpy":                 "numpy>=1.26.0",
    "rich":                  "rich>=13.0.0",
    "fastapi":               "fastapi>=0.110.0",
    "uvicorn":               "uvicorn[standard]>=0.29.0",
    "mcp":                   "mcp>=1.0.0",
    "yaml":                  "pyyaml>=6.0.0",
}

def _check_and_install_deps():
    missing_pkgs = []
    for module, pip_spec in REQUIRED.items():
        try:
            __import__(module)
        except ImportError:
            missing_pkgs.append(pip_spec)

    if not missing_pkgs:
        return

    print(f"\n[setup] Installing {len(missing_pkgs)} missing package(s)...")
    for pkg in missing_pkgs:
        print(f"        → {pkg}")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages"] + missing_pkgs,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        # Try without --break-system-packages (non-Homebrew Python)
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing_pkgs,
            capture_output=True, text=True
        )
    if result.returncode != 0:
        print(f"[ERROR] Failed to install deps:\n{result.stderr}")
        sys.exit(1)

    print("[setup] Dependencies installed.\n")


_check_and_install_deps()

# ── Silence HuggingFace Hub output BEFORE any imports ─────────────────────
# HF progress bars print to stdout, which bleeds into Rich's stdin reader
# and causes a cascade of spurious API calls. Kill it at the env level.
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("HF_HUB_VERBOSITY", "error")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

# ── Now safe to import ──────────────────────────────────────────────────────

import argparse
import getpass
import logging
from pathlib import Path

# ── Step 2: API key resolution ─────────────────────────────────────────────

def _load_env_file():
    """Load key=value pairs from data/.env into os.environ."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())


def _resolve_api_key() -> str:
    """
    Key resolution order:
      1. GEMINI_API_KEY env var
      2. ANTHROPIC_API_KEY env var
      2. data/.env file
      3. Interactive prompt (with optional save)
    """
    _load_env_file()

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key:
        return gemini_key

    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if key:
        return key

    # Try 1Password CLI silently
    try:
        result = subprocess.run(
            ["op", "item", "get", "Anthropic API Key",
             "--vault", "3i56wtg5jxdvaiz7ksc6bmh65y",
             "--fields", "label=credential", "--reveal"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            key = result.stdout.strip()
            os.environ["ANTHROPIC_API_KEY"] = key
            return key
    except Exception:
        pass

    # Prompt
    print("\n┌─ Anthropic API Key Required ─────────────────────────────────┐")
    print("│  Get yours at: https://console.anthropic.com/settings/keys   │")
    print("└───────────────────────────────────────────────────────────────┘")
    key = getpass.getpass("  Paste your API key (sk-ant-...): ").strip()

    if not key or not key.startswith("sk-ant-"):
        print("ERROR: Invalid API key format.")
        sys.exit(1)

    os.environ["ANTHROPIC_API_KEY"] = key

    save = input("  Save key to data/.env for future runs? [Y/n]: ").strip().lower()
    if save in ("", "y", "yes"):
        DATA_DIR.mkdir(exist_ok=True)
        ENV_FILE.write_text(f"ANTHROPIC_API_KEY={key}\n")
        ENV_FILE.chmod(0o600)
        print(f"  Saved to {ENV_FILE}\n")
    else:
        print("  Key not saved — set ANTHROPIC_API_KEY env var to skip this prompt.\n")

    return key


# ── Step 3: Index auto-build ────────────────────────────────────────────────

def _ensure_index():
    """Build the semantic skill index if it doesn't exist yet."""
    sys.path.insert(0, str(REPO_ROOT))
    from cyberagent.config import SKILL_META_FILE, EMBEDDINGS_FILE, SKILLS_DIR

    if SKILL_META_FILE.exists() and EMBEDDINGS_FILE.exists():
        return  # already built

    skill_count = len(list(SKILLS_DIR.glob("*/SKILL.md")))
    print(f"\n[setup] Building semantic index for {skill_count} skills...")
    print("        (This runs once and takes ~45 seconds on first run)\n")

    try:
        import build_index
        build_index.build()
    except Exception as e:
        print(f"[ERROR] Index build failed: {e}")
        print("        Run: python3 build_index.py manually to debug.")
        sys.exit(1)


# ── Step 4: Launch ──────────────────────────────────────────────────────────

def main():
    # Parse args first so --help works without any setup
    parser = argparse.ArgumentParser(
        description="Inspector Gadget — 754 skills · Gemini/Claude-powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cyberagent.py                              # start new session
  python3 cyberagent.py --search "T1078 valid accounts"
  python3 cyberagent.py --search "detect kerberoasting"
  python3 cyberagent.py --resume abc12345           # resume saved session
  python3 cyberagent.py -q "how do I hunt lateral movement with Zeek?"
  python3 cyberagent.py --api                       # start OpenAI-compatible API server
  python3 cyberagent.py --list-skills               # dump all 754 skill slugs

REPL commands:
  /skills <query>      search skill library
  /skill <slug>        show full skill content
  /session list        list saved sessions
  /session new [name]  start named session
  /history             show conversation length
  /verbose             toggle debug output
  /help                show all commands
  exit                 quit
        """,
    )
    parser.add_argument("-q", "--query", help="Single query, non-interactive", default=None)
    parser.add_argument("--resume", metavar="SESSION_ID", help="Resume a saved session")
    parser.add_argument("--search", metavar="QUERY", help="Search skills and exit (no LLM)")
    parser.add_argument("--list-skills", action="store_true", help="List all skill slugs and exit")
    parser.add_argument("--api", action="store_true", help="Start OpenAI-compatible API server")
    parser.add_argument("--port", type=int, default=8765, help="API server port (default: 8765)")
    parser.add_argument("--verbose", action="store_true", help="Show which skills are loaded per query")
    parser.add_argument("--update-key", action="store_true", help="Clear saved API key and re-prompt")
    args = parser.parse_args()

    # Always load data/.env before backend selection so Gemini/Anthropic keys
    # are available even when Ollama is running locally.
    _load_env_file()

    # Handle --update-key immediately
    if args.update_key:
        if ENV_FILE.exists():
            ENV_FILE.unlink()
            print("Cleared saved key.")
        os.environ.pop("ANTHROPIC_API_KEY", None)  # remove from env so prompt fires
        _resolve_api_key()
        print("Key updated. Run python3 cyberagent.py to start.")
        return

    # ── No-LLM modes (no API key needed) ───────────────────────────────────
    if args.list_skills:
        _ensure_index()
        sys.path.insert(0, str(REPO_ROOT))
        from cyberagent.retrieval import get_index
        idx = get_index()
        for s in idx.skills:
            print(f"{s['slug']:<62} {s.get('subdomain', '')}")
        return

    if args.search:
        _ensure_index()
        _print_search(args.search)
        return

    # ── Setup sequence ──────────────────────────────────────────────────────
    # Only prompt for API key if Ollama isn't running and no key was loaded
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT))
    from cyberagent.ollama_backend import is_ollama_running
    if not is_ollama_running() and not (os.environ.get("GEMINI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")):
        _resolve_api_key()
    _ensure_index()

    # API server mode
    if args.api:
        _start_api(args.port)
        return

    # ── REPL / single-query mode ────────────────────────────────────────────
    from cyberagent.session import new_session, get_session
    from cyberagent.agent import CybersecurityAgent

    if args.resume:
        sess = get_session(args.resume)
        if not sess:
            print(f"Session '{args.resume}' not found.")
            sys.exit(1)
        session_id = args.resume
        session_name = sess["name"]
    else:
        session_id = new_session()
        session_name = "New session"

    agent = CybersecurityAgent(session_id=session_id, verbose=args.verbose)

    if args.query:
        response = agent.chat(args.query)
        print(response)
        return

    # Pre-warm the embedding model before the REPL opens its stdin.
    # This ensures any model-loading output happens here, not mid-conversation.
    _prewarm_embed_model()

    _repl(agent, session_name)


# ── Model pre-warm ──────────────────────────────────────────────────────────

def _prewarm_embed_model():
    """Load the sentence-transformer model now so progress bars can't corrupt stdin later."""
    try:
        sys.path.insert(0, str(REPO_ROOT))
        from cyberagent.retrieval import get_index
        idx = get_index()
        if idx.semantic_enabled:
            idx.embed_query("warmup")  # silent — HF bars already disabled above
    except Exception:
        pass  # non-fatal; search will fall back to keyword mode


# ── REPL ────────────────────────────────────────────────────────────────────

def _repl(agent, session_name: str):
    from cyberagent.retrieval import get_index
    from cyberagent.session import new_session, list_sessions, get_session
    from cyberagent.skill_loader import load_skill

    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.markdown import Markdown
        from rich.table import Table
        console = Console()
        RICH = True
    except ImportError:
        console = None
        RICH = False

    idx = get_index()
    mode = "🔍 semantic" if idx.semantic_enabled else "🔤 keyword"

    backend_label = f"ollama/{agent.model}" if agent.backend == "ollama" else agent.model

    if RICH:
        console.print(Panel(
            f"[bold cyan]Inspector Gadget[/bold cyan]\n"
            f"[dim]{idx.count} skills · {mode} search · {backend_label}[/dim]\n"
            f"[dim]Session [green]{agent.session_id}[/green] · {session_name}[/dim]\n"
            f"[dim][bold]/help[/bold] for commands  ·  [bold]exit[/bold] to quit[/dim]",
            border_style="blue",
        ))
    else:
        print(f"\n{'='*60}\n  Inspector Gadget · {idx.count} skills\n  Session: {agent.session_id}\n{'='*60}\n")

    while True:
        try:
            prompt = "[bold green]You:[/bold green] " if RICH else "You: "
            user_input = (console.input(prompt) if RICH else input(prompt)).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            break

        # ── Meta commands ──────────────────────────────────────────────────

        if user_input.startswith("/skills "):
            _print_search(user_input[8:].strip(), console=console, RICH=RICH)
            continue

        if user_input.startswith("/skill "):
            slug = user_input[7:].strip()
            skill = idx.get_by_slug(slug)
            if not skill:
                matches = idx.search(slug, top_k=3)
                tip = f"Closest: {matches[0]['slug']}" if matches else "No matches."
                _warn(f"Skill '{slug}' not found. {tip}", console, RICH)
            else:
                content = load_skill(skill)
                if RICH:
                    console.print(Panel(Markdown(content), title=slug, border_style="green"))
                else:
                    print(content)
            continue

        if user_input == "/session list":
            sessions = list_sessions(limit=10)
            if RICH:
                t = Table(title="Recent Sessions")
                t.add_column("ID", style="cyan"); t.add_column("Name"); t.add_column("Last Active", style="dim")
                for s in sessions:
                    t.add_row(s["id"], s["name"], s["last_active"][:19])
                console.print(t)
            else:
                for s in sessions:
                    print(f"  {s['id']}  {s['name']}  {s['last_active'][:19]}")
            continue

        if user_input.startswith("/session new"):
            parts = user_input.split(None, 2)
            sid = new_session(parts[2] if len(parts) > 2 else None)
            _info(f"New session: {sid} — restart with --resume {sid} to load it", console, RICH)
            continue

        if user_input == "/history":
            _info(f"{agent.history_length} messages in this session.", console, RICH)
            continue

        if user_input == "/clear":
            agent.clear_history()
            _info("History cleared.", console, RICH)
            continue

        if user_input == "/verbose":
            agent.verbose = not agent.verbose
            _info(f"Verbose: {'on' if agent.verbose else 'off'}", console, RICH)
            continue

        if user_input == "/help":
            _print_help(console, RICH)
            continue

        # ── Agent query ────────────────────────────────────────────────────
        try:
            if RICH:
                with console.status("[cyan]Thinking...[/cyan]", spinner="dots"):
                    response = agent.chat(user_input)
                console.print(Panel(Markdown(response), border_style="cyan", padding=(1, 2)))
            else:
                response = agent.chat(user_input)
                print(f"\n{response}\n")
        except KeyboardInterrupt:
            print("\n[cancelled]")
        except Exception as e:
            err_str = str(e)
            if "credit balance" in err_str.lower():
                _warn(
                    "⚠  Anthropic credit balance too low.\n"
                    "   Add credits: https://console.anthropic.com/settings/billing\n"
                    "   If you have a new key, run: python3 cyberagent.py --update-key",
                    console, RICH
                )
                _offer_key_update()
                break  # stop — don't hammer a depleted account
            elif "invalid" in err_str.lower() and "key" in err_str.lower():
                _warn(
                    "⚠  Invalid or expired API key.\n"
                    "   Run: python3 cyberagent.py --update-key",
                    console, RICH
                )
                _offer_key_update()
                break
            else:
                _warn(f"Error: {e}", console, RICH)

# ── Key update helper ───────────────────────────────────────────────────────────

def _offer_key_update():
    """Offer to clear the saved API key so the next run re-prompts."""
    if not ENV_FILE.exists():
        return
    try:
        ans = input("  Clear saved key so next run prompts for a new one? [Y/n]: ").strip().lower()
        if ans in ("", "y", "yes"):
            ENV_FILE.unlink()
            print("  Cleared. Re-run cyberagent.py to enter your new key.")
    except (KeyboardInterrupt, EOFError):
        pass


# ── API server ──────────────────────────────────────────────────────────────

def _start_api(port: int):
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed — run: pip3 install uvicorn")
        sys.exit(1)

    print(f"\n🔐 Inspector Gadget API")
    print(f"   http://0.0.0.0:{port}")
    print(f"   /health   /v1/models   POST /v1/chat/completions")
    print(f"   Add to Open WebUI → URL: http://localhost:{port}  Model: inspector-gadget\n")
    uvicorn.run("cyberagent.api:app", host="0.0.0.0", port=port, log_level="info")


# ── Helpers ─────────────────────────────────────────────────────────────────

def _print_search(query: str, console=None, RICH=False):
    sys.path.insert(0, str(REPO_ROOT))
    from cyberagent.retrieval import get_index
    idx = get_index()
    results = idx.search(query, top_k=12)
    if not results:
        _info("No matching skills found.", console, RICH)
        return
    if RICH:
        from rich.table import Table
        t = Table(title=f"Skills: '{query}'", show_lines=False)
        t.add_column("#", style="dim", width=3)
        t.add_column("Slug", style="cyan")
        t.add_column("Domain", style="green", width=30)
        t.add_column("Tags", style="dim")
        for i, s in enumerate(results, 1):
            t.add_row(str(i), s["slug"], s.get("subdomain", "?"), ", ".join(s.get("tags", [])[:3]))
        console.print(t)
    else:
        for i, s in enumerate(results, 1):
            print(f"  {i:2}. {s['slug']}")
            print(f"       {s.get('subdomain', '?')} | {', '.join(s.get('tags', [])[:3])}")


def _info(msg, console, RICH):
    if RICH: console.print(f"[dim]{msg}[/dim]")
    else: print(msg)


def _warn(msg, console, RICH):
    if RICH: console.print(f"[yellow]{msg}[/yellow]")
    else: print(f"WARN: {msg}")


def _print_help(console, RICH):
    text = """
**Skill commands:**
  /skills \\<query>     Semantic search across 754 skills
  /skill \\<slug>       Show full skill content + workflow

**Session:**
  /session list       List recent sessions
  /session new [name] Start a new named session
  /history            Show message count
  /clear              Clear in-memory history

**Debug:**
  /verbose            Toggle skill-loading debug output

**General:**
  /help               This message
  exit / quit         Exit
"""
    if RICH:
        from rich.panel import Panel
        from rich.markdown import Markdown
        console.print(Panel(Markdown(text), border_style="dim"))
    else:
        print(text)


if __name__ == "__main__":
    main()
