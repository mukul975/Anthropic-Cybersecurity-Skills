"""
cyberagent/config.py — Central configuration for the Cybersecurity Skills Agent.
All paths, model names, and tunable constants live here.
"""

import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parent.parent
SKILLS_DIR  = REPO_ROOT / "skills"
DATA_DIR    = REPO_ROOT / "data"

EMBEDDINGS_FILE = DATA_DIR / "embeddings.npy"
SKILL_META_FILE = DATA_DIR / "skill_meta.json"
SESSIONS_DB     = DATA_DIR / "sessions.db"
AUDIT_LOG       = DATA_DIR / "audit.log"
DROPZONE_DIR    = Path(os.environ.get(
    "DROPZONE_DIR",
    str(Path.home() / "Desktop" / "anchor memory" / "Antigravity" / "05-Dropzone"),
))

# ── LLM ───────────────────────────────────────────────────────────────────
AGENT_BACKEND     = os.environ.get("AGENT_BACKEND", "auto").strip().lower()
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL      = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_MAX_RETRIES = int(os.environ.get("GEMINI_MAX_RETRIES", "2"))
GEMINI_RETRY_BUFFER_SEC = float(os.environ.get("GEMINI_RETRY_BUFFER_SEC", "1.0"))
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL             = os.environ.get("AGENT_MODEL", "claude-sonnet-4-5")
MAX_TOKENS        = int(os.environ.get("MAX_TOKENS", "4096"))

# ── Retrieval ──────────────────────────────────────────────────────────────
MAX_SKILLS        = int(os.environ.get("MAX_SKILLS", "4"))
EMBED_MODEL_NAME  = "all-MiniLM-L6-v2"   # 84 MB, runs locally
SEMANTIC_THRESHOLD = 0.15                  # min cosine sim to include a skill

# ── Context budget ─────────────────────────────────────────────────────────
# Rough: 4 chars ≈ 1 token. 30k tokens × 4 = 120k chars.
MAX_CONTEXT_CHARS = 120_000

# ── API server ─────────────────────────────────────────────────────────────
API_HOST  = os.environ.get("API_HOST", "127.0.0.1")
API_PORT  = int(os.environ.get("API_PORT", "8765"))
API_TOKEN = os.environ.get("API_TOKEN", "")  # required when binding beyond localhost
API_MAX_UPLOAD_MB = int(os.environ.get("API_MAX_UPLOAD_MB", "50"))
API_CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("API_CORS_ORIGINS", "").split(",")
    if origin.strip()
]
API_CORS_ALLOW_CREDENTIALS = os.environ.get("API_CORS_ALLOW_CREDENTIALS", "0") == "1"
API_ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("API_ALLOWED_HOSTS", "127.0.0.1,localhost,::1").split(",")
    if host.strip()
]
LOCALHOST_NAMES = {"127.0.0.1", "localhost", "::1"}

# ── Execution ──────────────────────────────────────────────────────────────
# Off by default. Set ENABLE_EXECUTION=1 to allow running skill scripts.
ENABLE_EXECUTION = os.environ.get("ENABLE_EXECUTION", "0") == "1"
SCRIPT_TIMEOUT   = int(os.environ.get("SCRIPT_TIMEOUT", "120"))  # seconds
ALLOW_LOCAL_FILE_TOOLS = os.environ.get("ALLOW_LOCAL_FILE_TOOLS", "0") == "1"
FILE_TOOL_EXTRA_ROOTS = [
    Path(root).expanduser()
    for root in os.environ.get("FILE_TOOL_EXTRA_ROOTS", "").split(":")
    if root.strip()
]


def validate_api_security_config(
    host: str | None = None,
    token: str | None = None,
    allow_unauthenticated_lan: bool = False,
) -> None:
    """Validate API exposure settings before importing or starting the live app."""
    selected_host = host if host is not None else API_HOST
    selected_token = token if token is not None else API_TOKEN

    if selected_host not in LOCALHOST_NAMES and not selected_token and not allow_unauthenticated_lan:
        raise RuntimeError(
            "Refusing to bind beyond localhost without API_TOKEN. "
            "Set API_TOKEN or pass --allow-unauthenticated-lan for an intentional private-network run."
        )

    if "*" in API_CORS_ORIGINS and API_CORS_ALLOW_CREDENTIALS:
        raise RuntimeError("Refusing wildcard CORS with credentials enabled")

# ── Offensive skill gate ───────────────────────────────────────────────────
OFFENSIVE_SUBDOMAINS = {
    "penetration-testing",
    "red-teaming",
    "red-team",
    "offensive-security",
}

OFFENSIVE_KEYWORDS = {
    "exploit", "attack", "crack", "bypass", "escalate",
    "kerberoast", "exfiltrate", "pivot", "bruteforce",
    "brute-force", "payload", "backdoor", "persistence",
    "reverse shell", "bind shell", "shellcode", "lateral movement",
}

# Skill slugs that always require the auth gate regardless of subdomain
ALWAYS_GATE_SLUGS = {
    "performing-kerberoasting-attack",
    "performing-privilege-escalation-on-linux",
    "performing-lateral-movement-with-wmiexec",
    "performing-credential-access-with-lazagne",
    "performing-initial-access-with-evilginx3",
    "performing-hash-cracking-with-hashcat",
    "performing-jwt-none-algorithm-attack",
    "performing-ssl-stripping-attack",
    "performing-wifi-password-cracking-with-aircrack",
}
