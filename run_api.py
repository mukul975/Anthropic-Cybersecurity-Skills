#!/usr/bin/env python3
"""
run_api.py — Start the Cybersecurity Skills Agent API server.

Usage:
    python3 run_api.py
    python3 run_api.py --host 0.0.0.0 --port 8765
    API_TOKEN=mysecret python3 run_api.py
    python3 run_api.py --host 0.0.0.0 --allow-unauthenticated-lan

Add to Open WebUI:
    Settings → Connections → Add OpenAI-compatible API
    URL:   http://localhost:8765   (or LAN IP for Open WebUI on Pi5)
    Key:   your API_TOKEN when binding beyond localhost
    Model: cybersecurity-agent
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

from cyberagent.config import API_TOKEN, validate_api_security_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

for noisy_logger in ("httpx", "sentence_transformers", "huggingface_hub", "transformers"):
    logging.getLogger(noisy_logger).setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Agent API Server")
    parser.add_argument("--host", default=os.environ.get("API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("API_PORT", "8765")))
    parser.add_argument("--reload", action="store_true", help="Dev mode: auto-reload on changes")
    parser.add_argument(
        "--allow-unauthenticated-lan",
        action="store_true",
        help="Allow binding beyond localhost without API_TOKEN. Use only on a trusted private network.",
    )
    args = parser.parse_args()

    try:
        validate_api_security_config(
            host=args.host,
            token=API_TOKEN,
            allow_unauthenticated_lan=args.allow_unauthenticated_lan,
        )
    except RuntimeError as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        import uvicorn
    except ImportError:
        print("ERROR: uvicorn not installed. Run: pip3 install uvicorn --break-system-packages")
        sys.exit(1)

    from cyberagent.agent import _BACKEND, _MODEL

    print(f"\n🔐 Cybersecurity Skills Agent API")
    print(f"   Backend:  {_BACKEND}/{_MODEL}")
    print(f"   Listening on http://{args.host}:{args.port}")
    print(f"   Auth:     {'enabled' if API_TOKEN else 'disabled'}")
    print(f"   Health:  http://{args.host}:{args.port}/health")
    print(f"   Models:  http://{args.host}:{args.port}/v1/models")
    print(f"   Chat:    POST http://{args.host}:{args.port}/v1/chat/completions\n")

    uvicorn.run(
        "cyberagent.api:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
