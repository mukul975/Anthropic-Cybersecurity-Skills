#!/usr/bin/env python3
"""End-to-end verification harness for the Cybersecurity Skills Agent.

Verifies the exact operator path that matters most:
1. Forced backend selection
2. Direct tool-loop execution via CybersecurityAgent
3. CLI entrypoint behavior
4. API /v1/models metadata
5. API non-streaming chat completions
6. API streaming chat completions

The default scenario checks that the agent uses ``load_skill`` for an exact
slug and returns grounded content instead of vague summary sludge.

Usage:
    python tools/verify-agent-e2e.py
    python tools/verify-agent-e2e.py --mode quick
    python tools/verify-agent-e2e.py --backend gemini
    python tools/verify-agent-e2e.py --scenario search-then-load --mode quick
    python tools/verify-agent-e2e.py --skill performing-api-rate-limiting-bypass
    python tools/verify-agent-e2e.py --json
"""

from __future__ import annotations

import argparse
import http.client
import importlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml
from dataclasses import dataclass, field


REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_ENV = REPO_ROOT / "data" / ".env"
DEFAULT_SKILL = "performing-api-rate-limiting-bypass"
DEFAULT_BACKEND = "gemini"


class VerificationBlocked(RuntimeError):
    """Raised when live verification is blocked by provider/runtime limits."""


@dataclass(frozen=True)
class Scenario:
    name: str
    slug: str
    prompt_template: str
    expected_tool_names: list[str]
    env_overrides: dict[str, str] = field(default_factory=dict)


SCENARIOS: dict[str, Scenario] = {
    "exact-load-skill": Scenario(
        name="exact-load-skill",
        slug=DEFAULT_SKILL,
        prompt_template=(
            "Use only the load_skill tool with slug '{slug}'. "
            "Do not use search_skills. After loading it, answer with exactly three lines: "
            "SLUG: <slug>\\nDESC: <first sentence of the description>\\n"
            "STEP1: <exact Step 1 workflow heading text, without Markdown # characters>."
        ),
        expected_tool_names=["load_skill"],
    ),
    "search-then-load": Scenario(
        name="search-then-load",
        slug=DEFAULT_SKILL,
        prompt_template=(
            "First use search_skills to find the exact skill slug for API rate limiting bypass testing. "
            "Then use load_skill for the exact slug '{slug}'. "
            "After loading it, answer with exactly three lines: "
            "SLUG: <slug>\\nDESC: <first sentence of the description>\\n"
            "STEP1: <exact Step 1 workflow heading text, without Markdown # characters>."
        ),
        expected_tool_names=["search_skills", "load_skill"],
        env_overrides={"MAX_SKILLS": "0"},
    ),
}


def load_env_file() -> None:
    if not DATA_ENV.exists():
        return
    for line in DATA_ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def first_sentence(text: str) -> str:
    flat = " ".join(text.split())
    match = re.match(r"(.+?\.)($|\s)", flat)
    return match.group(1).strip() if match else flat.strip()


def expected_skill_values(slug: str) -> dict[str, str]:
    skill_path = REPO_ROOT / "skills" / slug / "SKILL.md"
    if not skill_path.exists():
        raise FileNotFoundError(f"Skill not found: {skill_path}")

    text = skill_path.read_text(encoding="utf-8", errors="replace")

    frontmatter_match = re.match(r"^---\n([\s\S]*?)\n---", text)
    if not frontmatter_match:
        raise RuntimeError(f"Could not parse frontmatter from {skill_path}")
    frontmatter = yaml.safe_load(frontmatter_match.group(1)) or {}

    description_value = frontmatter.get("description")
    if not isinstance(description_value, str) or not description_value.strip():
        raise RuntimeError(f"Could not parse description from {skill_path}")
    description = first_sentence(description_value)

    step_match = re.search(r"^###\s+Step\s+1:\s+(.+)$", text, re.MULTILINE)
    if not step_match:
        raise RuntimeError(f"Could not parse first workflow step from {skill_path}")

    return {
        "slug": slug,
        "description": description,
        "step1": step_match.group(1).strip(),
    }


def expected_response(expected: dict[str, str]) -> str:
    return (
        f"SLUG: {expected['slug']}\n"
        f"DESC: {expected['description']}\n"
        f"STEP1: {expected['step1']}"
    )


def scenario_prompt(scenario: Scenario) -> str:
    return scenario.prompt_template.format(slug=scenario.slug)


def find_open_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def base_env(backend: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    env["AGENT_BACKEND"] = backend
    if extra:
        env.update(extra)
    return env


def normalize_output(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def normalize_expected_shape(text: str) -> str:
    normalized = normalize_output(text)
    return re.sub(r"(?m)^STEP1:\s+Step\s+1:\s+", "STEP1: ", normalized)


def raise_if_blocked(text: str, label: str) -> None:
    normalized = normalize_output(text)
    if "API Error: 429 RESOURCE_EXHAUSTED" in normalized:
        raise VerificationBlocked(f"{label} blocked by Gemini quota exhaustion: {normalized}")
    if "API Error: 503 UNAVAILABLE" in normalized:
        raise VerificationBlocked(f"{label} blocked by Gemini service unavailable: {normalized}")


def reset_imports() -> None:
    for mod_name in [
        "cyberagent.config",
        "cyberagent.ollama_backend",
        "cyberagent.gemini_backend",
        "cyberagent.agent",
        "cyberagent.api",
    ]:
        sys.modules.pop(mod_name, None)


def load_backend_modules(backend: str, extra_env: dict[str, str] | None = None):
    os.environ["AGENT_BACKEND"] = backend
    if extra_env:
        for key, value in extra_env.items():
            os.environ[key] = value
    sys.path.insert(0, str(REPO_ROOT))
    reset_imports()
    agent_module = importlib.import_module("cyberagent.agent")
    api_module = importlib.import_module("cyberagent.api")
    return agent_module, api_module


def assert_expected_output(actual: str, expected_text: str, label: str) -> None:
    normalized = normalize_expected_shape(actual)
    expected_normalized = normalize_expected_shape(expected_text)
    raise_if_blocked(normalized, label)
    if normalized != expected_normalized:
        raise AssertionError(
            f"{label} output mismatch\n--- expected ---\n{expected_normalized}\n--- actual ---\n{normalized}"
        )


def run_direct_agent_check(backend: str, scenario: Scenario, expected_text: str) -> dict:
    agent_module, _ = load_backend_modules(backend, scenario.env_overrides)

    session_id = f"verify-e2e-{uuid.uuid4().hex[:8]}"
    agent = agent_module.CybersecurityAgent(session_id=session_id, verbose=False)
    response = agent.chat(scenario_prompt(scenario))
    assert_expected_output(response, expected_text, "direct-agent")

    tool_calls = [
        event for event in agent.last_trace
        if event.get("event") == "tool_call"
    ]
    tool_names = [event.get("tool") for event in tool_calls]
    if tool_names != scenario.expected_tool_names:
        raise AssertionError(f"direct-agent tool trace mismatch: {tool_calls!r}")
    if tool_calls[-1].get("tool") == "load_skill" and "slug" not in tool_calls[-1].get("input_keys", []):
        raise AssertionError(f"direct-agent load_skill trace missing slug input: {tool_calls!r}")

    return {
        "backend": agent.backend,
        "model": agent.model,
        "trace": agent.last_trace,
        "response": normalize_output(response),
    }


def run_quick_check(backend: str, scenario: Scenario, expected: dict[str, str]) -> dict:
    agent_module, api_module = load_backend_modules(backend, scenario.env_overrides)

    if agent_module._BACKEND != backend:
        raise AssertionError(f"Forced backend mismatch: expected {backend!r}, got {agent_module._BACKEND!r}")

    description = api_module.app.description
    if f"{backend}/{agent_module._MODEL}" not in description:
        raise AssertionError(f"API description missing backend/model truth: {description}")

    prompt = scenario_prompt(scenario)
    if scenario.slug not in prompt:
        raise AssertionError("Prompt generation did not pin exact slug")

    return {
        "backend": agent_module._BACKEND,
        "model": agent_module._MODEL,
        "api_description": description,
        "scenario": scenario.name,
        "expected_tools": scenario.expected_tool_names,
        "env_overrides": scenario.env_overrides,
        "expected": expected,
    }


def run_cli_check(backend: str, scenario: Scenario, expected_text: str) -> dict:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "run_agent.py"),
        "-q",
        scenario_prompt(scenario),
    ]
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=base_env(backend, scenario.env_overrides),
        capture_output=True,
        text=True,
        timeout=420,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"CLI check failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")

    stdout = normalize_output(proc.stdout)
    assert_expected_output(stdout, expected_text, "cli")
    return {"response": stdout}


def wait_for_http(host: str, port: int, path: str = "/health", timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError(f"Timed out waiting for http://{host}:{port}{path}")


def api_request(host: str, port: int, method: str, path: str, body: dict | None = None) -> tuple[int, str]:
    conn = http.client.HTTPConnection(host, port, timeout=120)
    headers = {"Content-Type": "application/json"}
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    text = resp.read().decode("utf-8", errors="replace")
    status = resp.status
    conn.close()
    return status, text


def api_stream_request(host: str, port: int, body: dict) -> tuple[int, str]:
    conn = http.client.HTTPConnection(host, port, timeout=120)
    headers = {"Content-Type": "application/json"}
    conn.request("POST", "/v1/chat/completions", body=json.dumps(body), headers=headers)
    resp = conn.getresponse()
    status = resp.status
    chunks: list[str] = []
    while True:
        line = resp.fp.readline().decode("utf-8", errors="replace")
        if not line:
            break
        line = line.rstrip("\n")
        if not line.startswith("data: "):
            continue
        data = line[6:]
        if data == "[DONE]":
            break
        if not data.strip():
            continue
        payload = json.loads(data)
        delta = payload["choices"][0].get("delta", {})
        if "content" in delta:
            chunks.append(delta["content"])
    conn.close()
    return status, normalize_output("".join(chunks))


def run_api_check(backend: str, scenario: Scenario, expected_text: str) -> dict:
    host = "127.0.0.1"
    port = find_open_port()
    cmd = [
        sys.executable,
        str(REPO_ROOT / "run_api.py"),
        "--host",
        host,
        "--port",
        str(port),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=REPO_ROOT,
        env=base_env(backend, scenario.env_overrides),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        wait_for_http(host, port)

        status, models_text = api_request(host, port, "GET", "/v1/models")
        if status != 200:
            raise RuntimeError(f"/v1/models returned {status}: {models_text}")
        models_payload = json.loads(models_text)
        description = models_payload["data"][0]["description"]
        if f"{backend}/" not in description:
            raise AssertionError(f"Model description does not reflect backend {backend!r}: {description}")

        request_body = {
            "model": "cybersecurity-agent",
            "stream": False,
            "user": f"verify-api-{uuid.uuid4().hex[:8]}",
            "messages": [{"role": "user", "content": scenario_prompt(scenario)}],
        }
        status, nonstream_text = api_request(host, port, "POST", "/v1/chat/completions", request_body)
        if status != 200:
            raise RuntimeError(f"Non-stream API returned {status}: {nonstream_text}")
        nonstream_payload = json.loads(nonstream_text)
        nonstream_content = nonstream_payload["choices"][0]["message"]["content"]
        assert_expected_output(nonstream_content, expected_text, "api-nonstream")

        request_body["stream"] = True
        request_body["user"] = f"verify-api-stream-{uuid.uuid4().hex[:8]}"
        status, stream_content = api_stream_request(host, port, request_body)
        if status != 200:
            raise RuntimeError(f"Stream API returned {status}")
        assert_expected_output(stream_content, expected_text, "api-stream")

        return {
            "models_description": description,
            "nonstream_response": normalize_output(nonstream_content),
            "stream_response": stream_content,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Cybersecurity Agent end-to-end behavior")
    parser.add_argument(
        "--mode",
        default="full",
        choices=["quick", "full", "provider-live"],
        help="Verification depth: quick=local truth only, full/provider-live=live backend checks",
    )
    parser.add_argument("--backend", default=DEFAULT_BACKEND, help="Backend to force (default: gemini)")
    parser.add_argument("--scenario", default="exact-load-skill", choices=sorted(SCENARIOS), help="Named smoke scenario")
    parser.add_argument("--skill", default=None, help="Override exact skill slug for the selected scenario")
    parser.add_argument("--json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()

    load_env_file()
    base_scenario = SCENARIOS[args.scenario]
    scenario = Scenario(
        name=base_scenario.name,
        slug=args.skill or base_scenario.slug,
        prompt_template=base_scenario.prompt_template,
        expected_tool_names=list(base_scenario.expected_tool_names),
        env_overrides=dict(base_scenario.env_overrides),
    )

    expected = expected_skill_values(scenario.slug)
    expected_text = expected_response(expected)

    summary = {
        "mode": args.mode,
        "backend": args.backend,
        "scenario": scenario.name,
        "skill": scenario.slug,
        "expected": expected,
        "checks": {},
    }

    exit_code = 0
    summary["checks"]["quick"] = run_quick_check(args.backend, scenario, expected)
    try:
        if args.mode in {"full", "provider-live"}:
            summary["checks"]["direct_agent"] = run_direct_agent_check(args.backend, scenario, expected_text)
            summary["checks"]["cli"] = run_cli_check(args.backend, scenario, expected_text)
            summary["checks"]["api"] = run_api_check(args.backend, scenario, expected_text)
    except VerificationBlocked as exc:
        summary["blocked"] = str(exc)
        exit_code = 2

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        if "quick" in summary["checks"]:
            print("PASS quick")
            print(f"  backend/model: {summary['checks']['quick']['backend']}/{summary['checks']['quick']['model']}")
            print(f"  api description: {summary['checks']['quick']['api_description']}")
        if "direct_agent" in summary["checks"]:
            print("PASS direct_agent")
            print(f"  backend/model: {summary['checks']['direct_agent']['backend']}/{summary['checks']['direct_agent']['model']}")
            tool_calls = [event for event in summary['checks']['direct_agent']['trace'] if event.get('event') == 'tool_call']
            print(f"  tool calls: {tool_calls}")
        if "cli" in summary["checks"]:
            print("PASS cli")
            print(f"  response: {summary['checks']['cli']['response']}")
        if "api" in summary["checks"]:
            print("PASS api")
            print(f"  models: {summary['checks']['api']['models_description']}")
            print(f"  response: {summary['checks']['api']['nonstream_response']}")
        if summary.get("blocked"):
            print(f"BLOCKED: {summary['blocked']}")

    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise
