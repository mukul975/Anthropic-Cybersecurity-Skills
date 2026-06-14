"""
cyberagent/ollama_backend.py — Ollama local LLM backend.

Backend auto-detection:
  - If model supports OpenAI function calling → native tool_calls
  - If model rejects tools (e.g. dolphin-llama3) → ReAct prompting:
      model outputs ACTION/ARGS text blocks, we parse and dispatch.
"""

import json
import logging
import os
import re

import requests

log = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL", "dolphin-llama3")
OLLAMA_TIMEOUT  = int(os.environ.get("OLLAMA_TIMEOUT", "120"))

# Cached per-model tool support: True = native function calling, False = ReAct
_TOOL_SUPPORT_CACHE: dict = {}

# ReAct instructions appended to system prompt when native tools aren't supported
_REACT_TOOL_INSTRUCTIONS = """

--- TOOL USE INSTRUCTIONS ---
You are an AI agent with access to a cybersecurity skill library. 
You MUST use a tool to answer any question. 
DO NOT answer from your own knowledge. 

To call a tool, output EXACTLY this format and nothing else:

ACTION: <tool_name>
ARGS: {"key": "value"}

Available tools:
  search_skills        {"query": "search terms"}   — find relevant skills
  load_skill           {"slug": "skill-slug"}       — load full skill procedures
  list_skill_domains   {}                           — list all skill categories
  execute_skill_script {"slug": "skill-slug"}       — run a skill script

CRITICAL: Your very first response MUST be an ACTION block using search_skills to find the correct OSINT or cybersecurity procedure. 
--- END TOOL USE INSTRUCTIONS ---
"""


def is_ollama_running() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def list_local_models() -> list:
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        return []


def _tools_to_openai(tool_schemas: list) -> list:
    return [{
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
        }
    } for t in tool_schemas]


def _messages_to_oai(system: str, messages: list) -> list:
    """Anthropic-style messages → OpenAI format."""
    out = [{"role": "system", "content": system}]
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
        elif isinstance(content, list):
            for block in content:
                btype = block.get("type", "") if isinstance(block, dict) else getattr(block, "type", "")
                if btype == "text":
                    txt = block["text"] if isinstance(block, dict) else block.text
                    out.append({"role": role, "content": txt})
                elif btype == "tool_use":
                    if isinstance(block, dict):
                        name, args, bid = block["name"], json.dumps(block.get("input", {})), block["id"]
                    else:
                        name, args, bid = block.name, json.dumps(getattr(block, "input", {})), block.id
                    out.append({"role": "assistant", "content": None, "tool_calls": [{
                        "id": bid, "type": "function",
                        "function": {"name": name, "arguments": args}
                    }]})
                elif btype == "tool_result":
                    rc = block.get("content", "") if isinstance(block, dict) else ""
                    tid = block.get("tool_use_id", "") if isinstance(block, dict) else ""
                    out.append({"role": "tool", "tool_call_id": tid,
                                "content": rc if isinstance(rc, str) else json.dumps(rc)})
    return out


def _messages_to_react(system: str, messages: list) -> list:
    """Convert messages to plain text ReAct format."""
    out = [{"role": "system", "content": system + _REACT_TOOL_INSTRUCTIONS}]
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
        elif isinstance(content, list):
            parts = []
            for block in content:
                btype = block.get("type", "") if isinstance(block, dict) else getattr(block, "type", "")
                if btype == "text":
                    txt = block["text"] if isinstance(block, dict) else block.text
                    parts.append(txt)
                elif btype == "tool_use":
                    if isinstance(block, dict):
                        name, args = block["name"], json.dumps(block.get("input", {}))
                    else:
                        name, args = block.name, json.dumps(getattr(block, "input", {}))
                    parts.append(f"ACTION: {name}\nARGS: {args}")
                elif btype == "tool_result":
                    rc = block.get("content", "") if isinstance(block, dict) else ""
                    parts.append(f"TOOL RESULT: {rc if isinstance(rc, str) else json.dumps(rc)}")
            if parts:
                out.append({"role": role, "content": "\n".join(parts)})
    return out


def _parse_action(text: str):
    """Extract (tool_name, args_dict) from ReAct output, or (None, {})."""
    am = re.search(r"ACTION:\s*(\w+)", text)
    if not am:
        return None, {}
    name = am.group(1).strip()
    args = {}
    gm = re.search(r"ARGS:\s*(\{.*?\})", text, re.DOTALL)
    if gm:
        try:
            args = json.loads(gm.group(1))
        except Exception:
            pass
    return name, args


# ---------------------------------------------------------------------------
# Response + block wrappers
# ---------------------------------------------------------------------------

class _TextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _ToolUseBlock:
    def __init__(self, id, name, input):
        self.type = "tool_use"
        self.id = id
        self.name = name
        self.input = input


class OllamaResponse:
    def __init__(self, raw: dict, react_mode: bool = False):
        msg = raw.get("choices", [{}])[0].get("message", {})
        text = msg.get("content") or ""
        native_calls = msg.get("tool_calls") or []

        if react_mode and not native_calls:
            tool_name, args = _parse_action(text)
            if tool_name:
                self.stop_reason = "tool_use"
                self.content = [_ToolUseBlock(id="react_0", name=tool_name, input=args)]
                return

        self.stop_reason = "tool_use" if native_calls else "end_turn"
        self.content = []
        if text:
            self.content.append(_TextBlock(text))
        for tc in native_calls:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments", "{}"))
            except Exception:
                args = {}
            self.content.append(_ToolUseBlock(
                id=tc.get("id", "call_0"), name=fn.get("name", ""), input=args
            ))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OllamaClient:
    def __init__(self, model: str = OLLAMA_MODEL):
        self.model = model
        self.messages = _OllamaMessages(model)


class _OllamaMessages:

    def __init__(self, model: str):
        self.model = model

    def _has_native_tools(self, model: str) -> bool:
        if model in _TOOL_SUPPORT_CACHE:
            return _TOOL_SUPPORT_CACHE[model]
        probe = {
            "model": model,
            "messages": [{"role": "user", "content": "ping"}],
            "tools": [{"type": "function", "function": {
                "name": "test", "description": "test",
                "parameters": {"type": "object", "properties": {}}
            }}],
            "stream": False,
        }
        try:
            r = requests.post(f"{OLLAMA_BASE_URL}/v1/chat/completions",
                              json=probe, timeout=15)
            ok = r.status_code == 200
        except Exception:
            ok = False
        _TOOL_SUPPORT_CACHE[model] = ok
        log.info("Ollama %s native tool support: %s", model, ok)
        return ok

    def create(self, model=None, max_tokens=4096, system="",
               tools=None, messages=None, **kwargs) -> OllamaResponse:
        m = model or self.model
        react_mode = False

        if tools:
            if self._has_native_tools(m):
                payload = {
                    "model": m,
                    "messages": _messages_to_oai(system, messages or []),
                    "tools": _tools_to_openai(tools),
                    "max_tokens": max_tokens,
                    "stream": False,
                }
            else:
                react_mode = True
                payload = {
                    "model": m,
                    "messages": _messages_to_react(system, messages or []),
                    "max_tokens": max_tokens,
                    "stream": False,
                }
        else:
            payload = {
                "model": m,
                "messages": _messages_to_oai(system, messages or []),
                "max_tokens": max_tokens,
                "stream": False,
            }

        try:
            r = requests.post(f"{OLLAMA_BASE_URL}/v1/chat/completions",
                              json=payload, timeout=OLLAMA_TIMEOUT)
            r.raise_for_status()
            return OllamaResponse(r.json(), react_mode=react_mode)
        except requests.exceptions.Timeout:
            raise RuntimeError(
                f"Ollama timed out after {OLLAMA_TIMEOUT}s. "
                "Try: OLLAMA_TIMEOUT=240 python3 cyberagent.py"
            )
        except requests.exceptions.ConnectionError:
            raise RuntimeError("Cannot reach Ollama. Run: ollama serve")

    def stream(self, **kwargs):
        return _FakeStream(self.create(**kwargs))


class _FakeStream:
    def __init__(self, response: OllamaResponse):
        text = next((b.text for b in response.content if b.type == "text"), "")
        self.text_stream = iter([text])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass
