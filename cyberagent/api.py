import json
import time
import uuid
import logging
import hashlib
import os
from typing import AsyncIterator, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel

from .config import (
    API_ALLOWED_HOSTS,
    API_CORS_ALLOW_CREDENTIALS,
    API_CORS_ORIGINS,
    API_MAX_UPLOAD_MB,
    API_TOKEN,
    DROPZONE_DIR,
    validate_api_security_config,
)
from .retrieval import get_index
from .skill_loader import load_skills_block
from .session import new_session
from .agent import CybersecurityAgent, SYSTEM_PROMPT, _BACKEND, _MODEL

log = logging.getLogger(__name__)

DROPZONE_DIR.mkdir(parents=True, exist_ok=True)
validate_api_security_config()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Cybersecurity Skills Agent",
    description=f"754 cybersecurity skills · {_BACKEND}/{_MODEL} powered · OpenAI-compatible",
    version="2.0.0",
)

if API_ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=API_ALLOWED_HOSTS)

if API_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=API_CORS_ORIGINS,
        allow_credentials=API_CORS_ALLOW_CREDENTIALS,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

# Pre-warm the index on startup
@app.on_event("startup")
async def startup():
    log.info("Pre-warming skill index...")
    idx = get_index()
    log.info("Skill index ready: %d skills, semantic=%s", idx.count, idx.semantic_enabled)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

async def check_auth(request: Request):
    if not API_TOKEN:
        return  # No auth configured
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or auth[7:] != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API token")


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "cybersecurity-agent"
    messages: list[ChatMessage]
    stream: bool = False
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None  # ignored; Claude controls this
    user: Optional[str] = None  # Maps to session_id for persistent memory


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    idx = get_index()
    return {
        "status": "ok",
        "skills": idx.count,
        "semantic_search": idx.semantic_enabled,
    }


@app.post("/v1/upload")
async def upload_file(file: UploadFile = File(...), _=Depends(check_auth)):
    """Receive a file upload, save to Dropzone, return metadata."""
    contents = await file.read()
    max_bytes = API_MAX_UPLOAD_MB * 1024 * 1024
    if len(contents) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {API_MAX_UPLOAD_MB} MB upload limit")
    file_hash = hashlib.sha256(contents).hexdigest()
    original_name = file.filename or "upload.bin"
    safe_name = Path(original_name.replace("\\", "/")).name or "upload.bin"
    if safe_name.startswith("."):
        safe_name = f"upload_{safe_name.lstrip('.') or 'file'}"
    dest = DROPZONE_DIR / safe_name

    # If file with same name exists, add hash prefix
    if dest.exists():
        dest = DROPZONE_DIR / f"{file_hash[:8]}_{safe_name}"

    dest.write_bytes(contents)
    size_bytes = len(contents)

    # Human-readable size
    if size_bytes < 1024:
        size_str = f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        size_str = f"{size_bytes / 1024:.1f} KB"
    else:
        size_str = f"{size_bytes / (1024 * 1024):.1f} MB"

    log.info("File uploaded: %s (%s) -> %s", safe_name, size_str, dest)

    return {
        "status": "ok",
        "filename": dest.name,
        "original_name": original_name,
        "size": size_bytes,
        "size_human": size_str,
        "sha256": file_hash,
        "path": str(dest),
        "content_type": file.content_type or "application/octet-stream",
    }


@app.get("/v1/files")
async def list_files(_=Depends(check_auth)):
    """List all files in the Dropzone."""
    files = []
    for f in sorted(DROPZONE_DIR.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            stat = f.stat()
            size = stat.st_size
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            files.append({
                "name": f.name,
                "size": size,
                "size_human": size_str,
                "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
                "path": str(f),
            })
    return {"status": "ok", "count": len(files), "files": files}


@app.get("/v1/models")
async def list_models(_=Depends(check_auth)):
    return {
        "object": "list",
        "data": [
            {
                "id": "cybersecurity-agent",
                "object": "model",
                "created": 1700000000,
                "owned_by": "cyberagent",
                "description": f"754-skill cybersecurity analyst · {_BACKEND}/{_MODEL}",
            }
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(
    request: ChatCompletionRequest,
    _=Depends(check_auth),
):
    messages = request.messages
    if not messages:
        raise HTTPException(status_code=400, detail="No messages provided")

    # If the client provides a 'user' field, we treat it as the session ID
    # This enables persistent memory across API calls!
    session_id = request.user if request.user else new_session(name=f"api-{uuid.uuid4().hex[:6]}")
    
    # Extract the last message to send to the agent
    last_message = messages[-1].content

    # Instantiate the stateful agent
    agent = CybersecurityAgent(session_id=session_id)

    completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created = int(time.time())

    if request.stream:
        return StreamingResponse(
            _stream_response(agent, last_message, completion_id, created),
            media_type="text/event-stream",
        )

    # Non-streaming
    # The agent.chat() call will execute the full tool-use loop and return the final text
    text = agent.chat(last_message)

    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": "cybersecurity-agent",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }

async def _stream_response(
    agent,
    user_message: str,
    completion_id: str,
    created: int,
) -> AsyncIterator[str]:

    def _chunk(content: str, finish: Optional[str] = None) -> str:
        delta = {"content": content} if content else {}
        if finish:
            delta = {}
        payload = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": "cybersecurity-agent",
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish,
                }
            ],
        }
        return f"data: {json.dumps(payload)}\n\n"

    try:
        # agent.chat_stream automatically executes tools and yields text chunks of the final turn
        for text in agent.chat_stream(user_message):
            yield _chunk(text)
    except Exception as e:
        log.exception("Streaming error")
        yield _chunk(f"\n[Error: {e}]")
    finally:
        yield _chunk("", finish="stop")
        yield "data: [DONE]\n\n"
