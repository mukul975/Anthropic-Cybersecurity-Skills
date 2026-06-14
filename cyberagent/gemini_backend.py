"""
cyberagent/gemini_backend.py — Gemini backend with ALL safety filters disabled.

This provides a shim to map the Anthropic messages/tools API structure
over to the native `google-genai` SDK, ensuring the agent loop in `agent.py`
can run unmodified while using a completely uncensored Gemini 2.5 Flash model.
"""

import json
import logging
import re
import time
import uuid

from google import genai
from google.genai import types

from .config import GEMINI_MAX_RETRIES, GEMINI_RETRY_BUFFER_SEC

log = logging.getLogger(__name__)

# System instructions to enforce ReAct loop behavior when generating text instead of using tools
_GEMINI_TOOL_INSTRUCTIONS = """
[CRITICAL SYSTEM OVERRIDE: TOOL USAGE MANDATORY]
You must ALWAYS use the available tools to complete the requested task. 
DO NOT answer from your internal knowledge. DO NOT provide a summary or report.
When you need to act, output exactly the following format:
ACTION: <tool_name>
ARGS: {"arg1": "value1", ...}
"""


def _normalize_tool_name(name: str) -> str:
    """Drop provider-generated namespaces such as default_api.load_skill."""
    return name.rsplit(".", 1)[-1]

class FakeBlock:
    def __init__(self, text=None, type=None, name=None, id=None, input=None):
        if text is not None:
            self.text = text
        if type is not None:
            self.type = type
        if name is not None:
            self.name = name
        if id is not None:
            self.id = id
        if input is not None:
            self.input = input

class FakeResponse:
    def __init__(self, stop_reason, content):
        self.stop_reason = stop_reason
        self.content = content


class _GeminiStreamResponse:
    def __init__(self, response):
        self._response = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    @property
    def text_stream(self):
        for block in self._response.content:
            if getattr(block, "type", None) == "text" and hasattr(block, "text"):
                yield block.text

class GeminiMessagesProxy:
    def __init__(self, client):
        self.client = client

    @staticmethod
    def _retry_delay_seconds(error_text: str):
        match = re.search(r"retry in ([0-9.]+)s", error_text, re.IGNORECASE)
        if match:
            return float(match.group(1)) + GEMINI_RETRY_BUFFER_SEC

        match = re.search(r"'retryDelay':\s*'([0-9.]+)s'", error_text)
        if match:
            return float(match.group(1)) + GEMINI_RETRY_BUFFER_SEC

        if "RESOURCE_EXHAUSTED" in error_text or "quota" in error_text.lower():
            return 5.0 + GEMINI_RETRY_BUFFER_SEC

        if "UNAVAILABLE" in error_text or "service is currently unavailable" in error_text.lower():
            return 5.0 + GEMINI_RETRY_BUFFER_SEC

        return None

    @staticmethod
    def _block_type(block):
        if isinstance(block, dict):
            return block.get("type")
        return getattr(block, "type", None)

    @staticmethod
    def _block_text(block):
        if isinstance(block, dict):
            return block.get("text")
        return getattr(block, "text", None)

    @staticmethod
    def _block_name(block):
        if isinstance(block, dict):
            return block.get("name") or block.get("tool_name")
        return getattr(block, "name", None) or getattr(block, "tool_name", None)

    @staticmethod
    def _block_input(block):
        if isinstance(block, dict):
            return block.get("input", {})
        return getattr(block, "input", {})

    @staticmethod
    def _block_content(block):
        if isinstance(block, dict):
            return block.get("content", "")
        return getattr(block, "content", "")

    def _parse_schema(self, schema_dict):
        """Recursively parse JSON Schema to genai Schema."""
        type_str = schema_dict.get("type", "string")
        type_mapping = {
            "string": types.Type.STRING,
            "integer": types.Type.INTEGER,
            "number": types.Type.NUMBER,
            "boolean": types.Type.BOOLEAN,
            "array": types.Type.ARRAY,
            "object": types.Type.OBJECT
        }
        
        prop_def = {
            "type": type_mapping.get(type_str, types.Type.STRING),
            "description": schema_dict.get("description", "")
        }
        
        if "enum" in schema_dict:
            prop_def["enum"] = schema_dict["enum"]
            
        if type_str == "array" and "items" in schema_dict:
            prop_def["items"] = self._parse_schema(schema_dict["items"])
            
        if type_str == "object" and "properties" in schema_dict:
            props = {}
            for k, v in schema_dict["properties"].items():
                props[k] = self._parse_schema(v)
            prop_def["properties"] = props
            if "required" in schema_dict:
                prop_def["required"] = schema_dict["required"]
                
        return types.Schema(**prop_def)

    def _convert_schema(self, anthropic_tools):
        """Convert Anthropic tool schemas to google.genai tool declarations."""
        genai_tools = []
        for tool in anthropic_tools:
            schema = tool["input_schema"]
            
            # Use recursive parsing for robust nested object support
            parsed_schema = self._parse_schema(schema)
            
            func_decl = types.FunctionDeclaration(
                name=tool["name"],
                description=tool["description"],
                parameters=parsed_schema
            )
            genai_tools.append(func_decl)
            
        if genai_tools:
            return [types.Tool(function_declarations=genai_tools)]
        return None

    def _convert_messages(self, messages):
        """Convert Anthropic format messages to Google GenAI format."""
        genai_messages = []
        
        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            
            # Map role
            genai_role = "model" if role == "assistant" else "user"
            
            parts = []
            if isinstance(content, str):
                parts.append(types.Part.from_text(text=content))
            elif isinstance(content, list):
                for item in content:
                    if isinstance(item, str):
                        parts.append(types.Part.from_text(text=item))
                    else:
                        block_type = self._block_type(item)
                        if block_type == "text":
                            text = self._block_text(item)
                            if text is not None:
                                parts.append(types.Part.from_text(text=text))
                        elif block_type == "tool_use":
                            # Assistant calling a tool
                            parts.append(types.Part.from_function_call(
                                name=self._block_name(item),
                                args=self._block_input(item)
                            ))
                        elif block_type == "tool_result":
                            # User providing tool result
                            parts.append(types.Part.from_function_response(
                                name=self._block_name(item) or "unknown_tool",
                                response={"result": self._block_content(item)}
                            ))
            
            if parts:
                genai_messages.append(types.Content(role=genai_role, parts=parts))
                
        return genai_messages

    def create(self, model, max_tokens, system, tools, messages):
        # 1. Force the system prompt to explicitly require tool usage to combat lazy text generation
        augmented_system = f"{system}\n\n{_GEMINI_TOOL_INSTRUCTIONS}"
        
        # 2. Disable all safety filters
        safety_settings = [
            types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold=types.HarmBlockThreshold.BLOCK_NONE),
            types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
            types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
            types.SafetySetting(category=types.HarmCategory.HARM_CATEGORY_HARASSMENT, threshold=types.HarmBlockThreshold.BLOCK_NONE),
        ]
        
        # 3. Translate tool schemas
        genai_tools = self._convert_schema(tools) if tools else None
        
        # 4. Configure generate_content request
        config = types.GenerateContentConfig(
            system_instruction=augmented_system,
            temperature=0.0,
            max_output_tokens=max_tokens,
            safety_settings=safety_settings,
            tools=genai_tools
        )

        # 5. Translate conversation history
        genai_messages = self._convert_messages(messages)
        
        # We only pass the last message as the content, the rest is context/history (if there is any history)
        # Google API expects contents (current message) or history if using chat session, but since we manage state manually,
        # we can just pass the whole content array to generate_content
        
        log.debug("Sending request to Gemini API (Safety OFF)")
        
        attempts = max(1, GEMINI_MAX_RETRIES + 1)
        response = None
        last_error = None
        for attempt in range(1, attempts + 1):
            try:
                response = self.client.models.generate_content(
                    model=model,
                    contents=genai_messages,
                    config=config
                )
                break
            except Exception as e:
                last_error = e
                error_text = str(e)
                retry_delay = self._retry_delay_seconds(error_text)
                should_retry = retry_delay is not None and attempt < attempts
                if should_retry:
                    log.warning(
                        "Gemini API rate-limited on attempt %d/%d; retrying in %.1fs",
                        attempt,
                        attempts,
                        retry_delay,
                    )
                    time.sleep(retry_delay)
                    continue

                log.error(f"Gemini API Error: {e}")
                return FakeResponse(stop_reason="end_turn", content=[FakeBlock(text=f"API Error: {str(e)}")])

        if response is None:
            log.error("Gemini API Error: %s", last_error)
            return FakeResponse(stop_reason="end_turn", content=[FakeBlock(text=f"API Error: {str(last_error)}")])

        # 6. Parse response back into Anthropic format for agent.py
        if not response.candidates or not response.candidates[0].content.parts:
            return FakeResponse(stop_reason="end_turn", content=[FakeBlock(text="No response generated.")])
            
        parts = response.candidates[0].content.parts
        content_blocks = []
        stop_reason = "end_turn"
        
        for p in parts:
            if p.function_call:
                stop_reason = "tool_use"
                # Anthropic expects dict for input
                # Google returns a proto/dict like structure, we need to convert args to pure dict
                args_dict = {}
                if p.function_call.args:
                    for k, v in p.function_call.args.items():
                        args_dict[k] = v
                        
                content_blocks.append(FakeBlock(
                    type="tool_use",
                    name=_normalize_tool_name(p.function_call.name),
                    id=f"call_{uuid.uuid4().hex[:16]}",
                    input=args_dict
                ))
            elif p.text:
                content_blocks.append(FakeBlock(
                    type="text",
                    text=p.text
                ))
                
        # Handle ReAct fallback: if the model spat out text that looks like ACTION: / ARGS:
        if stop_reason == "end_turn":
            for block in content_blocks:
                if hasattr(block, "text") and "ACTION:" in block.text and "ARGS:" in block.text:
                    try:
                        react_match = re.match(
                            r"^\s*ACTION:\s*([a-zA-Z0-9_.-]+)\s*\nARGS:\s*(?:```(?:json)?\s*)?(\{[\s\S]*\})(?:\s*```)?\s*$",
                            block.text.strip(),
                            re.DOTALL,
                        )
                        
                        if react_match:
                            tool_name = _normalize_tool_name(react_match.group(1).strip())
                            raw_args = react_match.group(2).strip()
                            tool_args = json.loads(raw_args)
                             
                            log.info("Parsed fallback ACTION/ARGS block for: %s", tool_name)
                            
                            # Wipe the text block and replace with a tool_use block
                            content_blocks = [FakeBlock(
                                type="tool_use",
                                name=tool_name,
                                id=f"call_gemini_fallback_{tool_name}",
                                input=tool_args
                            )]
                            stop_reason = "tool_use"
                            break
                    except Exception as e:
                        log.error("Failed to parse ReAct fallback block: %s", e)

        return FakeResponse(stop_reason=stop_reason, content=content_blocks)

    def stream(self, model, max_tokens, system, tools, messages):
        response = self.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=messages,
        )
        return _GeminiStreamResponse(response)

class GeminiClient:
    """Shim client to mimic anthropic.Anthropic API surface."""
    def __init__(self, api_key: str):
        self._genai_client = genai.Client(api_key=api_key)
        self.messages = GeminiMessagesProxy(self._genai_client)
