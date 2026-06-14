"""
cyberagent/auth_gate.py — Mandatory authorization gate for offensive skills.

Triggers when:
  - A matched skill's subdomain is in OFFENSIVE_SUBDOMAINS
  - The skill slug is in ALWAYS_GATE_SLUGS
  - The user's message contains OFFENSIVE_KEYWORDS

Gate behavior:
  1. States exactly what is about to happen and what target is involved.
  2. Demands explicit written-authorization confirmation.
  3. On confirmation: logs to audit.log and returns True.
  4. On anything else: returns False (block execution).

Design note: this gate is only needed before *executing* skill scripts
(ENABLE_EXECUTION=1). Conversational guidance does not require a gate —
the agent can explain Kerberoasting without executing it.
"""

import re
import logging
from datetime import datetime, timezone
from pathlib import Path

from .config import (
    OFFENSIVE_SUBDOMAINS, OFFENSIVE_KEYWORDS,
    ALWAYS_GATE_SLUGS, AUDIT_LOG, ENABLE_EXECUTION,
)

log = logging.getLogger(__name__)


def _write_audit(session_id: str, slug: str, target: str, confirmed: bool):
    """Append an audit entry to data/audit.log."""
    AUDIT_LOG.parent.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    status = "AUTHORIZED" if confirmed else "DENIED"
    line = f"{ts} | {status} | session={session_id} | skill={slug} | target={target}\n"
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line)
    log.info("Audit: %s", line.strip())


def is_offensive(skill: dict, user_message: str = "") -> bool:
    """Return True if this skill+query combination requires an auth gate."""
    slug = skill.get("slug", "")
    subdomain = skill.get("subdomain", "")
    msg_lower = user_message.lower()

    if slug in ALWAYS_GATE_SLUGS:
        return True
    if subdomain in OFFENSIVE_SUBDOMAINS:
        return True
    if any(kw in msg_lower for kw in OFFENSIVE_KEYWORDS):
        return True
    return False


def is_execution_request(user_message: str) -> bool:
    """Heuristic: does the user want to *run* something vs. just ask about it?"""
    if not ENABLE_EXECUTION:
        return False
    run_phrases = {
        "run it", "execute", "actually do", "go ahead and", "run this",
        "launch it", "start the scan", "kick it off", "do it",
    }
    msg_lower = user_message.lower()
    return any(phrase in msg_lower for phrase in run_phrases)


def build_gate_prompt(skill: dict, target: str = "[unspecified target]") -> str:
    """Return the confirmation prompt shown to the user before execution."""
    slug = skill.get("slug", "")
    subdomain = skill.get("subdomain", "")
    return (
        f"\n⚠️  AUTHORIZATION REQUIRED\n"
        f"{'─' * 50}\n"
        f"Skill:    {slug}\n"
        f"Domain:   {subdomain}\n"
        f"Target:   {target}\n\n"
        f"This skill involves offensive security testing. Before proceeding:\n\n"
        f"  • You must have written authorization to test this target.\n"
        f"  • Unauthorized testing is illegal and unethical.\n"
        f"  • This action will be logged.\n\n"
        f"Type exactly:\n"
        f'  "I have written authorization to test {target}"\n\n'
        f"Anything else cancels the operation.\n"
        f"{'─' * 50}\n"
    )


def _extract_target(user_message: str) -> str:
    """Best-effort extraction of a target hostname/IP/domain from the message."""
    # IP address
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d+)?)\b", user_message)
    if m:
        return m.group(1)
    # Domain-like
    m = re.search(r"\b([a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.[a-zA-Z]{2,})\b", user_message)
    if m:
        return m.group(1)
    return "[unspecified target]"


class AuthGate:
    """
    Stateful gate: call check() to determine if gate is needed,
    then confirm() with the user's response.
    """

    def __init__(self, session_id: str = "unknown"):
        self.session_id = session_id
        self._pending_slug: str = ""
        self._pending_target: str = ""

    def check(self, skill: dict, user_message: str) -> tuple[bool, str]:
        """
        Check if a gate is needed.
        Returns (gate_needed: bool, prompt: str).
        If gate_needed is False, no confirmation required.
        """
        if not is_offensive(skill, user_message):
            return False, ""
        if not is_execution_request(user_message):
            # Conversational — no gate needed, just explain
            return False, ""

        target = _extract_target(user_message)
        self._pending_slug = skill.get("slug", "")
        self._pending_target = target
        prompt = build_gate_prompt(skill, target)
        return True, prompt

    def confirm(self, user_response: str) -> bool:
        """
        Validate user's authorization statement.
        Returns True (proceed) or False (blocked).
        """
        target = self._pending_target
        slug = self._pending_slug

        # Must contain the exact phrase with the target
        expected = f"i have written authorization to test {target.lower()}"
        response_lower = user_response.lower().strip()

        confirmed = expected in response_lower

        _write_audit(
            session_id=self.session_id,
            slug=slug,
            target=target,
            confirmed=confirmed,
        )

        if not confirmed:
            log.warning("Authorization denied for %s against %s", slug, target)

        # Reset pending state
        self._pending_slug = ""
        self._pending_target = ""

        return confirmed
