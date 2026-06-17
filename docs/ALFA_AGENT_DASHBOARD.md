# ALFA Agent Dashboard — Specification

> **Version:** 1.0
> **Author:** Karen Tonoyan (ALFA Brain Project)
> **Repo:** Anthropic-and-Alfa-Security-Skill-whyd-graff-and-Alfa-brain
> **Purpose:** Specification for building an agent status dashboard that shows all agents and their live runtime states.

---

## Overview

The ALFA Agent Dashboard gives any user (or admin) a **real-time view of all agents** in the system — who is working, who is idle, who hit an error, and when each one last ran.

It is the operational layer that makes ALFA Brain visible. Without it, agents are invisible processes. With it, they are observable workers in a room.

---

## What the Dashboard Shows

Each agent appears as a card containing:

| Field | Source | Description |
|---|---|---|
| Agent name | agent.name | Display name |
| Status dot | live status state | Animated: Pracuje / Czeka / Gotowe / Blad / Bezczynny |
| Platform badges | agent.platforms | whatsapp, telegram, instagram, etc. |
| Brain type | agent.brain.type + model | ollama / lovable / openai-compatible |
| Last run | agent.lastRun (timestamp) | Formatted local time |
| Personality | agent.personality | Shown when card is selected |

---

## Status Definitions

| Status | Polish | Dot color | Animation | ALFA Runtime mapping |
|---|---|---|---|---|
| idle | Bezczynny | grey | static | Agent waiting, no task |
| working | Pracuje | blue | pulse | APPROVED + TOOL_GRANTED |
| waiting | Czeka | yellow | pulse | ON_TRACK but blocked |
| error | Blad | red | static | HOLD or pre-DESTROY |
| done | Gotowe | green | static | PASS issued |

---

## State Architecture

```
agentStatuses: Record<string, AgentStatus>
     ^
     |— useEffect([status, selectedAgentId])
           → agentStatuses[selectedAgentId] = status
```

- Each agent card reads: `selectedAgentId === agent.id ? status : agentStatuses[agent.id] ?? "idle"`
- The active agent always shows live React state
- Inactive agents show their last known status from the map
- No backend required — works with localStorage-based agents

---

## Layout

```
┌─────────────────────────────────────────────────────┐
│  Dashboard agentow                             live ● │
├──────────────┬──────────────┬──────────────────────┤
│  Agent A     │  Agent B     │  Agent C             │
│  ● Pracuje   │  ○ Bezczynny │  ● Czeka             │
│  [whatsapp]  │  [telegram]  │  [instagram][tiktok] │
│  ollama/     │  lovable     │  ollama/llama3        │
│  llama3.2    │              │                      │
│  11:42       │  wczoraj     │  11:39               │
└──────────────┴──────────────┴──────────────────────┘
```

Grid: 1 column mobile / 2 columns sm / 3 columns lg

---

## Cerber Integration

The dashboard is a **read-only observer** — it does not issue commands or write to Brain.

For Cerber-aware deployments:

```json
{
  "dashboard_event": {
    "agent_id": "agent-alpha-7",
    "status_change": "idle → working",
    "timestamp": "2026-06-17T10:00:00Z",
    "cerber_checkpoint": "ckpt-20260617-001",
    "trust_score": 8.2
  }
}
```

Cerber can read dashboard events to:
- Detect agents stuck in `waiting` for too long → issue HOLD
- Detect agents in `error` without recovery → issue DESTROY
- Track trajectory completeness across multiple agents

---

## OWASP / Security Notes

| Risk | Mitigation |
|---|---|
| Dashboard exposes agent topology | Dashboard is admin-only view, not public |
| Status data could leak task context | Status labels are opaque (Pracuje/Czeka, not task content) |
| Clicking a card switches active agent | Requires authenticated session |
| agentStatuses map persists in memory | Cleared on page reload — no persistent exposure |

---

## Extension Points

| Feature | How to add |
|---|---|
| Trust score per card | Read from Brain trust_ledger via API |
| Cerber verdict badge | Subscribe to /api/cerber-events SSE stream |
| Kill agent button | POST /api/agent/:id/kill → Cerber DESTROY |
| Restart button | POST /api/agent/:id/restart → REBUILT status |
| Filter by status | Add status filter chips above the grid |
| Sort by last run | Sort myAgents array by agent.lastRun desc |

---

*See skills/alfa-agent-dashboard/SKILL.md for the invocable skill.*
*See skills/alfa-agent-dashboard/components/AgentDashboard.tsx for the React component.*
