---
name: ALFA Agent Dashboard
description: Build or audit an agent status dashboard. Shows all agents with live status (working/idle/waiting/error/done), platform badges, brain type, last run time. Works without backend using React state + localStorage. Integrates with Cerber for trust_score and verdict display. Use when building multi-agent UIs or auditing agent visibility in ALFA runtime.
type: ui_component
author: Karen Tonoyan
version: 1.0
tags: [dashboard, agents, status, monitoring, real-time, react, alfa-runtime]
---

# ALFA Agent Dashboard Skill

## When to invoke this skill

- You are building a UI that shows multiple agents
- You need to display live agent status without a backend
- You want to add Cerber verdict visibility to a dashboard
- You are auditing an existing agent dashboard for completeness

---

## Core Pattern

```tsx
// 1. State
const [agentStatuses, setAgentStatuses] = useState<Record<string, AgentStatus>>({});

// 2. Sync active agent status
useEffect(() => {
  if (!selectedAgentId) return;
  setAgentStatuses(prev => ({ ...prev, [selectedAgentId]: status }));
}, [status, selectedAgentId]);

// 3. Read per card
const agentStatus = selectedAgentId === agent.id
  ? status
  : (agentStatuses[agent.id] ?? "idle");
```

---

## Status → Visual Mapping

```
idle     → grey dot,   static,  "Bezczynny"
working  → blue dot,   pulse,   "Pracuje"
waiting  → yellow dot, pulse,   "Czeka"
error    → red dot,    static,  "Blad"
done     → green dot,  static,  "Gotowe"
```

---

## Checklist before shipping

- [ ] Dashboard is accessible only to authenticated admin
- [ ] Status labels do not leak task content
- [ ] agentStatuses map does not persist sensitive data to localStorage
- [ ] Cards are clickable and switch active agent correctly
- [ ] Grid is responsive (1 / 2 / 3 columns)
- [ ] Live pulse animation works for working + waiting states
- [ ] Last run time formats correctly for local timezone
- [ ] Empty state handled (no agents yet)

---

## Cerber Readiness Check

Before shipping a dashboard to production, run:

```
Cerber check — dashboard:
[ ] Does it expose agent names to unauthenticated users? → NO required
[ ] Does it expose task content? → NO required
[ ] Does it allow write operations? → NO (read-only)
[ ] Is trust_score visible only to admin? → YES required
[ ] Are DESTROY/HOLD verdicts shown with appropriate context? → YES
```

Verdict: PASS only when all checks are met.

---

## Full component

See `skills/alfa-agent-dashboard/components/AgentDashboard.tsx`
