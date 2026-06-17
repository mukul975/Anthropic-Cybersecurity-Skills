/**
 * ALFA Agent Dashboard — standalone React component
 * Repository: Anthropic-and-Alfa-Security-Skill-whyd-graff-and-Alfa-brain
 * Author: Karen Tonoyan
 * Version: 1.0
 *
 * Drop this component into any TanStack Start / Vite React project.
 * Requires: tailwindcss, clsx or cn utility, lucide-react (optional).
 *
 * Props:
 *   agents          — array of PersonalAgent (from agent-store)
 *   selectedAgentId — currently active agent id (or null)
 *   activeStatus    — live AgentStatus of the selected agent
 *   onSelect        — callback(agentId: string) when card is clicked
 */

import { useEffect, useState } from "react";

// ── Types ────────────────────────────────────────────────────────────────────

export type AgentStatus = "idle" | "working" | "waiting" | "error" | "done";

export type AgentBrain = {
  type: "ollama" | "lovable" | "openai-compatible";
  baseURL?: string;
  model?: string;
  apiKey?: string;
};

export type PersonalAgent = {
  id: string;
  name: string;
  personality: string;
  brain: AgentBrain;
  platforms: string[];
  lastRun?: number;
  [key: string]: unknown;
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function cn(...classes: (string | undefined | false | null)[]): string {
  return classes.filter(Boolean).join(" ");
}

function formatLastRun(ts: number | undefined): string {
  if (!ts) return "nigdy";
  const d = new Date(ts);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) return d.toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString("pl-PL", { day: "2-digit", month: "2-digit" });
}

// ── Status config ─────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<AgentStatus, { label: string; dot: string; text: string }> = {
  idle:    { label: "Bezczynny", dot: "bg-gray-400",                     text: "text-gray-500" },
  working: { label: "Pracuje",   dot: "bg-blue-500 animate-pulse",       text: "text-blue-600" },
  waiting: { label: "Czeka",     dot: "bg-yellow-400 animate-pulse",     text: "text-yellow-600" },
  error:   { label: "Blad",      dot: "bg-red-500",                      text: "text-red-600" },
  done:    { label: "Gotowe",    dot: "bg-green-500",                    text: "text-green-600" },
};

// ── AgentCard ────────────────────────────────────────────────────────────────

interface AgentCardProps {
  agent: PersonalAgent;
  agentStatus: AgentStatus;
  isSelected: boolean;
  onClick: () => void;
}

function AgentCard({ agent, agentStatus, isSelected, onClick }: AgentCardProps) {
  const sc = STATUS_CONFIG[agentStatus];

  return (
    <button
      onClick={onClick}
      className={cn(
        "text-left rounded-xl border-2 p-3 transition-all duration-200",
        "hover:scale-[1.02] active:scale-[0.99]",
        isSelected
          ? "border-blue-500 bg-blue-50 dark:bg-blue-950/30"
          : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 hover:border-gray-400"
      )}
    >
      {/* Header: name + status */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="font-bold text-sm truncate text-gray-900 dark:text-gray-100">
          {agent.name}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <span className={cn("size-2 rounded-full", sc.dot)} />
          <span className={cn("text-[10px] font-semibold", sc.text)}>
            {sc.label}
          </span>
        </div>
      </div>

      {/* Platform badges */}
      <div className="flex flex-wrap gap-1 mb-2">
        {agent.platforms.map((p) => (
          <span
            key={p}
            className="text-[10px] px-1.5 py-0.5 rounded border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
          >
            {p}
          </span>
        ))}
        {agent.platforms.length === 0 && (
          <span className="text-[10px] text-gray-400">brak platform</span>
        )}
      </div>

      {/* Brain + last run */}
      <div className="text-[10px] text-gray-500 dark:text-gray-400 flex flex-wrap gap-x-3 gap-y-0.5">
        <span>
          {agent.brain.type}
          {agent.brain.model ? ` / ${agent.brain.model}` : ""}
        </span>
        <span>ostatni run: {formatLastRun(agent.lastRun)}</span>
      </div>

      {/* Personality — only when selected */}
      {isSelected && (
        <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-700 text-[10px] text-gray-500 dark:text-gray-400 truncate">
          {agent.personality}
        </div>
      )}
    </button>
  );
}

// ── AgentDashboard ───────────────────────────────────────────────────────────

interface AgentDashboardProps {
  agents: PersonalAgent[];
  selectedAgentId: string | null;
  activeStatus: AgentStatus;
  onSelect: (agentId: string) => void;
}

export function AgentDashboard({
  agents,
  selectedAgentId,
  activeStatus,
  onSelect,
}: AgentDashboardProps) {
  const [agentStatuses, setAgentStatuses] = useState<Record<string, AgentStatus>>({});

  // Sync active agent's live status into the map
  useEffect(() => {
    if (!selectedAgentId) return;
    setAgentStatuses((prev) => ({ ...prev, [selectedAgentId]: activeStatus }));
  }, [activeStatus, selectedAgentId]);

  if (agents.length === 0) {
    return (
      <div className="rounded-xl border-2 border-dashed border-gray-200 dark:border-gray-700 p-8 text-center">
        <p className="text-sm text-gray-500">Brak agentow. Stworz pierwszego agenta powyzej.</p>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs uppercase tracking-wider font-semibold text-gray-500 dark:text-gray-400">
          Dashboard agentow
        </div>
        <div className="text-[10px] text-gray-400 flex items-center gap-1.5">
          <span className="size-1.5 rounded-full bg-green-500 inline-block animate-pulse" />
          live
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {agents.map((agent) => {
          const agentStatus: AgentStatus =
            selectedAgentId === agent.id
              ? activeStatus
              : (agentStatuses[agent.id] ?? "idle");

          return (
            <AgentCard
              key={agent.id}
              agent={agent}
              agentStatus={agentStatus}
              isSelected={selectedAgentId === agent.id}
              onClick={() => onSelect(agent.id)}
            />
          );
        })}
      </div>
    </div>
  );
}

export default AgentDashboard;
