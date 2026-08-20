export type ListResponse<T> = {
  items: T[];
  total: number;
};

export type HealthResponse = {
  product: string;
  version: string;
  healthy: boolean;
  bind_addr: string;
  components: Array<{
    name: string;
    status: string;
    detail: string;
  }>;
};

export type SkillSummary = {
  id: string;
  name: string;
  path: string;
  domain: string;
  subdomain: string;
};

export type EventSummary = {
  id: string;
  source_product: string;
  event_time: string | null;
  event_type: string;
  host: string;
  user_name: string;
  src_ip: string;
  dest_ip: string;
  process_name: string;
  url: string;
  dns_query: string;
  severity: string;
  action: string;
};

export type AlertSummary = {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  status: string;
  attack_json: string;
  evidence_json: string;
};

export type CaseSummary = {
  id: string;
  title: string;
  status: string;
  severity: string;
  confidence: string;
  disposition: string;
  closed_at: string | null;
};

export type CaseTimelineItem = {
  item_type: string;
  item_id: string;
  case_id: string;
  alert_id: string | null;
  raw_event_id: string | null;
  normalized_event_id: string | null;
  summary: string;
  timeline_time: string;
};

export type DashboardData = {
  health: HealthResponse;
  skills: ListResponse<SkillSummary>;
  events: ListResponse<EventSummary>;
  alerts: ListResponse<AlertSummary>;
  cases: ListResponse<CaseSummary>;
};

export type ImportFileRequest = {
  path: string;
  source_name: string;
  source_product: string;
  format: "auto" | "json" | "jsonl";
};

export type ImportReport = {
  source_id: number;
  batch_id: string;
  scanned: number;
  imported: number;
  skipped: number;
  failed: number;
  normalized: number;
  errors: Array<{
    line: number | null;
    message: string;
  }>;
};

export type DetectionReport = {
  detector_id: string;
  detector_version: string;
  findings: unknown[];
  alerts_created: number;
};

export type CaseSummaryResult = {
  case_id: number;
  mode: string;
  model_name: string;
  model_health_status: string;
  ai_attempted: boolean;
  summary: string;
};

declare global {
  interface Window {
    __TAURI__?: {
      core?: {
        invoke<T>(command: string, args?: Record<string, unknown>): Promise<T>;
      };
    };
  }
}

export function hasDesktopApiBridge(): boolean {
  return typeof window.__TAURI__?.core?.invoke === "function";
}

export async function selectImportFile(): Promise<string | null> {
  return invokeDesktop<string | null>("select_import_file");
}

async function invokeDesktop<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T> {
  const invoke = window.__TAURI__?.core?.invoke;

  if (!invoke) {
    throw new Error("Desktop command bridge is unavailable.");
  }

  return invoke<T>(command, args);
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, {
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`${path} returned ${response.status}`);
  }

  return response.json() as Promise<T>;
}

async function postJson<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(await responseErrorMessage(response, path));
  }

  return response.json() as Promise<T>;
}

async function responseErrorMessage(response: Response, path: string): Promise<string> {
  try {
    const body = (await response.json()) as {
      error?: {
        message?: string;
      };
    };
    return body.error?.message ?? `${path} returned ${response.status}`;
  } catch {
    return `${path} returned ${response.status}`;
  }
}

export async function loadDashboardData(): Promise<DashboardData> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<DashboardData>("desktop_load_dashboard_data");
  }

  const [health, skills, events, alerts, cases] = await Promise.all([
    getJson<HealthResponse>("/api/health"),
    getJson<ListResponse<SkillSummary>>("/api/skills?q=network"),
    getJson<ListResponse<EventSummary>>("/api/events"),
    getJson<ListResponse<AlertSummary>>("/api/alerts"),
    getJson<ListResponse<CaseSummary>>("/api/cases"),
  ]);

  return {
    health,
    skills,
    events,
    alerts,
    cases,
  };
}

export async function loadCaseTimeline(
  caseId: string,
): Promise<ListResponse<CaseTimelineItem>> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<ListResponse<CaseTimelineItem>>("desktop_load_case_timeline", {
      request: { case_id: caseId },
    });
  }

  return getJson<ListResponse<CaseTimelineItem>>(`/api/cases/${caseId}/timeline`);
}

export async function importTelemetryFile(
  request: ImportFileRequest,
): Promise<ImportReport> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<ImportReport>("desktop_import_telemetry_file", { request });
  }

  return postJson<ImportReport>("/api/import-file", request);
}

export async function runDetectors(): Promise<DetectionReport[]> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<DetectionReport[]>("desktop_run_detectors");
  }

  return postJson<DetectionReport[]>("/api/detectors/run");
}

export async function promoteAlert(
  alertId: string,
  title?: string,
): Promise<CaseSummary> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<CaseSummary>("desktop_promote_alert", {
      request: { alert_id: alertId, title },
    });
  }

  return postJson<CaseSummary>(`/api/alerts/${alertId}/promote`, { title });
}

export async function summarizeCase(caseId: string): Promise<CaseSummaryResult> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<CaseSummaryResult>("desktop_summarize_case", {
      request: { case_id: caseId },
    });
  }

  return postJson<CaseSummaryResult>(`/api/cases/${caseId}/summarize`);
}

export async function closeCase(
  caseId: string,
  disposition: string,
  notes: string,
): Promise<CaseSummary> {
  if (hasDesktopApiBridge()) {
    return invokeDesktop<CaseSummary>("desktop_close_case", {
      request: { case_id: caseId, disposition, notes },
    });
  }

  return postJson<CaseSummary>(`/api/cases/${caseId}/close`, {
    disposition,
    notes,
  });
}
