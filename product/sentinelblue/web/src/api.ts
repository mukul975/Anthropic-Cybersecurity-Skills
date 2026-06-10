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

export async function loadDashboardData(): Promise<DashboardData> {
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
  return getJson<ListResponse<CaseTimelineItem>>(`/api/cases/${caseId}/timeline`);
}
