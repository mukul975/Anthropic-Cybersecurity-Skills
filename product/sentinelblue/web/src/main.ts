import {
  closeCase,
  importTelemetryFile,
  loadCaseTimeline,
  loadDashboardData,
  promoteAlert,
  runDetectors,
  summarizeCase,
  type AlertSummary,
  type CaseSummary,
  type CaseTimelineItem,
  type DashboardData,
  type EventSummary,
  type HealthResponse,
  type ListResponse,
  type SkillSummary,
} from "./api";
import "./styles.css";

type Screen =
  | "dashboard"
  | "alerts"
  | "cases"
  | "events"
  | "skills"
  | "connectors"
  | "model"
  | "policy"
  | "audit";

type ThemeMode = "system" | "light" | "dark";

type AppState = {
  screen: Screen;
  theme: ThemeMode;
  data: DashboardData | null;
  selectedCaseId: string | null;
  timeline: ListResponse<CaseTimelineItem> | null;
  timelineCaseId: string | null;
  eventQuery: string;
  importPath: string;
  importSourceName: string;
  importSourceProduct: string;
  importFormat: "auto" | "json" | "jsonl";
  closeDisposition: string;
  closeNotes: string;
  loading: boolean;
  timelineLoading: boolean;
  busyAction: string | null;
  notice: string | null;
  error: string | null;
};

const app = document.querySelector<HTMLDivElement>("#app");
const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");

if (!app) {
  throw new Error("Missing #app root");
}

const screens: Array<{ id: Screen; label: string }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "alerts", label: "Alerts" },
  { id: "cases", label: "Cases" },
  { id: "events", label: "Events" },
  { id: "skills", label: "Skills" },
  { id: "connectors", label: "Connectors" },
  { id: "model", label: "Model" },
  { id: "policy", label: "Policy" },
  { id: "audit", label: "Audit" },
];

const state: AppState = {
  screen: "dashboard",
  theme: "system",
  data: null,
  selectedCaseId: null,
  timeline: null,
  timelineCaseId: null,
  eventQuery: "",
  importPath: "",
  importSourceName: "manual-file",
  importSourceProduct: "wazuh",
  importFormat: "auto",
  closeDisposition: "benign",
  closeNotes: "",
  loading: true,
  timelineLoading: false,
  busyAction: null,
  notice: null,
  error: null,
};

themeMedia.addEventListener("change", applyTheme);
applyTheme();
render();
void refreshData();

async function refreshData() {
  state.loading = true;
  state.error = null;
  state.notice = null;
  render();

  try {
    const data = await loadDashboardData();
    state.data = data;
    state.selectedCaseId ??= data.cases.items[0]?.id ?? null;
    state.loading = false;
    render();
    await ensureSelectedCaseTimeline();
  } catch (error) {
    state.data = null;
    state.loading = false;
    state.error = error instanceof Error ? error.message : "API unavailable";
    render();
  }
}

async function ensureSelectedCaseTimeline() {
  if (!state.selectedCaseId || state.timelineCaseId === state.selectedCaseId) {
    return;
  }

  state.timelineLoading = true;
  state.timeline = null;
  render();

  try {
    state.timeline = await loadCaseTimeline(state.selectedCaseId);
    state.timelineCaseId = state.selectedCaseId;
  } catch (error) {
    state.timeline = {
      items: [],
      total: 0,
    };
    state.timelineCaseId = state.selectedCaseId;
    state.error = error instanceof Error ? error.message : "Timeline unavailable";
  } finally {
    state.timelineLoading = false;
    render();
  }
}

function render() {
  applyTheme();
  app.innerHTML = `
    <main class="shell">
      <aside class="sidebar" aria-label="Primary">
        <div class="brand">
          <span class="brand-mark" aria-hidden="true"></span>
          <span>SentinelBlue</span>
        </div>
        <nav class="nav-list" aria-label="Workspace">
          ${screens
            .map(
              (screen) => `
                <button
                  type="button"
                  class="${screen.id === state.screen ? "active" : ""}"
                  data-screen="${screen.id}"
                >
                  ${escapeHtml(screen.label)}
                </button>
              `,
            )
            .join("")}
        </nav>
        <div class="theme-control" role="group" aria-label="Theme">
          ${renderThemeButton("system", "System")}
          ${renderThemeButton("light", "Light")}
          ${renderThemeButton("dark", "Dark")}
        </div>
      </aside>
      <section class="content" aria-labelledby="page-title">
        <header class="topbar">
          <div>
            <p class="eyebrow">Local security monitoring</p>
            <h1 id="page-title">${escapeHtml(screenTitle(state.screen))}</h1>
          </div>
          <div class="topbar-actions">
            <span class="status ${healthClass(state.data?.health)}">${healthLabel()}</span>
            <button class="button secondary" type="button" data-refresh>Refresh</button>
          </div>
        </header>
        ${renderOfflineBanner()}
        ${renderNoticeBanner()}
        ${renderScreen()}
      </section>
    </main>
  `;

  bindEvents();
}

function renderThemeButton(mode: ThemeMode, label: string): string {
  return `
    <button
      type="button"
      class="${state.theme === mode ? "active" : ""}"
      data-theme-mode="${mode}"
    >
      ${label}
    </button>
  `;
}

function renderScreen(): string {
  if (state.loading) {
    return renderLoading();
  }

  if (!state.data) {
    return renderEmptyState("Backend data is unavailable.");
  }

  switch (state.screen) {
    case "dashboard":
      return renderDashboard(state.data);
    case "alerts":
      return renderAlerts(state.data.alerts.items);
    case "cases":
      return renderCases(state.data.cases.items);
    case "events":
      return renderEvents(state.data.events.items);
    case "skills":
      return renderSkills(state.data.skills);
    case "connectors":
      return renderConnectors(state.data.health);
    case "model":
      return renderModelSettings(state.data.health);
    case "policy":
      return renderPolicySettings();
    case "audit":
      return renderAuditLog();
  }
}

function renderDashboard(data: DashboardData): string {
  const openCases = data.cases.items.filter((item) => item.status !== "closed").length;
  const highAlerts = data.alerts.items.filter((item) => item.severity === "high").length;

  return `
    <section class="summary-grid" aria-label="System summary">
      ${renderMetric("Skills", data.skills.total.toString(), "Indexed")}
      ${renderMetric("Events", data.events.total.toString(), "Normalized")}
      ${renderMetric("High alerts", highAlerts.toString(), "Open queue")}
      ${renderMetric("Open cases", openCases.toString(), "Triage")}
    </section>
    ${renderWorkflowPanel()}
    <section class="workspace-grid">
      ${renderPanel("Health", renderHealthComponents(data.health))}
      ${renderPanel("Alert queue", renderAlertRows(data.alerts.items.slice(0, 6)))}
      ${renderPanel("Case workspace", renderCaseRows(data.cases.items.slice(0, 6)))}
      ${renderPanel("Recent events", renderEventRows(data.events.items.slice(0, 6)))}
    </section>
  `;
}

function renderAlerts(alerts: AlertSummary[]): string {
  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Alert Queue</h2>
          <p>${alerts.length} alerts returned from the local API.</p>
        </div>
      </div>
      ${alerts.length === 0 ? renderEmptyState("No alerts generated.") : renderAlertRows(alerts, true)}
    </section>
  `;
}

function renderCases(cases: CaseSummary[]): string {
  const selectedCase = cases.find((item) => item.id === state.selectedCaseId) ?? cases[0];

  if (!selectedCase) {
    return renderEmptyState("No cases created.");
  }

  return `
    <section class="case-layout">
      <div class="case-list" aria-label="Cases">
        ${cases
          .map(
            (caseItem) => `
              <button
                type="button"
                class="case-select ${caseItem.id === selectedCase.id ? "active" : ""}"
                data-case-id="${escapeHtml(caseItem.id)}"
              >
                <span>${escapeHtml(caseItem.title)}</span>
                <small>${escapeHtml(caseItem.status)} · ${escapeHtml(caseItem.severity)}</small>
              </button>
            `,
          )
          .join("")}
      </div>
      <article class="case-detail">
        <div class="section-head">
          <div>
            <h2>${escapeHtml(selectedCase.title)}</h2>
            <p>Case #${escapeHtml(selectedCase.id)} · ${escapeHtml(selectedCase.status)} · ${escapeHtml(selectedCase.severity)}</p>
          </div>
          <div class="button-row">
            <button class="button secondary" type="button" data-action="summarize-case" ${busyAttr("summarize-case")}>Summarize</button>
          </div>
        </div>
        <dl class="detail-grid">
          <div><dt>Confidence</dt><dd>${escapeHtml(selectedCase.confidence)}</dd></div>
          <div><dt>Disposition</dt><dd>${escapeHtml(selectedCase.disposition || "Open")}</dd></div>
          <div><dt>Closed</dt><dd>${escapeHtml(selectedCase.closed_at ?? "No")}</dd></div>
        </dl>
        ${renderCloseCaseForm(selectedCase)}
        <h3>Timeline</h3>
        ${renderTimeline()}
      </article>
    </section>
  `;
}

function renderEvents(events: EventSummary[]): string {
  const query = state.eventQuery.trim().toLowerCase();
  const filtered = query
    ? events.filter((event) => eventSearchText(event).includes(query))
    : events;

  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Event Search</h2>
          <p>${filtered.length} events visible from ${events.length} API rows.</p>
        </div>
        <label class="search-box">
          <span>Search</span>
          <input id="event-search" type="search" value="${escapeHtml(state.eventQuery)}" placeholder="host, user, IP, process, URL" />
        </label>
      </div>
      ${filtered.length === 0 ? renderEmptyState("No matching events.") : renderEventRows(filtered)}
    </section>
  `;
}

function renderSkills(response: ListResponse<SkillSummary>): string {
  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Skill Library</h2>
          <p>${response.total} network-focused skills returned.</p>
        </div>
      </div>
      ${
        response.items.length === 0
          ? renderEmptyState("No skills returned.")
          : response.items
              .map(
                (skill) => `
                  <div class="data-row">
                    <div>
                      <strong>${escapeHtml(skill.name)}</strong>
                      <small>${escapeHtml(skill.path)}</small>
                    </div>
                    <span>${escapeHtml(skill.subdomain || skill.domain)}</span>
                  </div>
                `,
              )
              .join("")
      }
    </section>
  `;
}

function renderConnectors(health: HealthResponse): string {
  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Connectors</h2>
          <p>${health.components.length} health components visible.</p>
        </div>
        <button class="button secondary" type="button" disabled title="Connector mutation route unavailable">Add connector</button>
      </div>
      <div class="settings-grid">
        ${renderSettingTile("Manual file import", "Available through local server command", "Ready")}
        ${renderSettingTile("Wazuh", "Read-only connector target", "Not configured")}
        ${renderSettingTile("Network sensors", "Zeek and Suricata file sources", "Import-ready")}
        ${renderSettingTile("Identity logs", "Authentication telemetry source", "Import-ready")}
      </div>
    </section>
  `;
}

function renderModelSettings(health: HealthResponse): string {
  const model = health.components.find((component) => component.name === "model");

  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Model Settings</h2>
          <p>${escapeHtml(model?.detail ?? "No model health component returned.")}</p>
        </div>
        <button class="button secondary" type="button" data-action="summarize-case" ${state.selectedCaseId ? busyAttr("summarize-case") : "disabled"}>Test summary</button>
      </div>
      <div class="settings-grid">
        ${renderSettingTile("Runtime", escapeHtml(model?.detail ?? "Unknown"), escapeHtml(model?.status ?? "unknown"))}
        ${renderSettingTile("Fallback", "Deterministic evidence-cited summaries", "Enabled")}
        ${renderSettingTile("Prompt redaction", "Secret-like values redacted before model use", "Enabled")}
      </div>
    </section>
  `;
}

function renderPolicySettings(): string {
  const tiers = [
    ["Read-only", "Allowed"],
    ["Analysis-only", "Allowed"],
    ["Low-risk write", "Approval required"],
    ["Containment", "Elevated approval"],
    ["Destructive", "Blocked"],
    ["Lab-only", "Isolated"],
  ];

  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Policy Settings</h2>
          <p>Production action tiers.</p>
        </div>
        <button class="button secondary" type="button" disabled title="Policy editor unavailable">Edit policy</button>
      </div>
      <div class="settings-grid">
        ${tiers
          .map(([name, status]) => renderSettingTile(name, "Action tier", status))
          .join("")}
      </div>
    </section>
  `;
}

function renderAuditLog(): string {
  return `
    <section class="screen-band">
      <div class="section-head">
        <div>
          <h2>Audit Log</h2>
          <p>No audit records returned.</p>
        </div>
      </div>
      ${renderEmptyState("No audit records.")}
    </section>
  `;
}

function renderWorkflowPanel(): string {
  return `
    <section class="screen-band workflow-panel" aria-label="Local workflow">
      <div class="section-head">
        <div>
          <h2>Local Workflow</h2>
          <p>Import, detection, and investigation commands run against the local backend.</p>
        </div>
        <button class="button danger" type="button" disabled title="Approval gate unavailable">Containment action</button>
      </div>
      <div class="form-grid">
        ${renderField("Import file path", "import-path", state.importPath, "Path to JSON or JSONL telemetry")}
        ${renderField("Source name", "import-source-name", state.importSourceName, "manual-file")}
        ${renderField("Source product", "import-source-product", state.importSourceProduct, "wazuh, sysmon, zeek, suricata")}
        <label class="field">
          <span>Format</span>
          <select id="import-format">
            ${renderOption("auto", "Auto", state.importFormat)}
            ${renderOption("json", "JSON", state.importFormat)}
            ${renderOption("jsonl", "JSONL", state.importFormat)}
          </select>
        </label>
      </div>
      <div class="action-strip">
        <button class="button" type="button" data-action="import-file" ${busyAttr("import-file")}>Import logs</button>
        <button class="button secondary" type="button" data-action="run-detectors" ${busyAttr("run-detectors")}>Run detectors</button>
      </div>
    </section>
  `;
}

function renderField(
  label: string,
  id: string,
  value: string,
  placeholder: string,
): string {
  return `
    <label class="field">
      <span>${escapeHtml(label)}</span>
      <input id="${id}" type="text" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" />
    </label>
  `;
}

function renderOption(value: "auto" | "json" | "jsonl", label: string, selected: string): string {
  return `<option value="${value}" ${value === selected ? "selected" : ""}>${label}</option>`;
}

function renderCloseCaseForm(selectedCase: CaseSummary): string {
  if (selectedCase.status === "closed") {
    return "";
  }

  return `
    <section class="inline-form" aria-label="Close case">
      <div class="form-grid two">
        ${renderField("Disposition", "close-disposition", state.closeDisposition, "benign, malicious, false_positive")}
        <label class="field">
          <span>Closure notes</span>
          <textarea id="close-notes" rows="3" placeholder="Required review notes">${escapeHtml(state.closeNotes)}</textarea>
        </label>
      </div>
      <div class="action-strip">
        <button class="button secondary" type="button" data-action="close-case" ${busyAttr("close-case")}>Close case</button>
      </div>
    </section>
  `;
}

function renderMetric(label: string, value: string, meta: string): string {
  return `
    <div class="metric">
      <dt>${escapeHtml(label)}</dt>
      <dd>${escapeHtml(value)}</dd>
      <small>${escapeHtml(meta)}</small>
    </div>
  `;
}

function renderPanel(title: string, body: string): string {
  return `
    <section class="panel" aria-label="${escapeHtml(title)}">
      <h2>${escapeHtml(title)}</h2>
      ${body}
    </section>
  `;
}

function renderHealthComponents(health: HealthResponse): string {
  return health.components
    .map(
      (component) => `
        <div class="data-row">
          <div>
            <strong>${escapeHtml(component.name)}</strong>
            <small>${escapeHtml(component.detail)}</small>
          </div>
          <span class="pill ${statusTone(component.status)}">${escapeHtml(component.status)}</span>
        </div>
      `,
    )
    .join("");
}

function renderAlertRows(alerts: AlertSummary[], includeActions = false): string {
  if (alerts.length === 0) {
    return renderEmptyState("No alerts generated.");
  }

  return alerts
    .map(
      (alert) => `
        <div class="data-row">
          <div>
            <strong>${escapeHtml(alert.title)}</strong>
            <small>${escapeHtml(alert.description || "No description")}</small>
          </div>
          <span class="pill ${severityTone(alert.severity)}">${escapeHtml(alert.severity)}</span>
          <span>${Math.round(alert.confidence * 100)}%</span>
          ${
            includeActions
              ? `<button class="button secondary compact" type="button" data-promote-alert-id="${escapeHtml(alert.id)}" ${busyAttr(`promote-alert-${alert.id}`)}>Promote</button>`
              : `<span>${escapeHtml(alert.status)}</span>`
          }
        </div>
      `,
    )
    .join("");
}

function renderCaseRows(cases: CaseSummary[]): string {
  if (cases.length === 0) {
    return renderEmptyState("No cases created.");
  }

  return cases
    .map(
      (caseItem) => `
        <button type="button" class="data-row clickable" data-case-id="${escapeHtml(caseItem.id)}" data-screen-target="cases">
          <div>
            <strong>${escapeHtml(caseItem.title)}</strong>
            <small>Case #${escapeHtml(caseItem.id)} · ${escapeHtml(caseItem.confidence)}</small>
          </div>
          <span class="pill ${severityTone(caseItem.severity)}">${escapeHtml(caseItem.severity)}</span>
          <span>${escapeHtml(caseItem.status)}</span>
        </button>
      `,
    )
    .join("");
}

function renderEventRows(events: EventSummary[]): string {
  if (events.length === 0) {
    return renderEmptyState("No events imported.");
  }

  return events
    .map(
      (event) => `
        <div class="data-row event-row">
          <div>
            <strong>${escapeHtml(event.event_type || "event")} · ${escapeHtml(event.source_product)}</strong>
            <small>${escapeHtml(event.event_time ?? "No event time")}</small>
          </div>
          <span>${escapeHtml(event.host || event.src_ip || "-")}</span>
          <span>${escapeHtml(event.user_name || event.process_name || event.url || event.dns_query || "-")}</span>
          <span class="pill ${severityTone(event.severity)}">${escapeHtml(event.severity || "info")}</span>
        </div>
      `,
    )
    .join("");
}

function renderTimeline(): string {
  if (state.timelineLoading) {
    return renderEmptyState("Loading timeline.");
  }

  if (!state.timeline || state.timeline.items.length === 0) {
    return renderEmptyState("No timeline entries.");
  }

  return `
    <ol class="timeline">
      ${state.timeline.items
        .map(
          (item) => `
            <li>
              <div>
                <strong>${escapeHtml(timelineLabel(item.item_type))} #${escapeHtml(item.item_id)}</strong>
                <small>${escapeHtml(item.timeline_time)}</small>
              </div>
              <p>${escapeHtml(timelineSummary(item))}</p>
              <small>${renderEvidenceRefs(item)}</small>
            </li>
          `,
        )
        .join("")}
    </ol>
  `;
}

function renderEvidenceRefs(item: CaseTimelineItem): string {
  const refs = [
    item.alert_id ? `alert ${item.alert_id}` : "",
    item.raw_event_id ? `raw ${item.raw_event_id}` : "",
    item.normalized_event_id ? `event ${item.normalized_event_id}` : "",
  ].filter(Boolean);

  return escapeHtml(refs.join(" · ") || `case ${item.case_id}`);
}

function renderSettingTile(name: string, detail: string, status: string): string {
  return `
    <div class="setting-tile">
      <strong>${escapeHtml(name)}</strong>
      <span>${escapeHtml(detail)}</span>
      <small>${escapeHtml(status)}</small>
    </div>
  `;
}

function renderOfflineBanner(): string {
  if (!state.error) {
    return "";
  }

  return `<div class="banner" role="status">${escapeHtml(state.error)}</div>`;
}

function renderNoticeBanner(): string {
  if (!state.notice) {
    return "";
  }

  return `<div class="banner good" role="status">${escapeHtml(state.notice)}</div>`;
}

function renderLoading(): string {
  return `
    <section class="summary-grid" aria-label="Loading system summary">
      ${renderMetric("Skills", "-", "Loading")}
      ${renderMetric("Events", "-", "Loading")}
      ${renderMetric("Alerts", "-", "Loading")}
      ${renderMetric("Cases", "-", "Loading")}
    </section>
  `;
}

function renderEmptyState(message: string): string {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function bindEvents() {
  app.querySelectorAll<HTMLButtonElement>("[data-screen]").forEach((button) => {
    button.addEventListener("click", () => {
      state.screen = button.dataset.screen as Screen;
      render();
      if (state.screen === "cases") {
        void ensureSelectedCaseTimeline();
      }
    });
  });

  app.querySelectorAll<HTMLButtonElement>("[data-theme-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      state.theme = button.dataset.themeMode as ThemeMode;
      render();
    });
  });

  app.querySelector<HTMLButtonElement>("[data-refresh]")?.addEventListener("click", () => {
    void refreshData();
  });

  app.querySelectorAll<HTMLButtonElement>("[data-case-id]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedCaseId = button.dataset.caseId ?? state.selectedCaseId;
      if (button.dataset.screenTarget === "cases") {
        state.screen = "cases";
      }
      void ensureSelectedCaseTimeline();
      render();
    });
  });

  app.querySelector<HTMLInputElement>("#event-search")?.addEventListener("input", (event) => {
    state.eventQuery = event.currentTarget.value;
    render();
    const input = app.querySelector<HTMLInputElement>("#event-search");
    input?.focus();
    input?.setSelectionRange(state.eventQuery.length, state.eventQuery.length);
  });

  bindFormState();
  bindActionButtons();
}

function bindFormState() {
  app.querySelector<HTMLInputElement>("#import-path")?.addEventListener("input", (event) => {
    state.importPath = event.currentTarget.value;
  });
  app.querySelector<HTMLInputElement>("#import-source-name")?.addEventListener("input", (event) => {
    state.importSourceName = event.currentTarget.value;
  });
  app.querySelector<HTMLInputElement>("#import-source-product")?.addEventListener("input", (event) => {
    state.importSourceProduct = event.currentTarget.value;
  });
  app.querySelector<HTMLSelectElement>("#import-format")?.addEventListener("change", (event) => {
    state.importFormat = event.currentTarget.value as AppState["importFormat"];
  });
  app.querySelector<HTMLInputElement>("#close-disposition")?.addEventListener("input", (event) => {
    state.closeDisposition = event.currentTarget.value;
  });
  app.querySelector<HTMLTextAreaElement>("#close-notes")?.addEventListener("input", (event) => {
    state.closeNotes = event.currentTarget.value;
  });
}

function bindActionButtons() {
  app.querySelector<HTMLButtonElement>("[data-action='import-file']")?.addEventListener("click", () => {
    void importFileAction();
  });
  app.querySelector<HTMLButtonElement>("[data-action='run-detectors']")?.addEventListener("click", () => {
    void runDetectorAction();
  });
  app.querySelector<HTMLButtonElement>("[data-action='summarize-case']")?.addEventListener("click", () => {
    void summarizeCaseAction();
  });
  app.querySelector<HTMLButtonElement>("[data-action='close-case']")?.addEventListener("click", () => {
    void closeCaseAction();
  });
  app.querySelectorAll<HTMLButtonElement>("[data-promote-alert-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const alertId = button.dataset.promoteAlertId;
      if (alertId) {
        void promoteAlertAction(alertId);
      }
    });
  });
}

async function importFileAction() {
  if (!state.importPath.trim()) {
    state.error = "Import file path is required.";
    state.notice = null;
    render();
    return;
  }

  await runAction("import-file", async () => {
    const report = await importTelemetryFile({
      path: state.importPath.trim(),
      source_name: state.importSourceName.trim() || "manual-file",
      source_product: state.importSourceProduct.trim() || "custom",
      format: state.importFormat,
    });
    return `Imported ${report.imported} events, normalized ${report.normalized}, skipped ${report.skipped}.`;
  });
}

async function runDetectorAction() {
  await runAction("run-detectors", async () => {
    const reports = await runDetectors();
    const created = reports.reduce((sum, report) => sum + report.alerts_created, 0);
    return `Detector run completed across ${reports.length} detectors and created ${created} alerts.`;
  });
}

async function promoteAlertAction(alertId: string) {
  await runAction(`promote-alert-${alertId}`, async () => {
    const caseItem = await promoteAlert(alertId);
    state.selectedCaseId = caseItem.id;
    state.timeline = null;
    state.timelineCaseId = null;
    state.screen = "cases";
    return `Promoted alert ${alertId} to case ${caseItem.id}.`;
  });
}

async function summarizeCaseAction() {
  if (!state.selectedCaseId) {
    state.error = "Select a case before generating a summary.";
    state.notice = null;
    render();
    return;
  }

  await runAction("summarize-case", async () => {
    const summary = await summarizeCase(state.selectedCaseId ?? "");
    state.timeline = null;
    state.timelineCaseId = null;
    return `Generated ${summary.mode} summary for case ${summary.case_id}.`;
  });
}

async function closeCaseAction() {
  if (!state.selectedCaseId) {
    state.error = "Select a case before closing it.";
    state.notice = null;
    render();
    return;
  }
  if (!state.closeDisposition.trim() || !state.closeNotes.trim()) {
    state.error = "Disposition and closure notes are required.";
    state.notice = null;
    render();
    return;
  }

  await runAction("close-case", async () => {
    const caseItem = await closeCase(
      state.selectedCaseId ?? "",
      state.closeDisposition.trim(),
      state.closeNotes.trim(),
    );
    state.closeNotes = "";
    state.timeline = null;
    state.timelineCaseId = null;
    return `Closed case ${caseItem.id} as ${caseItem.disposition}.`;
  });
}

async function runAction(action: string, execute: () => Promise<string>) {
  state.busyAction = action;
  state.error = null;
  state.notice = null;
  render();

  try {
    state.notice = await execute();
    await refreshDataAfterMutation();
  } catch (error) {
    state.error = error instanceof Error ? error.message : "Action failed";
  } finally {
    state.busyAction = null;
    render();
  }
}

async function refreshDataAfterMutation() {
  const selectedCaseId = state.selectedCaseId;
  const data = await loadDashboardData();
  state.data = data;
  state.selectedCaseId =
    selectedCaseId && data.cases.items.some((caseItem) => caseItem.id === selectedCaseId)
      ? selectedCaseId
      : data.cases.items[0]?.id ?? null;
  if (state.selectedCaseId) {
    state.timeline = await loadCaseTimeline(state.selectedCaseId);
    state.timelineCaseId = state.selectedCaseId;
  }
}

function busyAttr(_action: string): string {
  return state.busyAction ? "disabled" : "";
}

function applyTheme() {
  const resolved =
    state.theme === "system" ? (themeMedia.matches ? "dark" : "light") : state.theme;
  document.documentElement.dataset.theme = resolved;
}

function screenTitle(screen: Screen): string {
  const screenConfig = screens.find((item) => item.id === screen);
  return screenConfig?.label ?? "Dashboard";
}

function healthLabel(): string {
  if (state.loading) {
    return "Loading";
  }
  if (!state.data) {
    return "Offline";
  }
  return state.data.health.healthy ? "Healthy" : "Degraded";
}

function healthClass(health?: HealthResponse): string {
  if (!health) {
    return "bad";
  }
  return health.healthy ? "good" : "warn";
}

function eventSearchText(event: EventSummary): string {
  return [
    event.id,
    event.source_product,
    event.event_time ?? "",
    event.event_type,
    event.host,
    event.user_name,
    event.src_ip,
    event.dest_ip,
    event.process_name,
    event.url,
    event.dns_query,
    event.severity,
    event.action,
  ]
    .join(" ")
    .toLowerCase();
}

function statusTone(status: string): string {
  if (status === "healthy" || status === "ready") {
    return "good";
  }
  if (status === "degraded" || status === "loading") {
    return "warn";
  }
  return "bad";
}

function severityTone(severity: string): string {
  const normalized = severity.toLowerCase();
  if (normalized === "critical" || normalized === "high" || Number(severity) >= 8) {
    return "bad";
  }
  if (normalized === "medium" || Number(severity) >= 5) {
    return "warn";
  }
  return "good";
}

function timelineLabel(itemType: string): string {
  return itemType.replace(/_/g, " ");
}

function timelineSummary(item: CaseTimelineItem): string {
  if (item.item_type !== "model_summary") {
    return item.summary;
  }

  try {
    const parsed = JSON.parse(item.summary) as { summary?: unknown };
    if (typeof parsed.summary === "string" && parsed.summary.trim().length > 0) {
      return parsed.summary;
    }
  } catch {
    return item.summary;
  }

  return item.summary;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    const entities: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return entities[character] ?? character;
  });
}
