import { loadDashboardData, type ListResponse, type SkillSummary } from "./api";
import "./styles.css";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Missing #app root");
}

app.innerHTML = `
  <main class="shell">
    <aside class="sidebar" aria-label="Primary">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true"></span>
        <span>SentinelBlue</span>
      </div>
      <nav>
        <a class="active" href="#">Dashboard</a>
        <a href="#">Alerts</a>
        <a href="#">Cases</a>
        <a href="#">Events</a>
        <a href="#">Skills</a>
      </nav>
    </aside>
    <section class="content" aria-labelledby="page-title">
      <header class="topbar">
        <div>
          <p class="eyebrow">Local security monitoring</p>
          <h1 id="page-title">Operations dashboard</h1>
        </div>
        <span class="status" id="health-status">Loading</span>
      </header>
      <section class="summary-grid" aria-label="System summary">
        <div>
          <dt>Skills</dt>
          <dd id="skill-count">-</dd>
        </div>
        <div>
          <dt>Events</dt>
          <dd id="event-count">-</dd>
        </div>
        <div>
          <dt>Alerts</dt>
          <dd id="alert-count">-</dd>
        </div>
        <div>
          <dt>Cases</dt>
          <dd id="case-count">-</dd>
        </div>
      </section>
      <section class="workspace-grid">
        <section class="panel" aria-label="Health">
          <h2>Health</h2>
          <div id="health-detail" class="list-text">Waiting for API response.</div>
        </section>
        <section class="panel" aria-label="Network skill search">
          <h2>Network skills</h2>
          <div id="skills-list" class="list-text">Loading network skill results.</div>
        </section>
        <section class="panel" aria-label="Events">
          <h2>Events</h2>
          <div id="events-list" class="list-text">Loading events.</div>
        </section>
        <section class="panel" aria-label="Alerts">
          <h2>Alerts</h2>
          <div id="alerts-list" class="list-text">Loading alerts.</div>
        </section>
        <section class="panel" aria-label="Cases">
          <h2>Cases</h2>
          <div id="cases-list" class="list-text">Loading cases.</div>
        </section>
      </section>
    </section>
  </main>
`;

void hydrateDashboard();

async function hydrateDashboard() {
  try {
    const data = await loadDashboardData();
    setText("health-status", data.health.healthy ? "Healthy" : "Degraded");
    setText("skill-count", data.skills.total.toString());
    setText("event-count", data.events.total.toString());
    setText("alert-count", data.alerts.total.toString());
    setText("case-count", data.cases.total.toString());
    setHtml(
      "health-detail",
      data.health.components
        .map((component) => {
          return `<div class="row"><strong>${escapeHtml(component.name)}</strong><span>${escapeHtml(component.status)}</span></div>`;
        })
        .join(""),
    );
    setHtml("skills-list", renderSkills(data.skills));
    setHtml("events-list", renderSimpleList(data.events.items, "No events imported yet."));
    setHtml("alerts-list", renderSimpleList(data.alerts.items, "No alerts generated yet."));
    setHtml("cases-list", renderSimpleList(data.cases.items, "No cases created yet."));
  } catch (error) {
    setText("health-status", "Offline");
    setText("skill-count", "0");
    setText("event-count", "0");
    setText("alert-count", "0");
    setText("case-count", "0");
    setText(
      "health-detail",
      error instanceof Error ? error.message : "API unavailable",
    );
    setText("skills-list", "No API data available.");
    setText("events-list", "No API data available.");
    setText("alerts-list", "No API data available.");
    setText("cases-list", "No API data available.");
  }
}

function renderSkills(response: ListResponse<SkillSummary>): string {
  if (response.items.length === 0) {
    return "No network skill results.";
  }

  return response.items
    .slice(0, 6)
    .map((skill) => {
      return `<div class="row"><strong>${escapeHtml(skill.name)}</strong><span>${escapeHtml(skill.subdomain || skill.domain)}</span></div>`;
    })
    .join("");
}

function renderSimpleList(items: Array<Record<string, unknown>>, emptyText: string): string {
  if (items.length === 0) {
    return emptyText;
  }

  return items
    .slice(0, 6)
    .map((item) => {
      const title = String(item.title ?? item.event_type ?? item.id ?? "item");
      const meta = String(item.severity ?? item.source_product ?? item.status ?? "");
      return `<div class="row"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(meta)}</span></div>`;
    })
    .join("");
}

function setText(id: string, value: string) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function setHtml(id: string, value: string) {
  const element = document.getElementById(id);
  if (element) {
    element.innerHTML = value;
  }
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
