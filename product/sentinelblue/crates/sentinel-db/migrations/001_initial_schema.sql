CREATE TABLE IF NOT EXISTS skills (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  domain TEXT NOT NULL DEFAULT 'cybersecurity',
  subdomain TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  license TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  author TEXT NOT NULL DEFAULT '',
  checksum TEXT NOT NULL DEFAULT '',
  attack_json TEXT NOT NULL DEFAULT '[]',
  nist_json TEXT NOT NULL DEFAULT '[]',
  atlas_json TEXT NOT NULL DEFAULT '[]',
  d3fend_json TEXT NOT NULL DEFAULT '[]',
  ai_rmf_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS telemetry_sources (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  source_type TEXT NOT NULL,
  connector_kind TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'enabled',
  last_seen_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS raw_events (
  id INTEGER PRIMARY KEY,
  source_id INTEGER REFERENCES telemetry_sources(id) ON DELETE SET NULL,
  source_product TEXT NOT NULL DEFAULT '',
  event_time TEXT,
  raw_payload TEXT NOT NULL,
  raw_hash TEXT NOT NULL DEFAULT '',
  ingest_batch TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS normalized_events (
  id INTEGER PRIMARY KEY,
  raw_event_id INTEGER REFERENCES raw_events(id) ON DELETE CASCADE,
  event_time TEXT,
  event_type TEXT NOT NULL DEFAULT '',
  source_product TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  asset_id TEXT NOT NULL DEFAULT '',
  user_name TEXT NOT NULL DEFAULT '',
  user_id TEXT NOT NULL DEFAULT '',
  src_ip TEXT NOT NULL DEFAULT '',
  src_port INTEGER,
  dest_ip TEXT NOT NULL DEFAULT '',
  dest_port INTEGER,
  protocol TEXT NOT NULL DEFAULT '',
  dns_query TEXT NOT NULL DEFAULT '',
  http_method TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL DEFAULT '',
  status_code INTEGER,
  process_name TEXT NOT NULL DEFAULT '',
  process_path TEXT NOT NULL DEFAULT '',
  parent_process_name TEXT NOT NULL DEFAULT '',
  command_line TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL DEFAULT '',
  file_hash_sha256 TEXT NOT NULL DEFAULT '',
  rule_id TEXT NOT NULL DEFAULT '',
  rule_name TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT '',
  fields_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS detector_runs (
  id INTEGER PRIMARY KEY,
  detector_id TEXT NOT NULL,
  detector_version TEXT NOT NULL,
  input_query TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'completed',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT,
  finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  detector_run_id INTEGER REFERENCES detector_runs(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  confidence REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new',
  attack_json TEXT NOT NULL DEFAULT '[]',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  severity TEXT NOT NULL DEFAULT 'info',
  confidence TEXT NOT NULL DEFAULT 'unknown',
  disposition TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  closed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
  alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
  raw_event_id INTEGER REFERENCES raw_events(id) ON DELETE SET NULL,
  normalized_event_id INTEGER REFERENCES normalized_events(id) ON DELETE SET NULL,
  evidence_type TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY,
  case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
  action_id TEXT NOT NULL,
  tier TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  input_json TEXT NOT NULL DEFAULT '{}',
  expected_effect TEXT NOT NULL DEFAULT '',
  rollback_guidance TEXT NOT NULL DEFAULT '',
  approval_state TEXT NOT NULL DEFAULT 'not_required',
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY,
  actor TEXT NOT NULL DEFAULT 'system',
  event_type TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS model_runs (
  id INTEGER PRIMARY KEY,
  case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
  model_name TEXT NOT NULL DEFAULT '',
  prompt_hash TEXT NOT NULL DEFAULT '',
  output_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'completed',
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL DEFAULT 'production',
  body_toml TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_raw_events_source_id ON raw_events(source_id);
CREATE INDEX IF NOT EXISTS idx_normalized_events_raw_event_id ON normalized_events(raw_event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_detector_run_id ON alerts(detector_run_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_actions_case_id ON actions(case_id);
CREATE INDEX IF NOT EXISTS idx_model_runs_case_id ON model_runs(case_id);
