use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Result, params};

pub const CURRENT_SCHEMA_VERSION: i64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "001_initial_schema",
        sql: include_str!("../migrations/001_initial_schema.sql"),
    },
    Migration {
        version: 2,
        name: "002_skill_fts",
        sql: include_str!("../migrations/002_skill_fts.sql"),
    },
    Migration {
        version: 3,
        name: "003_raw_event_hash_index",
        sql: include_str!("../migrations/003_raw_event_hash_index.sql"),
    },
    Migration {
        version: 4,
        name: "004_alert_description",
        sql: include_str!("../migrations/004_alert_description.sql"),
    },
];

#[derive(Debug)]
pub struct Database {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseHealth {
    pub schema_version: i64,
    pub applied_migrations: usize,
    pub core_table_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSkill {
    pub id: i64,
    pub name: String,
    pub path: String,
    pub description: String,
    pub domain: String,
    pub subdomain: String,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub id: i64,
    pub source_product: String,
    pub event_time: Option<String>,
    pub event_type: String,
    pub host: String,
    pub user_name: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub process_name: String,
    pub url: String,
    pub dns_query: String,
    pub severity: String,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySource {
    pub id: i64,
    pub name: String,
    pub source_type: String,
    pub connector_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRawEvent {
    pub id: i64,
    pub source_product: String,
    pub event_time: Option<String>,
    pub raw_payload: String,
    pub raw_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNormalizedEvent {
    pub id: i64,
    pub raw_event_id: Option<i64>,
    pub event_time: Option<String>,
    pub event_type: String,
    pub source_product: String,
    pub host: String,
    pub asset_id: String,
    pub user_name: String,
    pub user_id: String,
    pub src_ip: String,
    pub src_port: Option<i64>,
    pub dest_ip: String,
    pub dest_port: Option<i64>,
    pub protocol: String,
    pub dns_query: String,
    pub http_method: String,
    pub url: String,
    pub status_code: Option<i64>,
    pub process_name: String,
    pub process_path: String,
    pub parent_process_name: String,
    pub command_line: String,
    pub file_path: String,
    pub file_hash_sha256: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub action: String,
    pub fields_json: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredAlert {
    pub id: i64,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: f64,
    pub status: String,
    pub attack_json: String,
    pub evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDetectorRun {
    pub id: i64,
    pub detector_id: String,
    pub detector_version: String,
    pub input_query: String,
    pub status: String,
    pub finding_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvidence {
    pub id: i64,
    pub case_id: Option<i64>,
    pub alert_id: Option<i64>,
    pub raw_event_id: Option<i64>,
    pub normalized_event_id: Option<i64>,
    pub evidence_type: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCase {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub severity: String,
    pub confidence: String,
    pub disposition: String,
    pub closed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseTimelineItem {
    pub item_type: String,
    pub item_id: i64,
    pub case_id: i64,
    pub alert_id: Option<i64>,
    pub raw_event_id: Option<i64>,
    pub normalized_event_id: Option<i64>,
    pub summary: String,
    pub timeline_time: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredModelRun {
    pub id: i64,
    pub case_id: Option<i64>,
    pub model_name: String,
    pub prompt_hash: String,
    pub output_json: String,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillUpsertStatus {
    Inserted,
    Updated,
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillUpsert {
    pub id: i64,
    pub status: SkillUpsertStatus,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self { conn })
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self { conn })
    }

    pub fn open_initialized(path: impl AsRef<Path>) -> Result<Self> {
        let mut database = Self::open(path)?;
        database.initialize()?;
        Ok(database)
    }

    pub fn open_initialized_memory() -> Result<Self> {
        let mut database = Self::open_memory()?;
        database.initialize()?;
        Ok(database)
    }

    pub fn initialize(&mut self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_migrations (
               version INTEGER PRIMARY KEY,
               name TEXT NOT NULL,
               applied_at TEXT NOT NULL DEFAULT (datetime('now'))
             );",
        )?;

        for migration in MIGRATIONS {
            if !self.is_migration_applied(migration.version)? {
                let transaction = self.conn.transaction()?;
                transaction.execute_batch(migration.sql)?;
                transaction.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?1, ?2)",
                    params![migration.version, migration.name],
                )?;
                transaction.commit()?;
            }
        }

        Ok(())
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn schema_version(&self) -> Result<i64> {
        self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
    }

    pub fn applied_migration_count(&self) -> Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count as usize)
    }

    pub fn table_exists(&self, table_name: &str) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'virtual table') AND name = ?1 LIMIT 1",
                params![table_name],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn health(&self) -> Result<DatabaseHealth> {
        let mut core_table_count = 0;
        for table in CORE_TABLES {
            if self.table_exists(table)? {
                core_table_count += 1;
            }
        }

        Ok(DatabaseHealth {
            schema_version: self.schema_version()?,
            applied_migrations: self.applied_migration_count()?,
            core_table_count,
        })
    }

    pub fn insert_skill(&self, skill: NewSkill<'_>) -> Result<i64> {
        Ok(self.upsert_skill(skill)?.id)
    }

    pub fn upsert_skill(&self, skill: NewSkill<'_>) -> Result<SkillUpsert> {
        let existing = self.skill_by_path(skill.path)?;
        if let Some(existing) = &existing {
            if existing.checksum == skill.checksum {
                return Ok(SkillUpsert {
                    id: existing.id,
                    status: SkillUpsertStatus::Unchanged,
                });
            }
        }

        self.conn.execute(
            "INSERT INTO skills (
               name, path, description, domain, subdomain, tags_json, license, version,
               author, checksum, attack_json, nist_json, atlas_json, d3fend_json, ai_rmf_json
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(path) DO UPDATE SET
               name = excluded.name,
               description = excluded.description,
               domain = excluded.domain,
               subdomain = excluded.subdomain,
               tags_json = excluded.tags_json,
               license = excluded.license,
               version = excluded.version,
               author = excluded.author,
               checksum = excluded.checksum,
               attack_json = excluded.attack_json,
               nist_json = excluded.nist_json,
               atlas_json = excluded.atlas_json,
               d3fend_json = excluded.d3fend_json,
               ai_rmf_json = excluded.ai_rmf_json,
               updated_at = datetime('now')",
            params![
                skill.name,
                skill.path,
                skill.description,
                skill.domain,
                skill.subdomain,
                json_array(skill.tags)?,
                skill.license,
                skill.version,
                skill.author,
                skill.checksum,
                json_array(skill.mitre_attack)?,
                json_array(skill.nist_csf)?,
                json_array(skill.mitre_atlas)?,
                json_array(skill.d3fend)?,
                json_array(skill.nist_ai_rmf)?
            ],
        )?;

        let stored = self
            .skill_by_path(skill.path)?
            .expect("upserted skill should be queryable");
        self.refresh_skill_fts(stored.id, skill)?;

        Ok(SkillUpsert {
            id: stored.id,
            status: if existing.is_some() {
                SkillUpsertStatus::Updated
            } else {
                SkillUpsertStatus::Inserted
            },
        })
    }

    pub fn skill_count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM skills", [], |row| row.get(0))
    }

    pub fn skill_by_path(&self, path: &str) -> Result<Option<StoredSkill>> {
        self.conn
            .query_row(
                "SELECT id, name, path, description, domain, subdomain, checksum
                 FROM skills WHERE path = ?1",
                params![path],
                stored_skill_from_row,
            )
            .optional()
    }

    pub fn list_skills(&self, limit: usize) -> Result<Vec<StoredSkill>> {
        let mut statement = self.conn.prepare(
            "SELECT id, name, path, description, domain, subdomain, checksum
             FROM skills ORDER BY name LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], stored_skill_from_row)?;
        rows.collect()
    }

    pub fn search_skills(&self, query: &str, limit: usize) -> Result<Vec<StoredSkill>> {
        let fts_query = fts_query(query);
        if fts_query.is_empty() {
            return self.list_skills(limit);
        }

        let mut statement = self.conn.prepare(
            "SELECT s.id, s.name, s.path, s.description, s.domain, s.subdomain, s.checksum
             FROM skills_fts f
             JOIN skills s ON s.id = f.rowid
             WHERE skills_fts MATCH ?1
             ORDER BY bm25(skills_fts), s.name
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![fts_query, bounded_limit(limit)],
            stored_skill_from_row,
        )?;
        rows.collect()
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<StoredEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, source_product, event_time, event_type, host, user_name, src_ip,
                    dest_ip, process_name, url, dns_query, severity, action
             FROM normalized_events
             ORDER BY COALESCE(event_time, created_at) DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], |row| {
            Ok(StoredEvent {
                id: row.get(0)?,
                source_product: row.get(1)?,
                event_time: row.get(2)?,
                event_type: row.get(3)?,
                host: row.get(4)?,
                user_name: row.get(5)?,
                src_ip: row.get(6)?,
                dest_ip: row.get(7)?,
                process_name: row.get(8)?,
                url: row.get(9)?,
                dns_query: row.get(10)?,
                severity: row.get(11)?,
                action: row.get(12)?,
            })
        })?;
        rows.collect()
    }

    pub fn upsert_telemetry_source(&self, source: NewTelemetrySource<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO telemetry_sources (name, source_type, connector_kind, config_json, status)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
               source_type = excluded.source_type,
               connector_kind = excluded.connector_kind,
               config_json = excluded.config_json,
               status = excluded.status,
               updated_at = datetime('now')",
            params![
                source.name,
                source.source_type,
                source.connector_kind,
                source.config_json,
                source.status
            ],
        )?;

        self.conn.query_row(
            "SELECT id FROM telemetry_sources WHERE name = ?1",
            params![source.name],
            |row| row.get(0),
        )
    }

    pub fn telemetry_source_by_name(&self, name: &str) -> Result<Option<TelemetrySource>> {
        self.conn
            .query_row(
                "SELECT id, name, source_type, connector_kind
                 FROM telemetry_sources WHERE name = ?1",
                params![name],
                |row| {
                    Ok(TelemetrySource {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        source_type: row.get(2)?,
                        connector_kind: row.get(3)?,
                    })
                },
            )
            .optional()
    }

    pub fn raw_event_hash_exists(&self, raw_hash: &str) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM raw_events WHERE raw_hash = ?1 LIMIT 1",
                params![raw_hash],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    pub fn insert_raw_event(&self, raw_event: NewRawEvent<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO raw_events (
               source_id, source_product, event_time, raw_payload, raw_hash, ingest_batch
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                raw_event.source_id,
                raw_event.source_product,
                raw_event.event_time,
                raw_event.raw_payload,
                raw_event.raw_hash,
                raw_event.ingest_batch
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn raw_event_count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))
    }

    pub fn raw_events(&self, limit: usize) -> Result<Vec<StoredRawEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, source_product, event_time, raw_payload, raw_hash
             FROM raw_events
             ORDER BY id
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], |row| {
            Ok(StoredRawEvent {
                id: row.get(0)?,
                source_product: row.get(1)?,
                event_time: row.get(2)?,
                raw_payload: row.get(3)?,
                raw_hash: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn normalized_event_count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM normalized_events", [], |row| {
                row.get(0)
            })
    }

    pub fn normalized_events(&self, limit: usize) -> Result<Vec<StoredNormalizedEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT id, raw_event_id, event_time, event_type, source_product, host, asset_id,
                    user_name, user_id, src_ip, src_port, dest_ip, dest_port, protocol,
                    dns_query, http_method, url, status_code, process_name, process_path,
                    parent_process_name, command_line, file_path, file_hash_sha256, rule_id,
                    rule_name, severity, action, fields_json
             FROM normalized_events
             ORDER BY COALESCE(event_time, created_at) DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], |row| {
            Ok(StoredNormalizedEvent {
                id: row.get(0)?,
                raw_event_id: row.get(1)?,
                event_time: row.get(2)?,
                event_type: row.get(3)?,
                source_product: row.get(4)?,
                host: row.get(5)?,
                asset_id: row.get(6)?,
                user_name: row.get(7)?,
                user_id: row.get(8)?,
                src_ip: row.get(9)?,
                src_port: row.get(10)?,
                dest_ip: row.get(11)?,
                dest_port: row.get(12)?,
                protocol: row.get(13)?,
                dns_query: row.get(14)?,
                http_method: row.get(15)?,
                url: row.get(16)?,
                status_code: row.get(17)?,
                process_name: row.get(18)?,
                process_path: row.get(19)?,
                parent_process_name: row.get(20)?,
                command_line: row.get(21)?,
                file_path: row.get(22)?,
                file_hash_sha256: row.get(23)?,
                rule_id: row.get(24)?,
                rule_name: row.get(25)?,
                severity: row.get(26)?,
                action: row.get(27)?,
                fields_json: row.get(28)?,
            })
        })?;
        rows.collect()
    }

    pub fn insert_normalized_event(&self, event: NewNormalizedEvent<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO normalized_events (
               raw_event_id, event_time, event_type, source_product, host, asset_id,
               user_name, user_id, src_ip, src_port, dest_ip, dest_port, protocol,
               dns_query, http_method, url, status_code, process_name, process_path,
               parent_process_name, command_line, file_path, file_hash_sha256, rule_id,
               rule_name, severity, action, fields_json
             )
             VALUES (
               ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
               ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
               ?27, ?28
             )",
            params![
                event.raw_event_id,
                event.event_time,
                event.event_type,
                event.source_product,
                event.host,
                event.asset_id,
                event.user_name,
                event.user_id,
                event.src_ip,
                event.src_port,
                event.dest_ip,
                event.dest_port,
                event.protocol,
                event.dns_query,
                event.http_method,
                event.url,
                event.status_code,
                event.process_name,
                event.process_path,
                event.parent_process_name,
                event.command_line,
                event.file_path,
                event.file_hash_sha256,
                event.rule_id,
                event.rule_name,
                event.severity,
                event.action,
                event.fields_json,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn start_detector_run(&self, run: NewDetectorRun<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO detector_runs (detector_id, detector_version, input_query, status)
             VALUES (?1, ?2, ?3, 'running')",
            params![run.detector_id, run.detector_version, run.input_query],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn complete_detector_run(
        &self,
        detector_run_id: i64,
        status: &str,
        finding_count: usize,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE detector_runs
             SET status = ?1, finding_count = ?2, completed_at = datetime('now')
             WHERE id = ?3",
            params![status, finding_count as i64, detector_run_id],
        )?;
        Ok(())
    }

    pub fn detector_run_by_id(&self, id: i64) -> Result<Option<StoredDetectorRun>> {
        self.conn
            .query_row(
                "SELECT id, detector_id, detector_version, input_query, status, finding_count
                 FROM detector_runs WHERE id = ?1",
                params![id],
                |row| {
                    Ok(StoredDetectorRun {
                        id: row.get(0)?,
                        detector_id: row.get(1)?,
                        detector_version: row.get(2)?,
                        input_query: row.get(3)?,
                        status: row.get(4)?,
                        finding_count: row.get(5)?,
                    })
                },
            )
            .optional()
    }

    pub fn insert_alert(&self, alert: NewAlert<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO alerts (
               detector_run_id, title, description, severity, confidence, status, attack_json,
               evidence_json
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                alert.detector_run_id,
                alert.title,
                alert.description,
                alert.severity,
                alert.confidence,
                alert.status,
                alert.attack_json,
                alert.evidence_json
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_alert_evidence_json(&self, alert_id: i64, evidence_json: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE alerts SET evidence_json = ?1, updated_at = datetime('now') WHERE id = ?2",
            params![evidence_json, alert_id],
        )?;
        Ok(())
    }

    pub fn insert_evidence(&self, evidence: NewEvidence<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO evidence (
               case_id, alert_id, raw_event_id, normalized_event_id, evidence_type, summary
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                evidence.case_id,
                evidence.alert_id,
                evidence.raw_event_id,
                evidence.normalized_event_id,
                evidence.evidence_type,
                evidence.summary,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn evidence_for_alert(&self, alert_id: i64) -> Result<Vec<StoredEvidence>> {
        let mut statement = self.conn.prepare(
            "SELECT id, case_id, alert_id, raw_event_id, normalized_event_id, evidence_type, summary
             FROM evidence
             WHERE alert_id = ?1
             ORDER BY id",
        )?;
        let rows = statement.query_map(params![alert_id], |row| {
            Ok(StoredEvidence {
                id: row.get(0)?,
                case_id: row.get(1)?,
                alert_id: row.get(2)?,
                raw_event_id: row.get(3)?,
                normalized_event_id: row.get(4)?,
                evidence_type: row.get(5)?,
                summary: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    pub fn alert_by_id(&self, id: i64) -> Result<Option<StoredAlert>> {
        self.conn
            .query_row(
                "SELECT id, title, description, severity, confidence, status, attack_json, evidence_json
                 FROM alerts WHERE id = ?1",
                params![id],
                stored_alert_from_row,
            )
            .optional()
    }

    pub fn list_alerts(&self, limit: usize) -> Result<Vec<StoredAlert>> {
        let mut statement = self.conn.prepare(
            "SELECT id, title, description, severity, confidence, status, attack_json, evidence_json
             FROM alerts
             ORDER BY created_at DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], stored_alert_from_row)?;
        rows.collect()
    }

    pub fn list_cases(&self, limit: usize) -> Result<Vec<StoredCase>> {
        let mut statement = self.conn.prepare(
            "SELECT id, title, status, severity, confidence, disposition, closed_at
             FROM cases
             ORDER BY created_at DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], stored_case_from_row)?;
        rows.collect()
    }

    pub fn case_by_id(&self, id: i64) -> Result<Option<StoredCase>> {
        self.conn
            .query_row(
                "SELECT id, title, status, severity, confidence, disposition, closed_at
                 FROM cases WHERE id = ?1",
                params![id],
                stored_case_from_row,
            )
            .optional()
    }

    pub fn create_case(&self, case: NewCase<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO cases (title, status, severity, confidence, disposition)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                case.title,
                case.status,
                case.severity,
                case.confidence,
                case.disposition
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn promote_alert_to_case(&self, alert_id: i64, title: Option<&str>) -> Result<i64> {
        let alert = self.alert_by_id(alert_id)?.ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!("alert {alert_id} not found"))
        })?;
        let case_title = title.unwrap_or(&alert.title);
        let case_id = self.create_case(NewCase {
            title: case_title,
            status: "triage",
            severity: &alert.severity,
            confidence: &format!("{:.2}", alert.confidence),
            disposition: "",
        })?;

        self.conn.execute(
            "UPDATE alerts SET status = 'in_case', updated_at = datetime('now') WHERE id = ?1",
            params![alert_id],
        )?;
        self.conn.execute(
            "UPDATE evidence SET case_id = ?1 WHERE alert_id = ?2 AND case_id IS NULL",
            params![case_id, alert_id],
        )?;
        self.insert_evidence(NewEvidence {
            case_id: Some(case_id),
            alert_id: Some(alert_id),
            raw_event_id: None,
            normalized_event_id: None,
            evidence_type: "detector_alert",
            summary: &format!("Promoted alert: {}", alert.title),
        })?;

        Ok(case_id)
    }

    pub fn add_case_note(&self, case_id: i64, note: &str) -> Result<i64> {
        let note = note.trim();
        if note.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "case note is required".to_string(),
            ));
        }
        if self.case_by_id(case_id)?.is_none() {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "case {case_id} not found"
            )));
        }

        self.insert_evidence(NewEvidence {
            case_id: Some(case_id),
            alert_id: None,
            raw_event_id: None,
            normalized_event_id: None,
            evidence_type: "analyst_note",
            summary: note,
        })
    }

    pub fn close_case(&self, case_id: i64, disposition: &str, notes: &str) -> Result<()> {
        let disposition = disposition.trim();
        let notes = notes.trim();
        if disposition.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "case closure disposition is required".to_string(),
            ));
        }
        if notes.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "case closure notes are required".to_string(),
            ));
        }
        if self.case_by_id(case_id)?.is_none() {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "case {case_id} not found"
            )));
        }

        self.add_case_note(case_id, &format!("Closure note: {notes}"))?;
        self.conn.execute(
            "UPDATE cases
             SET status = 'closed', disposition = ?1, closed_at = datetime('now'), updated_at = datetime('now')
             WHERE id = ?2",
            params![disposition, case_id],
        )?;
        Ok(())
    }

    pub fn case_timeline(&self, case_id: i64) -> Result<Vec<CaseTimelineItem>> {
        let mut statement = self.conn.prepare(
            "SELECT item_type, item_id, case_id, alert_id, raw_event_id, normalized_event_id,
                    summary, timeline_time
             FROM (
               SELECT evidence_type AS item_type, id AS item_id, case_id, alert_id,
                      raw_event_id, normalized_event_id, summary, created_at AS timeline_time,
                      1 AS source_order
               FROM evidence
               WHERE case_id = ?1
               UNION ALL
               SELECT 'model_summary' AS item_type, id AS item_id, case_id, NULL AS alert_id,
                      NULL AS raw_event_id, NULL AS normalized_event_id, output_json AS summary,
                      started_at AS timeline_time, 2 AS source_order
               FROM model_runs
               WHERE case_id = ?1
               UNION ALL
               SELECT 'action' AS item_type, id AS item_id, case_id, NULL AS alert_id,
                      NULL AS raw_event_id, NULL AS normalized_event_id,
                      action_id || ' [' || status || ']' AS summary, created_at AS timeline_time,
                      3 AS source_order
               FROM actions
               WHERE case_id = ?1
             )
             ORDER BY timeline_time, source_order, item_id",
        )?;
        let rows = statement.query_map(params![case_id], |row| {
            Ok(CaseTimelineItem {
                item_type: row.get(0)?,
                item_id: row.get(1)?,
                case_id: row.get(2)?,
                alert_id: row.get(3)?,
                raw_event_id: row.get(4)?,
                normalized_event_id: row.get(5)?,
                summary: row.get(6)?,
                timeline_time: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn insert_model_run(&self, model_run: NewModelRun<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO model_runs (
               case_id, model_name, prompt_hash, output_json, status, completed_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, CASE WHEN ?5 = 'completed' THEN datetime('now') ELSE NULL END)",
            params![
                model_run.case_id,
                model_run.model_name,
                model_run.prompt_hash,
                model_run.output_json,
                model_run.status,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn model_runs_for_case(&self, case_id: i64) -> Result<Vec<StoredModelRun>> {
        let mut statement = self.conn.prepare(
            "SELECT id, case_id, model_name, prompt_hash, output_json, status
             FROM model_runs
             WHERE case_id = ?1
             ORDER BY started_at, id",
        )?;
        let rows = statement.query_map(params![case_id], |row| {
            Ok(StoredModelRun {
                id: row.get(0)?,
                case_id: row.get(1)?,
                model_name: row.get(2)?,
                prompt_hash: row.get(3)?,
                output_json: row.get(4)?,
                status: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    fn refresh_skill_fts(&self, rowid: i64, skill: NewSkill<'_>) -> Result<()> {
        self.conn
            .execute("DELETE FROM skills_fts WHERE rowid = ?1", params![rowid])?;
        self.conn.execute(
            "INSERT INTO skills_fts (rowid, name, description, domain, subdomain, tags, attack, nist, path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rowid,
                skill.name,
                skill.description,
                skill.domain,
                skill.subdomain,
                skill.tags.join(" "),
                skill.mitre_attack.join(" "),
                skill.nist_csf.join(" "),
                skill.path
            ],
        )?;
        Ok(())
    }

    fn is_migration_applied(&self, version: i64) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM schema_migrations WHERE version = ?1 LIMIT 1",
                params![version],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NewSkill<'a> {
    pub name: &'a str,
    pub path: &'a str,
    pub description: &'a str,
    pub domain: &'a str,
    pub subdomain: &'a str,
    pub tags: &'a [String],
    pub license: &'a str,
    pub version: &'a str,
    pub author: &'a str,
    pub checksum: &'a str,
    pub mitre_attack: &'a [String],
    pub nist_csf: &'a [String],
    pub mitre_atlas: &'a [String],
    pub d3fend: &'a [String],
    pub nist_ai_rmf: &'a [String],
}

#[derive(Debug, Clone, Copy)]
pub struct NewTelemetrySource<'a> {
    pub name: &'a str,
    pub source_type: &'a str,
    pub connector_kind: &'a str,
    pub config_json: &'a str,
    pub status: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewRawEvent<'a> {
    pub source_id: Option<i64>,
    pub source_product: &'a str,
    pub event_time: Option<&'a str>,
    pub raw_payload: &'a str,
    pub raw_hash: &'a str,
    pub ingest_batch: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewNormalizedEvent<'a> {
    pub raw_event_id: Option<i64>,
    pub event_time: Option<&'a str>,
    pub event_type: &'a str,
    pub source_product: &'a str,
    pub host: &'a str,
    pub asset_id: &'a str,
    pub user_name: &'a str,
    pub user_id: &'a str,
    pub src_ip: &'a str,
    pub src_port: Option<i64>,
    pub dest_ip: &'a str,
    pub dest_port: Option<i64>,
    pub protocol: &'a str,
    pub dns_query: &'a str,
    pub http_method: &'a str,
    pub url: &'a str,
    pub status_code: Option<i64>,
    pub process_name: &'a str,
    pub process_path: &'a str,
    pub parent_process_name: &'a str,
    pub command_line: &'a str,
    pub file_path: &'a str,
    pub file_hash_sha256: &'a str,
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub severity: &'a str,
    pub action: &'a str,
    pub fields_json: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewDetectorRun<'a> {
    pub detector_id: &'a str,
    pub detector_version: &'a str,
    pub input_query: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewAlert<'a> {
    pub detector_run_id: Option<i64>,
    pub title: &'a str,
    pub description: &'a str,
    pub severity: &'a str,
    pub confidence: f64,
    pub status: &'a str,
    pub attack_json: &'a str,
    pub evidence_json: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewEvidence<'a> {
    pub case_id: Option<i64>,
    pub alert_id: Option<i64>,
    pub raw_event_id: Option<i64>,
    pub normalized_event_id: Option<i64>,
    pub evidence_type: &'a str,
    pub summary: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewCase<'a> {
    pub title: &'a str,
    pub status: &'a str,
    pub severity: &'a str,
    pub confidence: &'a str,
    pub disposition: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub struct NewModelRun<'a> {
    pub case_id: Option<i64>,
    pub model_name: &'a str,
    pub prompt_hash: &'a str,
    pub output_json: &'a str,
    pub status: &'a str,
}

pub const CORE_TABLES: &[&str] = &[
    "skills",
    "telemetry_sources",
    "raw_events",
    "normalized_events",
    "alerts",
    "cases",
    "evidence",
    "detector_runs",
    "actions",
    "audit_events",
    "model_runs",
    "policies",
];

pub const AUXILIARY_TABLES: &[&str] = &["schema_migrations", "skills_fts"];

fn stored_skill_from_row(row: &rusqlite::Row<'_>) -> Result<StoredSkill> {
    Ok(StoredSkill {
        id: row.get(0)?,
        name: row.get(1)?,
        path: row.get(2)?,
        description: row.get(3)?,
        domain: row.get(4)?,
        subdomain: row.get(5)?,
        checksum: row.get(6)?,
    })
}

fn stored_alert_from_row(row: &rusqlite::Row<'_>) -> Result<StoredAlert> {
    Ok(StoredAlert {
        id: row.get(0)?,
        title: row.get(1)?,
        description: row.get(2)?,
        severity: row.get(3)?,
        confidence: row.get(4)?,
        status: row.get(5)?,
        attack_json: row.get(6)?,
        evidence_json: row.get(7)?,
    })
}

fn stored_case_from_row(row: &rusqlite::Row<'_>) -> Result<StoredCase> {
    Ok(StoredCase {
        id: row.get(0)?,
        title: row.get(1)?,
        status: row.get(2)?,
        severity: row.get(3)?,
        confidence: row.get(4)?,
        disposition: row.get(5)?,
        closed_at: row.get(6)?,
    })
}

fn json_array(values: &[String]) -> Result<String> {
    serde_json::to_string(values)
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))
}

fn bounded_limit(limit: usize) -> i64 {
    limit.clamp(1, 500) as i64
}

fn fts_query(query: &str) -> String {
    query
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_strings() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn migrations_create_core_tables() {
        let database = Database::open_initialized_memory().expect("database initializes");

        for table in CORE_TABLES {
            assert!(
                database.table_exists(table).expect("table check works"),
                "{table}"
            );
        }
        for table in AUXILIARY_TABLES {
            assert!(
                database.table_exists(table).expect("table check works"),
                "{table}"
            );
        }
        assert_eq!(database.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn initialization_is_idempotent() {
        let mut database = Database::open_memory().expect("database opens");

        database.initialize().expect("first migration run succeeds");
        database
            .initialize()
            .expect("second migration run succeeds");

        assert_eq!(
            database.applied_migration_count().unwrap(),
            MIGRATIONS.len()
        );
    }

    #[test]
    fn can_create_and_reopen_local_database() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let db_path = dir.path().join("sentinelblue.db");
        let empty = empty_strings();

        {
            let database = Database::open_initialized(&db_path).expect("database initializes");
            database
                .insert_skill(NewSkill {
                    name: "test-skill",
                    path: "skills/test-skill",
                    description: "Test skill",
                    domain: "cybersecurity",
                    subdomain: "network-security",
                    tags: &empty,
                    license: "",
                    version: "",
                    author: "",
                    checksum: "abc123",
                    mitre_attack: &empty,
                    nist_csf: &empty,
                    mitre_atlas: &empty,
                    d3fend: &empty,
                    nist_ai_rmf: &empty,
                })
                .expect("skill inserts");
        }

        let database = Database::open_initialized(&db_path).expect("database reopens");

        assert_eq!(database.skill_count().unwrap(), 1);
    }

    #[test]
    fn skill_upsert_refreshes_search_and_detects_unchanged_checksum() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let tags = vec!["network-security".to_string(), "zeek".to_string()];
        let attack = vec!["T1040".to_string()];
        let nist = vec!["DE.CM-01".to_string()];
        let empty = empty_strings();

        let inserted = database
            .upsert_skill(NewSkill {
                name: "analyzing-network-traffic",
                path: "skills/analyzing-network-traffic",
                description: "Analyze network traffic with Zeek",
                domain: "cybersecurity",
                subdomain: "network-security",
                tags: &tags,
                license: "Apache-2.0",
                version: "1.0",
                author: "tester",
                checksum: "checksum-a",
                mitre_attack: &attack,
                nist_csf: &nist,
                mitre_atlas: &empty,
                d3fend: &empty,
                nist_ai_rmf: &empty,
            })
            .expect("skill inserts");
        assert_eq!(inserted.status, SkillUpsertStatus::Inserted);

        let unchanged = database
            .upsert_skill(NewSkill {
                name: "analyzing-network-traffic",
                path: "skills/analyzing-network-traffic",
                description: "Analyze network traffic with Zeek",
                domain: "cybersecurity",
                subdomain: "network-security",
                tags: &tags,
                license: "Apache-2.0",
                version: "1.0",
                author: "tester",
                checksum: "checksum-a",
                mitre_attack: &attack,
                nist_csf: &nist,
                mitre_atlas: &empty,
                d3fend: &empty,
                nist_ai_rmf: &empty,
            })
            .expect("unchanged skill is skipped");
        assert_eq!(unchanged.status, SkillUpsertStatus::Unchanged);

        let updated = database
            .upsert_skill(NewSkill {
                name: "analyzing-network-traffic",
                path: "skills/analyzing-network-traffic",
                description: "Analyze packet traffic with Zeek and Suricata",
                domain: "cybersecurity",
                subdomain: "network-security",
                tags: &tags,
                license: "Apache-2.0",
                version: "1.0",
                author: "tester",
                checksum: "checksum-b",
                mitre_attack: &attack,
                nist_csf: &nist,
                mitre_atlas: &empty,
                d3fend: &empty,
                nist_ai_rmf: &empty,
            })
            .expect("changed skill updates");
        assert_eq!(updated.status, SkillUpsertStatus::Updated);
        assert_eq!(database.skill_count().unwrap(), 1);

        let results = database
            .search_skills("packet suricata", 10)
            .expect("search succeeds");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].checksum, "checksum-b");
    }

    #[test]
    fn basic_insert_query_works_for_core_entities() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let conn = database.connection();

        conn.execute(
            "INSERT INTO skills (name, path) VALUES ('skill-a', 'skills/skill-a')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO telemetry_sources (name, source_type, connector_kind)
             VALUES ('wazuh-dev', 'endpoint', 'file')",
            [],
        )
        .unwrap();
        let source_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO raw_events (source_id, source_product, raw_payload)
             VALUES (?1, 'wazuh', '{\"rule\":{}}')",
            params![source_id],
        )
        .unwrap();
        let raw_event_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO normalized_events (raw_event_id, event_type, source_product)
             VALUES (?1, 'alert', 'wazuh')",
            params![raw_event_id],
        )
        .unwrap();
        let normalized_event_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO detector_runs (detector_id, detector_version)
             VALUES ('detector.test', '0.1.0')",
            [],
        )
        .unwrap();
        let detector_run_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO alerts (detector_run_id, title, severity, confidence)
             VALUES (?1, 'Test alert', 'medium', 0.75)",
            params![detector_run_id],
        )
        .unwrap();
        let alert_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO cases (title, status, severity)
             VALUES ('Test case', 'triage', 'medium')",
            [],
        )
        .unwrap();
        let case_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO evidence (case_id, alert_id, raw_event_id, normalized_event_id, evidence_type, summary)
             VALUES (?1, ?2, ?3, ?4, 'event', 'Test evidence')",
            params![case_id, alert_id, raw_event_id, normalized_event_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO actions (case_id, action_id, tier)
             VALUES (?1, 'case.note', 'low-risk-write')",
            params![case_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO audit_events (actor, event_type, target_type, target_id)
             VALUES ('tester', 'case.created', 'case', ?1)",
            params![case_id.to_string()],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO model_runs (case_id, model_name, prompt_hash)
             VALUES (?1, 'deterministic-only', 'hash')",
            params![case_id],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO policies (name, mode, body_toml, active)
             VALUES ('default', 'production', 'mode = \"production\"', 1)",
            [],
        )
        .unwrap();

        for table in CORE_TABLES {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn read_models_list_events_alerts_and_cases() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let conn = database.connection();

        conn.execute(
            "INSERT INTO normalized_events (event_type, source_product, event_time)
             VALUES ('dns', 'zeek', '2026-06-09T12:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO alerts (title, severity, confidence, status)
             VALUES ('DNS beacon candidate', 'medium', 0.62, 'new')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO cases (title, status, severity)
             VALUES ('Suspicious DNS activity', 'triage', 'medium')",
            [],
        )
        .unwrap();

        assert_eq!(database.list_events(10).unwrap()[0].source_product, "zeek");
        assert_eq!(database.list_alerts(10).unwrap()[0].severity, "medium");
        assert_eq!(database.list_cases(10).unwrap()[0].status, "triage");
    }

    #[test]
    fn detector_run_alert_and_evidence_helpers_persist_links() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "sysmon",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "hash-detector",
                ingest_batch: "batch-detector",
            })
            .expect("raw event inserts");
        let normalized_event_id = database
            .insert_normalized_event(NewNormalizedEvent {
                raw_event_id: Some(raw_event_id),
                event_time: Some("2026-06-10T01:00:00Z"),
                event_type: "process_start",
                source_product: "sysmon",
                host: "win-host-01",
                asset_id: "asset-win-01",
                user_name: "ACME\\alice",
                user_id: "",
                src_ip: "",
                src_port: None,
                dest_ip: "",
                dest_port: None,
                protocol: "",
                dns_query: "",
                http_method: "",
                url: "",
                status_code: None,
                process_name: "powershell.exe",
                process_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                parent_process_name: "explorer.exe",
                command_line: "powershell.exe -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "sysmon-1",
                rule_name: "process_start",
                severity: "info",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");
        let detector_run_id = database
            .start_detector_run(NewDetectorRun {
                detector_id: "detector.test",
                detector_version: "0.1.0",
                input_query: "normalized_events",
            })
            .expect("detector run starts");
        let alert_id = database
            .insert_alert(NewAlert {
                detector_run_id: Some(detector_run_id),
                title: "Suspicious PowerShell encoded command",
                description: "PowerShell execution used an encoded command indicator.",
                severity: "high",
                confidence: 0.86,
                status: "new",
                attack_json: r#"[{"technique_id":"T1059.001"}]"#,
                evidence_json: "[]",
            })
            .expect("alert inserts");
        let evidence_id = database
            .insert_evidence(NewEvidence {
                case_id: None,
                alert_id: Some(alert_id),
                raw_event_id: Some(raw_event_id),
                normalized_event_id: Some(normalized_event_id),
                evidence_type: "normalized_event",
                summary: "Encoded PowerShell command line",
            })
            .expect("evidence inserts");
        database
            .update_alert_evidence_json(
                alert_id,
                &format!(
                    r#"[{{"evidence_id":{evidence_id},"raw_event_id":{raw_event_id},"normalized_event_id":{normalized_event_id}}}]"#
                ),
            )
            .expect("alert evidence updates");
        database
            .complete_detector_run(detector_run_id, "completed", 1)
            .expect("detector run completes");

        let run = database
            .detector_run_by_id(detector_run_id)
            .unwrap()
            .expect("run exists");
        assert_eq!(run.status, "completed");
        assert_eq!(run.finding_count, 1);
        let evidence = database.evidence_for_alert(alert_id).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].raw_event_id, Some(raw_event_id));
        assert_eq!(evidence[0].normalized_event_id, Some(normalized_event_id));
    }

    #[test]
    fn alert_can_be_promoted_to_case_with_chronological_timeline() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let raw_event_id = database
            .insert_raw_event(NewRawEvent {
                source_id: None,
                source_product: "wazuh",
                event_time: Some("2026-06-10T01:00:00Z"),
                raw_payload: "{}",
                raw_hash: "hash-case",
                ingest_batch: "batch-case",
            })
            .expect("raw event inserts");
        let normalized_event_id = database
            .insert_normalized_event(NewNormalizedEvent {
                raw_event_id: Some(raw_event_id),
                event_time: Some("2026-06-10T01:00:00Z"),
                event_type: "alert",
                source_product: "wazuh",
                host: "demo-host",
                asset_id: "001",
                user_name: "deploy",
                user_id: "",
                src_ip: "10.0.0.5",
                src_port: None,
                dest_ip: "",
                dest_port: None,
                protocol: "",
                dns_query: "",
                http_method: "",
                url: "",
                status_code: None,
                process_name: "powershell.exe",
                process_path: "",
                parent_process_name: "",
                command_line: "powershell.exe -EncodedCommand redacted",
                file_path: "",
                file_hash_sha256: "",
                rule_id: "100001",
                rule_name: "Suspicious command execution",
                severity: "8",
                action: "",
                fields_json: "{}",
            })
            .expect("normalized event inserts");
        let alert_id = database
            .insert_alert(NewAlert {
                detector_run_id: None,
                title: "Suspicious PowerShell encoded command",
                description: "PowerShell execution used an encoded command indicator.",
                severity: "high",
                confidence: 0.86,
                status: "new",
                attack_json: r#"[{"technique_id":"T1059.001"}]"#,
                evidence_json: "[]",
            })
            .expect("alert inserts");
        let alert_evidence_id = database
            .insert_evidence(NewEvidence {
                case_id: None,
                alert_id: Some(alert_id),
                raw_event_id: Some(raw_event_id),
                normalized_event_id: Some(normalized_event_id),
                evidence_type: "normalized_event",
                summary: "Encoded PowerShell evidence",
            })
            .expect("alert evidence inserts");

        let case_id = database
            .promote_alert_to_case(alert_id, None)
            .expect("alert promotes");
        let case = database.case_by_id(case_id).unwrap().expect("case exists");
        let alert = database
            .alert_by_id(alert_id)
            .unwrap()
            .expect("alert exists");
        let evidence = database.evidence_for_alert(alert_id).unwrap();

        assert_eq!(case.title, "Suspicious PowerShell encoded command");
        assert_eq!(case.status, "triage");
        assert_eq!(case.severity, "high");
        assert_eq!(case.confidence, "0.86");
        assert_eq!(alert.status, "in_case");
        assert!(evidence.iter().any(|item| item.id == alert_evidence_id
            && item.case_id == Some(case_id)
            && item.raw_event_id == Some(raw_event_id)
            && item.normalized_event_id == Some(normalized_event_id)));
        assert!(evidence
            .iter()
            .any(|item| item.case_id == Some(case_id) && item.evidence_type == "detector_alert"));

        let note_id = database
            .add_case_note(case_id, "Analyst reviewed encoded command evidence.")
            .expect("note inserts");
        database
            .connection()
            .execute(
                "UPDATE evidence SET created_at = CASE
                   WHEN id = ?1 THEN '2026-06-10T01:00:00Z'
                   WHEN id = ?2 THEN '2026-06-10T01:01:00Z'
                   ELSE '2026-06-10T01:02:00Z'
                 END
                 WHERE case_id = ?3",
                params![alert_evidence_id, note_id, case_id],
            )
            .unwrap();
        database
            .connection()
            .execute(
                "INSERT INTO actions (case_id, action_id, tier, status, created_at)
                 VALUES (?1, 'case.comment', 'low-risk-write', 'draft', '2026-06-10T01:03:00Z')",
                params![case_id],
            )
            .unwrap();
        database
            .connection()
            .execute(
                "INSERT INTO model_runs (case_id, model_name, output_json, started_at)
                 VALUES (?1, 'deterministic-summary', '{\"summary\":\"review\"}', '2026-06-10T01:04:00Z')",
                params![case_id],
            )
            .unwrap();

        let timeline = database.case_timeline(case_id).expect("timeline loads");
        let timeline_types = timeline
            .iter()
            .map(|item| item.item_type.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            timeline_types,
            vec![
                "normalized_event",
                "analyst_note",
                "detector_alert",
                "action",
                "model_summary"
            ]
        );
        assert!(
            timeline
                .windows(2)
                .all(|window| window[0].timeline_time <= window[1].timeline_time)
        );
    }

    #[test]
    fn closing_case_requires_disposition_and_notes() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let case_id = database
            .create_case(NewCase {
                title: "Suspicious DNS activity",
                status: "triage",
                severity: "medium",
                confidence: "0.70",
                disposition: "",
            })
            .expect("case creates");

        assert!(database.close_case(case_id, "", "reviewed").is_err());
        assert!(database.close_case(case_id, "benign", "").is_err());
        assert_eq!(
            database.case_by_id(case_id).unwrap().unwrap().status,
            "triage"
        );

        database
            .close_case(case_id, "benign", "Confirmed expected admin activity.")
            .expect("case closes");
        let closed = database.case_by_id(case_id).unwrap().expect("case exists");
        let timeline = database.case_timeline(case_id).expect("timeline loads");

        assert_eq!(closed.status, "closed");
        assert_eq!(closed.disposition, "benign");
        assert!(closed.closed_at.is_some());
        assert!(timeline.iter().any(|item| {
            item.item_type == "analyst_note"
                && item.summary.contains("Confirmed expected admin activity")
        }));
    }

    #[test]
    fn model_runs_are_persisted_and_returned_in_case_timeline() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let case_id = database
            .create_case(NewCase {
                title: "Suspicious PowerShell encoded command",
                status: "triage",
                severity: "high",
                confidence: "0.86",
                disposition: "",
            })
            .expect("case creates");
        let model_run_id = database
            .insert_model_run(NewModelRun {
                case_id: Some(case_id),
                model_name: "deterministic-case-summary",
                prompt_hash: "abc123",
                output_json: r#"{"summary":"Case summary","claims":[{"evidence_ids":[1]}]}"#,
                status: "completed",
            })
            .expect("model run inserts");

        let runs = database.model_runs_for_case(case_id).expect("runs list");
        let timeline = database.case_timeline(case_id).expect("timeline loads");

        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, model_run_id);
        assert_eq!(runs[0].status, "completed");
        assert_eq!(timeline.len(), 1);
        assert_eq!(timeline[0].item_type, "model_summary");
        assert_eq!(timeline[0].item_id, model_run_id);
        assert!(timeline[0].summary.contains("Case summary"));
    }
}
