use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Result, params};

pub const CURRENT_SCHEMA_VERSION: i64 = 3;

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

#[derive(Debug, Clone, PartialEq)]
pub struct StoredAlert {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCase {
    pub id: i64,
    pub title: String,
    pub status: String,
    pub severity: String,
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
            "SELECT id, source_product, event_time, event_type
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

    pub fn insert_normalized_event(&self, event: NewNormalizedEvent<'_>) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO normalized_events (
               raw_event_id, event_time, event_type, source_product, host, asset_id,
               user_name, src_ip, command_line, rule_id, rule_name, severity, fields_json
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.raw_event_id,
                event.event_time,
                event.event_type,
                event.source_product,
                event.host,
                event.asset_id,
                event.user_name,
                event.src_ip,
                event.command_line,
                event.rule_id,
                event.rule_name,
                event.severity,
                event.fields_json,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_alerts(&self, limit: usize) -> Result<Vec<StoredAlert>> {
        let mut statement = self.conn.prepare(
            "SELECT id, title, severity, confidence, status
             FROM alerts
             ORDER BY created_at DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], |row| {
            Ok(StoredAlert {
                id: row.get(0)?,
                title: row.get(1)?,
                severity: row.get(2)?,
                confidence: row.get(3)?,
                status: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_cases(&self, limit: usize) -> Result<Vec<StoredCase>> {
        let mut statement = self.conn.prepare(
            "SELECT id, title, status, severity
             FROM cases
             ORDER BY created_at DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map(params![bounded_limit(limit)], |row| {
            Ok(StoredCase {
                id: row.get(0)?,
                title: row.get(1)?,
                status: row.get(2)?,
                severity: row.get(3)?,
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
    pub src_ip: &'a str,
    pub command_line: &'a str,
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub severity: &'a str,
    pub fields_json: &'a str,
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
}
