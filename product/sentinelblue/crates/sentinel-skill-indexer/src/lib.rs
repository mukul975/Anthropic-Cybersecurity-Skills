use std::{fmt, fs, path::Path};

use sentinel_db::{Database, NewSkill, SkillUpsertStatus};
use serde::Deserialize;
use serde_yaml::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum SkillIndexError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Yaml(serde_yaml::Error),
    Database(String),
    MissingFrontmatter,
    MissingField(&'static str),
    MissingSkillFile(String),
}

impl fmt::Display for SkillIndexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON parse error: {error}"),
            Self::Yaml(error) => write!(formatter, "YAML parse error: {error}"),
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::MissingFrontmatter => write!(formatter, "skill file is missing YAML frontmatter"),
            Self::MissingField(field) => write!(formatter, "skill frontmatter missing {field}"),
            Self::MissingSkillFile(path) => write!(formatter, "skill file is missing: {path}"),
        }
    }
}

impl std::error::Error for SkillIndexError {}

impl From<std::io::Error> for SkillIndexError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for SkillIndexError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<serde_yaml::Error> for SkillIndexError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Yaml(value)
    }
}

impl From<rusqlite::Error> for SkillIndexError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SkillIndexError>;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SkillIndex {
    pub total_skills: usize,
    pub skills: Vec<IndexSkill>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IndexSkill {
    pub name: String,
    pub description: String,
    pub domain: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillMetadata {
    pub name: String,
    pub path: String,
    pub description: String,
    pub domain: String,
    pub subdomain: String,
    pub tags: Vec<String>,
    pub license: String,
    pub version: String,
    pub author: String,
    pub checksum_sha256: String,
    pub framework_mappings: FrameworkMappings,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FrameworkMappings {
    pub mitre_attack: Vec<String>,
    pub nist_csf: Vec<String>,
    pub mitre_atlas: Vec<String>,
    pub d3fend: Vec<String>,
    pub nist_ai_rmf: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndexReport {
    pub scanned: usize,
    pub indexed: usize,
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
}

pub fn parse_index_file(path: impl AsRef<Path>) -> Result<SkillIndex> {
    let content = fs::read_to_string(path)?;
    parse_index_json(&content)
}

pub fn parse_index_json(content: &str) -> Result<SkillIndex> {
    serde_json::from_str(content).map_err(SkillIndexError::from)
}

pub fn parse_skill_file(path: impl AsRef<Path>) -> Result<SkillMetadata> {
    let path = path.as_ref();
    let content = fs::read_to_string(path)?;
    parse_skill_text(&path.to_string_lossy(), &content)
}

pub fn index_skill_repository(
    database: &Database,
    repository_root: impl AsRef<Path>,
) -> Result<IndexReport> {
    let repository_root = repository_root.as_ref();
    let index = parse_index_file(repository_root.join("index.json"))?;
    let mut report = IndexReport {
        scanned: index.skills.len(),
        ..IndexReport::default()
    };

    for indexed_skill in index.skills {
        let skill_file = repository_root.join(&indexed_skill.path).join("SKILL.md");
        if !skill_file.exists() {
            return Err(SkillIndexError::MissingSkillFile(
                skill_file.to_string_lossy().to_string(),
            ));
        }

        let content = fs::read_to_string(&skill_file)?;
        let metadata = parse_skill_text(&indexed_skill.path, &content)?;
        let upsert = database.upsert_skill(NewSkill {
            name: &metadata.name,
            path: &metadata.path,
            description: &metadata.description,
            domain: &metadata.domain,
            subdomain: &metadata.subdomain,
            tags: &metadata.tags,
            license: &metadata.license,
            version: &metadata.version,
            author: &metadata.author,
            checksum: &metadata.checksum_sha256,
            mitre_attack: &metadata.framework_mappings.mitre_attack,
            nist_csf: &metadata.framework_mappings.nist_csf,
            mitre_atlas: &metadata.framework_mappings.mitre_atlas,
            d3fend: &metadata.framework_mappings.d3fend,
            nist_ai_rmf: &metadata.framework_mappings.nist_ai_rmf,
        })?;

        report.indexed += 1;
        match upsert.status {
            SkillUpsertStatus::Inserted => report.inserted += 1,
            SkillUpsertStatus::Updated => report.updated += 1,
            SkillUpsertStatus::Unchanged => report.unchanged += 1,
        }
    }

    Ok(report)
}

pub fn parse_skill_text(path: &str, content: &str) -> Result<SkillMetadata> {
    let frontmatter = extract_frontmatter(content)?;
    let value: Value = serde_yaml::from_str(&frontmatter)?;

    Ok(SkillMetadata {
        name: required_string(&value, "name")?,
        path: path.to_string(),
        description: required_string(&value, "description")?,
        domain: required_string(&value, "domain")?,
        subdomain: string_field(&value, "subdomain").unwrap_or_default(),
        tags: string_list(&value, "tags"),
        license: string_field(&value, "license").unwrap_or_default(),
        version: string_field(&value, "version").unwrap_or_default(),
        author: string_field(&value, "author").unwrap_or_default(),
        checksum_sha256: sha256_hex(content.as_bytes()),
        framework_mappings: FrameworkMappings {
            mitre_attack: string_list(&value, "mitre_attack"),
            nist_csf: string_list(&value, "nist_csf"),
            mitre_atlas: string_list(&value, "mitre_atlas"),
            d3fend: string_list(&value, "d3fend"),
            nist_ai_rmf: string_list(&value, "nist_ai_rmf")
                .into_iter()
                .chain(string_list(&value, "ai_rmf"))
                .collect(),
        },
    })
}

fn extract_frontmatter(content: &str) -> Result<String> {
    let mut lines = content.lines();
    if lines.next().map(str::trim) != Some("---") {
        return Err(SkillIndexError::MissingFrontmatter);
    }

    let mut frontmatter = Vec::new();
    for line in lines {
        if line.trim() == "---" {
            return Ok(frontmatter.join("\n"));
        }
        frontmatter.push(line);
    }

    Err(SkillIndexError::MissingFrontmatter)
}

fn required_string(value: &Value, field: &'static str) -> Result<String> {
    string_field(value, field).ok_or(SkillIndexError::MissingField(field))
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    let value = value.get(field)?;
    match value {
        Value::String(text) => Some(text.trim().to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
    .filter(|text| !text.is_empty())
}

fn string_list(value: &Value, field: &str) -> Vec<String> {
    match value.get(field) {
        Some(Value::Sequence(items)) => items.iter().filter_map(value_to_string).collect(),
        Some(item) => value_to_string(item).into_iter().collect(),
        None => Vec::new(),
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
    .filter(|text| !text.is_empty())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FIXTURE_SKILL: &str = r#"---
name: analyzing-demo-traffic
description: Analyze demo network traffic
domain: cybersecurity
subdomain: network-security
tags:
  - network-security
  - zeek
version: '1.0'
author: test-author
license: Apache-2.0
mitre_attack:
  - T1040
nist_csf:
  - DE.CM-01
nist_ai_rmf:
  - MEASURE-2.6
---
# Analyze Demo Traffic
"#;

    #[test]
    fn parses_root_index_json() {
        let index = parse_index_json(
            r#"{
              "total_skills": 1,
              "skills": [
                {
                  "name": "analyzing-demo-traffic",
                  "description": "Analyze demo network traffic",
                  "domain": "cybersecurity",
                  "path": "skills/analyzing-demo-traffic"
                }
              ]
            }"#,
        )
        .expect("index parses");

        assert_eq!(index.total_skills, 1);
        assert_eq!(index.skills[0].path, "skills/analyzing-demo-traffic");
    }

    #[test]
    fn parses_skill_frontmatter_and_checksum() {
        let metadata = parse_skill_text("skills/analyzing-demo-traffic/SKILL.md", FIXTURE_SKILL)
            .expect("skill parses");

        assert_eq!(metadata.name, "analyzing-demo-traffic");
        assert_eq!(metadata.subdomain, "network-security");
        assert_eq!(metadata.tags, vec!["network-security", "zeek"]);
        assert_eq!(metadata.framework_mappings.mitre_attack, vec!["T1040"]);
        assert_eq!(metadata.framework_mappings.nist_csf, vec!["DE.CM-01"]);
        assert_eq!(metadata.framework_mappings.nist_ai_rmf, vec!["MEASURE-2.6"]);
        assert_eq!(metadata.checksum_sha256.len(), 64);
    }

    #[test]
    fn parses_skill_file_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir exists");
        let path = dir.path().join("SKILL.md");
        std::fs::write(&path, FIXTURE_SKILL).expect("fixture writes");

        let metadata = parse_skill_file(&path).expect("skill file parses");

        assert_eq!(metadata.name, "analyzing-demo-traffic");
        assert_eq!(metadata.domain, "cybersecurity");
    }

    #[test]
    fn rejects_missing_frontmatter() {
        let error = parse_skill_text("SKILL.md", "# Missing frontmatter").unwrap_err();

        assert!(matches!(error, SkillIndexError::MissingFrontmatter));
    }

    #[test]
    fn durable_indexing_is_idempotent_and_reindexes_changed_skill() {
        let database = Database::open_initialized_memory().expect("database initializes");
        let repo = tempfile::tempdir().expect("repo tempdir exists");
        let skill_dir = repo.path().join("skills/analyzing-demo-traffic");
        std::fs::create_dir_all(&skill_dir).expect("skill dir creates");
        std::fs::write(skill_dir.join("SKILL.md"), FIXTURE_SKILL).expect("skill writes");
        std::fs::write(
            repo.path().join("index.json"),
            r#"{
              "total_skills": 1,
              "skills": [
                {
                  "name": "analyzing-demo-traffic",
                  "description": "Analyze demo network traffic",
                  "domain": "cybersecurity",
                  "path": "skills/analyzing-demo-traffic"
                }
              ]
            }"#,
        )
        .expect("index writes");

        let first = index_skill_repository(&database, repo.path()).expect("first index succeeds");
        assert_eq!(first.scanned, 1);
        assert_eq!(first.indexed, 1);
        assert_eq!(first.inserted, 1);

        let second = index_skill_repository(&database, repo.path()).expect("second index succeeds");
        assert_eq!(second.unchanged, 1);
        assert_eq!(database.skill_count().unwrap(), 1);

        let changed = FIXTURE_SKILL.replace(
            "Analyze demo network traffic",
            "Analyze demo packet traffic and Wazuh alerts",
        );
        std::fs::write(skill_dir.join("SKILL.md"), changed).expect("changed skill writes");

        let third = index_skill_repository(&database, repo.path()).expect("third index succeeds");
        assert_eq!(third.updated, 1);
        assert_eq!(database.skill_count().unwrap(), 1);

        let results = database.search_skills("Wazuh packet", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "skills/analyzing-demo-traffic");
    }

    #[test]
    fn indexes_repository_skill_fixture_set() {
        let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../..")
            .canonicalize()
            .expect("repository root resolves");
        let database = Database::open_initialized_memory().expect("database initializes");
        let index =
            parse_index_file(repository_root.join("index.json")).expect("root index parses");

        let report = index_skill_repository(&database, &repository_root)
            .expect("repository skill set indexes");

        assert_eq!(report.scanned, index.total_skills);
        assert_eq!(report.indexed, index.total_skills);
        assert_eq!(database.skill_count().unwrap(), index.total_skills as i64);
        assert!(
            database
                .search_skills("network traffic", 10)
                .expect("network traffic search works")
                .iter()
                .any(
                    |skill| skill.name.contains("network") || skill.description.contains("network")
                )
        );
        assert!(
            database
                .search_skills("Wazuh", 10)
                .expect("Wazuh search works")
                .iter()
                .any(|skill| skill.name.contains("wazuh") || skill.description.contains("Wazuh"))
        );
        assert!(
            database
                .search_skills("PowerShell", 10)
                .expect("PowerShell search works")
                .iter()
                .any(|skill| {
                    skill.name.to_lowercase().contains("powershell")
                        || skill.description.to_lowercase().contains("powershell")
                })
        );
        assert!(
            database
                .search_skills("DNS tunneling", 10)
                .expect("DNS tunneling search works")
                .iter()
                .any(|skill| {
                    let haystack = format!("{} {}", skill.name, skill.description).to_lowercase();
                    haystack.contains("dns") || haystack.contains("tunnel")
                })
        );
    }
}
