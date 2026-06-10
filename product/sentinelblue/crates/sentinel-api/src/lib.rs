use sentinel_core::HealthSnapshot;
use serde::{Deserialize, Serialize};

pub const API_PREFIX: &str = "/api";
pub const HEALTH_ROUTE: &str = "/api/health";
pub const SKILLS_ROUTE: &str = "/api/skills";
pub const EVENTS_ROUTE: &str = "/api/events";
pub const ALERTS_ROUTE: &str = "/api/alerts";
pub const CASES_ROUTE: &str = "/api/cases";

pub fn bootstrap_health_response(version: &str) -> HealthSnapshot {
    HealthSnapshot::bootstrap(version)
}

pub fn initial_routes() -> [&'static str; 5] {
    [
        HEALTH_ROUTE,
        SKILLS_ROUTE,
        EVENTS_ROUTE,
        ALERTS_ROUTE,
        CASES_ROUTE,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("API error serializes")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListResponse<T> {
    pub items: Vec<T>,
    pub total: usize,
}

impl<T> ListResponse<T> {
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkillSummary {
    pub id: String,
    pub name: String,
    pub path: String,
    pub domain: String,
    pub subdomain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSummary {
    pub id: String,
    pub source_product: String,
    pub event_time: Option<String>,
    pub event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: f64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseSummary {
    pub id: String,
    pub title: String,
    pub status: String,
    pub severity: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_routes_are_api_routes() {
        for route in initial_routes() {
            assert!(route.starts_with(API_PREFIX));
        }
    }

    #[test]
    fn health_response_uses_core_snapshot() {
        let snapshot = bootstrap_health_response("0.1.0");

        assert_eq!(snapshot.product, "SentinelBlue");
        assert!(snapshot.is_healthy());
    }

    #[test]
    fn api_error_serializes_to_stable_shape() {
        let json = ApiError::new("not_found", "Route not found").to_json();

        assert_eq!(
            json,
            r#"{"error":{"code":"not_found","message":"Route not found"}}"#
        );
    }

    #[test]
    fn list_response_can_represent_empty_contracts() {
        let skills: ListResponse<SkillSummary> = ListResponse::empty();

        assert!(skills.items.is_empty());
        assert_eq!(skills.total, 0);
    }
}
