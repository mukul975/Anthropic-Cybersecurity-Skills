use std::path::{Path, PathBuf};

pub const PRODUCT_NAME: &str = "SentinelBlue";
pub const DEFAULT_API_BIND_ADDR: &str = "127.0.0.1:8741";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentStatus {
    Healthy,
    Degraded,
    Unavailable,
}

impl ComponentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentHealth {
    pub name: String,
    pub status: ComponentStatus,
    pub detail: String,
}

impl ComponentHealth {
    pub fn healthy(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ComponentStatus::Healthy,
            detail: detail.into(),
        }
    }

    pub fn degraded(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ComponentStatus::Degraded,
            detail: detail.into(),
        }
    }

    pub fn unavailable(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ComponentStatus::Unavailable,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub product: String,
    pub version: String,
    pub components: Vec<ComponentHealth>,
}

impl HealthSnapshot {
    pub fn bootstrap(version: impl Into<String>) -> Self {
        Self {
            product: PRODUCT_NAME.to_string(),
            version: version.into(),
            components: vec![ComponentHealth::healthy(
                "workspace",
                "product workspace initialized",
            )],
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.components
            .iter()
            .all(|component| component.status == ComponentStatus::Healthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePaths {
    pub root: PathBuf,
    pub crates: PathBuf,
    pub web: PathBuf,
    pub packaging: PathBuf,
    pub sample_data: PathBuf,
    pub docs: PathBuf,
}

impl WorkspacePaths {
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            crates: root.join("crates"),
            web: root.join("web"),
            packaging: root.join("packaging"),
            sample_data: root.join("sample-data"),
            docs: root.join("docs"),
            root,
        }
    }

    pub fn required_paths(&self) -> [&Path; 6] {
        [
            self.root.as_path(),
            self.crates.as_path(),
            self.web.as_path(),
            self.packaging.as_path(),
            self.sample_data.as_path(),
            self.docs.as_path(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_health_is_healthy() {
        let snapshot = HealthSnapshot::bootstrap("0.1.0");

        assert_eq!(snapshot.product, PRODUCT_NAME);
        assert!(snapshot.is_healthy());
        assert_eq!(snapshot.components[0].status.as_str(), "healthy");
    }

    #[test]
    fn workspace_paths_are_derived_from_root() {
        let paths = WorkspacePaths::from_root("/tmp/sentinelblue");

        assert_eq!(paths.web, PathBuf::from("/tmp/sentinelblue/web"));
        assert_eq!(
            paths.sample_data,
            PathBuf::from("/tmp/sentinelblue/sample-data")
        );
        assert_eq!(paths.required_paths().len(), 6);
    }
}
