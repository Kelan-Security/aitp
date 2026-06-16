use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    AIModel,
    Human,
    #[default]
    Service,
    Device,
}

/// Loaded from a TOML file. All fields have sensible defaults.
#[derive(Debug, Deserialize)]
pub struct KelanConfig {
    #[serde(default = "default_intelligence_core_url")]
    pub intelligence_core_url: String, // e.g. "http://localhost:3000"

    #[serde(default = "default_entity_name")]
    pub entity_name: String,

    #[serde(default)]
    pub entity_type: EntityType,

    #[serde(default)]
    pub department: Option<String>,

    #[serde(default)]
    pub clearance_level: u8,
}

fn default_intelligence_core_url() -> String {
    "http://localhost:3000".to_string()
}

fn default_entity_name() -> String {
    "kelan-entity".to_string()
}

impl Default for KelanConfig {
    fn default() -> Self {
        Self {
            intelligence_core_url: default_intelligence_core_url(),
            entity_name: default_entity_name(),
            entity_type: EntityType::default(),
            department: None,
            clearance_level: 0,
        }
    }
}
