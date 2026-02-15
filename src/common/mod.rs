//! Common MAEC types and utilities
//!
//! This module provides core types shared across all MAEC objects, including
//! common properties, traits, and ID generation/validation helpers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

fn default_now() -> DateTime<Utc> {
    Utc::now()
}

fn default_version() -> Option<String> {
    Some("5.0".to_string())
}

/// Trait implemented by all MAEC objects for basic accessors
pub trait MaecObject {
    /// Returns the unique identifier of the object
    fn id(&self) -> &str;

    /// Returns the type of the MAEC object (e.g., "package", "malware-family")
    fn type_(&self) -> &str;

    /// Returns when the object was created
    fn created(&self) -> DateTime<Utc>;
}

/// Common properties shared by MAEC top-level objects
///
/// These properties are flattened into each MAEC object type via serde,
/// providing consistent ID generation, timestamping, and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CommonProperties {
    /// The type of MAEC object (e.g., "package", "malware-family")
    #[serde(rename = "type")]
    pub r#type: String,

    /// Unique identifier for this object (format: "type--uuid")
    pub id: String,

    /// MAEC specification version (should be "5.0")
    #[serde(default = "default_version", skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,

    /// Timestamp when the object was created
    #[serde(default = "default_now")]
    pub created: DateTime<Utc>,

    /// Timestamp when the object was last modified
    #[serde(default = "default_now")]
    pub modified: DateTime<Utc>,

    /// Reference to the identity that created this object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_ref: Option<String>,

    /// Custom properties for extensions
    #[serde(flatten)]
    pub custom_properties: HashMap<String, serde_json::Value>,
}

impl Default for CommonProperties {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            r#type: String::new(),
            id: generate_maec_id("object"),
            schema_version: Some("5.0".to_string()),
            created: now,
            modified: now,
            created_by_ref: None,
            custom_properties: HashMap::new(),
        }
    }
}

impl CommonProperties {
    /// Creates a new CommonProperties instance
    ///
    /// # Arguments
    ///
    /// * `object_type` - The MAEC object type (e.g., "package", "malware-family")
    /// * `created_by_ref` - Optional reference to the creating identity
    ///
    /// # Examples
    ///
    /// ```
    /// use maec::common::CommonProperties;
    ///
    /// let common = CommonProperties::new("malware-family", None);
    /// assert_eq!(common.r#type, "malware-family");
    /// assert_eq!(common.schema_version, Some("5.0".to_string()));
    /// ```
    pub fn new(object_type: impl Into<String>, created_by_ref: Option<String>) -> Self {
        let object_type = object_type.into();
        let now = Utc::now();
        Self {
            r#type: object_type.clone(),
            id: generate_maec_id(&object_type),
            schema_version: Some("5.0".to_string()),
            created: now,
            modified: now,
            created_by_ref,
            custom_properties: HashMap::new(),
        }
    }

    /// Creates a new version of this object by updating the modified timestamp
    ///
    /// In MAEC (like STIX), when you update an object, you keep the same ID
    /// and created timestamp but update the modified timestamp to indicate
    /// a new version.
    ///
    /// # Examples
    ///
    /// ```
    /// use maec::common::CommonProperties;
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// let mut common = CommonProperties::new("malware-family", None);
    /// let original_modified = common.modified;
    ///
    /// thread::sleep(Duration::from_millis(10));
    /// common.new_version();
    ///
    /// assert!(common.modified > original_modified);
    /// assert_eq!(common.created, original_modified); // created unchanged
    /// ```
    pub fn new_version(&mut self) {
        self.modified = Utc::now();
    }
}

impl MaecObject for CommonProperties {
    fn id(&self) -> &str {
        &self.id
    }

    fn type_(&self) -> &str {
        &self.r#type
    }

    fn created(&self) -> DateTime<Utc> {
        self.created
    }
}

/// Generates a unique MAEC identifier
///
/// MAEC IDs follow the format: `{object-type}--{uuid}`
///
/// # Examples
///
/// ```
/// use maec::common::generate_maec_id;
///
/// let id = generate_maec_id("malware-family");
/// assert!(id.starts_with("malware-family--"));
/// ```
pub fn generate_maec_id(object_type: &str) -> String {
    format!("{}--{}", object_type, Uuid::new_v4())
}

/// Validates that a string is a valid MAEC identifier
///
/// MAEC IDs must follow the format: `{object-type}--{uuid}`
///
/// # Examples
///
/// ```
/// use maec::common::is_valid_maec_id;
///
/// assert!(is_valid_maec_id("malware-family--12345678-1234-1234-1234-123456789abc"));
/// assert!(is_valid_maec_id("package--550e8400-e29b-41d4-a716-446655440000"));
/// assert!(!is_valid_maec_id("invalid"));
/// assert!(!is_valid_maec_id("malware-family-bad-uuid"));
/// ```
pub fn is_valid_maec_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split("--").collect();
    if parts.len() != 2 {
        return false;
    }

    // Validate the UUID part
    Uuid::parse_str(parts[1]).is_ok()
}

/// Extracts the object type from a MAEC ID
///
/// # Examples
///
/// ```
/// use maec::common::extract_type_from_id;
///
/// assert_eq!(
///     extract_type_from_id("malware-family--12345678-1234-1234-1234-123456789abc"),
///     Some("malware-family")
/// );
/// assert_eq!(extract_type_from_id("invalid"), None);
/// ```
pub fn extract_type_from_id(id: &str) -> Option<&str> {
    let parts: Vec<&str> = id.split("--").collect();
    if parts.len() == 2 && Uuid::parse_str(parts[1]).is_ok() {
        Some(parts[0])
    } else {
        None
    }
}

/// Validates that a reference ID matches the expected object type
///
/// # Examples
///
/// ```
/// use maec::common::is_valid_ref_for_type;
///
/// assert!(is_valid_ref_for_type(
///     "malware-family--12345678-1234-1234-1234-123456789abc",
///     "malware-family"
/// ));
/// assert!(!is_valid_ref_for_type(
///     "package--12345678-1234-1234-1234-123456789abc",
///     "malware-family"
/// ));
/// ```
pub fn is_valid_ref_for_type(id: &str, expected_type: &str) -> bool {
    extract_type_from_id(id)
        .map(|t| t == expected_type)
        .unwrap_or(false)
}

/// External Reference - Links to external resources
///
/// Used to reference external sources like ATT&CK techniques, CVEs,
/// or research papers related to MAEC objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExternalReference {
    /// Name of the source (e.g., "mitre-attack", "cve")
    pub source_name: String,

    /// Description of the reference
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL to the external resource
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// External identifier (e.g., "T1055" for ATT&CK)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl ExternalReference {
    /// Creates a new external reference with just a source name
    pub fn new(source_name: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            description: None,
            url: None,
            external_id: None,
        }
    }

    /// Creates an ATT&CK technique reference
    ///
    /// # Examples
    ///
    /// ```
    /// use maec::common::ExternalReference;
    ///
    /// let technique = ExternalReference::attack_technique("T1055", "Process Injection");
    /// assert_eq!(technique.source_name, "mitre-attack");
    /// assert_eq!(technique.external_id, Some("T1055".to_string()));
    /// ```
    pub fn attack_technique(technique_id: impl Into<String>, name: impl Into<String>) -> Self {
        let technique_id = technique_id.into();
        Self {
            source_name: "mitre-attack".to_string(),
            description: Some(name.into()),
            url: Some(format!(
                "https://attack.mitre.org/techniques/{}",
                technique_id
            )),
            external_id: Some(technique_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_maec_id() {
        let id = generate_maec_id("malware-family");
        assert!(id.starts_with("malware-family--"));
        assert!(is_valid_maec_id(&id));
    }

    #[test]
    fn test_is_valid_maec_id() {
        assert!(is_valid_maec_id(
            "malware-family--550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(is_valid_maec_id(
            "package--12345678-1234-1234-1234-123456789abc"
        ));
        assert!(!is_valid_maec_id("invalid"));
        assert!(!is_valid_maec_id("malware-family"));
        assert!(!is_valid_maec_id("malware-family-no-uuid"));
    }

    #[test]
    fn test_extract_type_from_id() {
        assert_eq!(
            extract_type_from_id("malware-family--550e8400-e29b-41d4-a716-446655440000"),
            Some("malware-family")
        );
        assert_eq!(
            extract_type_from_id("package--12345678-1234-1234-1234-123456789abc"),
            Some("package")
        );
        assert_eq!(extract_type_from_id("invalid"), None);
    }

    #[test]
    fn test_is_valid_ref_for_type() {
        assert!(is_valid_ref_for_type(
            "malware-family--550e8400-e29b-41d4-a716-446655440000",
            "malware-family"
        ));
        assert!(!is_valid_ref_for_type(
            "package--550e8400-e29b-41d4-a716-446655440000",
            "malware-family"
        ));
    }

    #[test]
    fn test_common_properties_new() {
        let common = CommonProperties::new("malware-family", None);
        assert_eq!(common.r#type, "malware-family");
        assert_eq!(common.schema_version, Some("5.0".to_string()));
        assert!(common.id.starts_with("malware-family--"));
    }

    #[test]
    fn test_new_version() {
        let mut common = CommonProperties::new("malware-family", None);
        let original_created = common.created;
        let original_modified = common.modified;

        std::thread::sleep(std::time::Duration::from_millis(10));
        common.new_version();

        assert_eq!(common.created, original_created);
        assert!(common.modified > original_modified);
    }

    #[test]
    fn test_external_reference_attack() {
        let ref_obj = ExternalReference::attack_technique("T1055", "Process Injection");
        assert_eq!(ref_obj.source_name, "mitre-attack");
        assert_eq!(ref_obj.external_id, Some("T1055".to_string()));
        assert!(ref_obj.url.unwrap().contains("T1055"));
    }
}
