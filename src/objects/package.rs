//! MAEC Package object implementation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::{CommonProperties, MaecObject};
use crate::error::{MaecError, Result};
use chrono::{DateTime, Utc};

/// Top-level MAEC Package
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Package {
    /// Common MAEC properties
    #[serde(flatten)]
    pub common: CommonProperties,

    /// MAEC objects contained in this package
    #[serde(default)]
    pub maec_objects: Vec<MaecObjectType>,

    /// STIX Cyber Observable Objects relevant to the package
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observable_objects: Option<HashMap<String, serde_json::Value>>,

    /// Relationships between objects in the package
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<crate::Relationship>,
}

/// MAEC object types that can be contained in a Package
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MaecObjectType {
    /// Behavior object
    Behavior(crate::Behavior),
    /// Collection object
    Collection(crate::Collection),
    /// Malware Action object
    MalwareAction(crate::MalwareAction),
    /// Malware Family object
    MalwareFamily(crate::MalwareFamily),
    /// Malware Instance object
    MalwareInstance(crate::MalwareInstance),
}

impl Package {
    /// Creates a new Package builder
    pub fn builder() -> PackageBuilder {
        PackageBuilder::default()
    }

    /// Creates a new minimal Package with required fields
    pub fn new() -> Self {
        Self {
            common: CommonProperties::new("package", None),
            maec_objects: vec![],
            observable_objects: None,
            relationships: vec![],
        }
    }

    /// Validates the Package structure
    pub fn validate(&self) -> Result<()> {
        if self.common.r#type != "package" {
            return Err(MaecError::ValidationError(format!(
                "type must be 'package', got '{}'",
                self.common.r#type
            )));
        }

        if self.common.schema_version.as_deref() != Some("5.0") {
            return Err(MaecError::ValidationError(format!(
                "schema_version must be '5.0', got '{:?}'",
                self.common.schema_version
            )));
        }

        if !crate::common::is_valid_maec_id(&self.common.id) {
            return Err(MaecError::InvalidId(self.common.id.clone()));
        }

        Ok(())
    }

    pub fn malware_families(&self) -> Vec<&crate::MalwareFamily> {
        self.maec_objects
            .iter()
            .filter_map(|obj| match obj {
                MaecObjectType::MalwareFamily(family) => Some(family),
                _ => None,
            })
            .collect()
    }

    pub fn malware_instances(&self) -> Vec<&crate::MalwareInstance> {
        self.maec_objects
            .iter()
            .filter_map(|obj| match obj {
                MaecObjectType::MalwareInstance(instance) => Some(instance),
                _ => None,
            })
            .collect()
    }

    pub fn behaviors(&self) -> Vec<&crate::Behavior> {
        self.maec_objects
            .iter()
            .filter_map(|obj| match obj {
                MaecObjectType::Behavior(behavior) => Some(behavior),
                _ => None,
            })
            .collect()
    }

    pub fn malware_actions(&self) -> Vec<&crate::MalwareAction> {
        self.maec_objects
            .iter()
            .filter_map(|obj| match obj {
                MaecObjectType::MalwareAction(action) => Some(action),
                _ => None,
            })
            .collect()
    }
}

impl MaecObject for Package {
    fn id(&self) -> &str {
        &self.common.id
    }
    fn type_(&self) -> &str {
        &self.common.r#type
    }
    fn created(&self) -> DateTime<Utc> {
        self.common.created
    }
}

impl Default for Package {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for Package objects
#[derive(Debug, Default)]
pub struct PackageBuilder {
    id: Option<String>,
    schema_version: Option<String>,
    maec_objects: Vec<MaecObjectType>,
    observable_objects: Option<HashMap<String, serde_json::Value>>,
    relationships: Vec<crate::Relationship>,
}

impl PackageBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn schema_version(mut self, version: impl Into<String>) -> Self {
        self.schema_version = Some(version.into());
        self
    }

    pub fn add_object(mut self, object: MaecObjectType) -> Self {
        self.maec_objects.push(object);
        self
    }

    pub fn add_malware_family(mut self, family: crate::MalwareFamily) -> Self {
        self.maec_objects
            .push(MaecObjectType::MalwareFamily(family));
        self
    }

    pub fn add_malware_instance(mut self, instance: crate::MalwareInstance) -> Self {
        self.maec_objects
            .push(MaecObjectType::MalwareInstance(instance));
        self
    }

    pub fn add_behavior(mut self, behavior: crate::Behavior) -> Self {
        self.maec_objects.push(MaecObjectType::Behavior(behavior));
        self
    }

    pub fn add_malware_action(mut self, action: crate::MalwareAction) -> Self {
        self.maec_objects
            .push(MaecObjectType::MalwareAction(action));
        self
    }

    pub fn build(self) -> Result<Package> {
        let mut common = CommonProperties::new("package", None);
        if let Some(id) = self.id {
            common.id = id;
        }
        if let Some(version) = self.schema_version {
            common.schema_version = Some(version);
        }

        let package = Package {
            common,
            maec_objects: self.maec_objects,
            observable_objects: self.observable_objects,
            relationships: self.relationships,
        };

        package.validate()?;
        Ok(package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_new() {
        let package = Package::new();
        assert_eq!(package.common.r#type, "package");
        assert_eq!(package.common.schema_version, Some("5.0".to_string()));
        assert!(package.common.id.starts_with("package--"));
    }

    #[test]
    fn test_package_builder() {
        let package = Package::builder().schema_version("5.0").build().unwrap();
        assert_eq!(package.common.r#type, "package");
        assert_eq!(package.common.schema_version, Some("5.0".to_string()));
    }
}
