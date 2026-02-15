//! MAEC Collection object

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::{CommonProperties, MaecObject};
use crate::error::{MaecError, Result};

/// MAEC Collection
///
/// Represents a grouping of related MAEC objects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Collection {
    /// Common MAEC properties
    #[serde(flatten)]
    pub common: CommonProperties,

    /// Name of the collection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Textual description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Collection {
    /// Creates a new Collection builder
    pub fn builder() -> CollectionBuilder {
        CollectionBuilder::default()
    }

    /// Creates a minimal Collection
    pub fn new() -> Self {
        Self {
            common: CommonProperties::new("collection", None),
            name: None,
            description: None,
        }
    }

    /// Validates the Collection structure
    pub fn validate(&self) -> Result<()> {
        if self.common.r#type != "collection" {
            return Err(MaecError::ValidationError(format!(
                "type must be 'collection', got '{}'",
                self.common.r#type
            )));
        }

        if !crate::common::is_valid_maec_id(&self.common.id) {
            return Err(MaecError::InvalidId(self.common.id.clone()));
        }

        Ok(())
    }
}

impl Default for Collection {
    fn default() -> Self {
        Self::new()
    }
}

impl MaecObject for Collection {
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

/// Builder for Collection objects
#[derive(Debug, Default)]
pub struct CollectionBuilder {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
}

impl CollectionBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn build(self) -> Result<Collection> {
        let mut common = CommonProperties::new("collection", None);
        if let Some(id) = self.id {
            common.id = id;
        }

        let collection = Collection {
            common,
            name: self.name,
            description: self.description,
        };

        collection.validate()?;
        Ok(collection)
    }
}
