//! MAEC Relationship object

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::MaecObject;
use crate::error::{MaecError, Result};

/// MAEC Relationship
///
/// Connects two MAEC objects, expressing how they are related.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Relationship {
    /// Common MAEC properties
    #[serde(flatten)]
    pub common: crate::common::CommonProperties,

    /// ID of the source object
    pub source_ref: String,

    /// ID of the target object
    pub target_ref: String,

    /// Type of relationship (e.g., "derived-from", "variant-of")
    pub relationship_type: String,

    /// Textual description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Relationship {
    pub fn builder() -> RelationshipBuilder {
        RelationshipBuilder::default()
    }

    pub fn new(
        source_ref: impl Into<String>,
        relationship_type: impl Into<String>,
        target_ref: impl Into<String>,
    ) -> Self {
        Self {
            common: crate::common::CommonProperties::new("relationship", None),
            source_ref: source_ref.into(),
            target_ref: target_ref.into(),
            relationship_type: relationship_type.into(),
            description: None,
        }
    }
}

impl MaecObject for Relationship {
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

#[derive(Debug, Default)]
pub struct RelationshipBuilder {
    id: Option<String>,
    source_ref: Option<String>,
    target_ref: Option<String>,
    relationship_type: Option<String>,
    description: Option<String>,
}

impl RelationshipBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn source_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.source_ref = Some(ref_id.into());
        self
    }

    pub fn target_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.target_ref = Some(ref_id.into());
        self
    }

    pub fn relationship_type(mut self, rel_type: impl Into<String>) -> Self {
        self.relationship_type = Some(rel_type.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn build(self) -> Result<Relationship> {
        let source_ref = self
            .source_ref
            .ok_or(MaecError::MissingField("source_ref"))?;
        let target_ref = self
            .target_ref
            .ok_or(MaecError::MissingField("target_ref"))?;
        let relationship_type = self
            .relationship_type
            .ok_or(MaecError::MissingField("relationship_type"))?;

        let mut common = crate::common::CommonProperties::new("relationship", None);
        if let Some(id) = self.id {
            common.id = id;
        }

        Ok(Relationship {
            common,
            source_ref,
            target_ref,
            relationship_type,
            description: self.description,
        })
    }
}
