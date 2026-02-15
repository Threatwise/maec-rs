//! MAEC Behavior object implementation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::{ExternalReference, MaecObject};
use crate::error::{MaecError, Result};

/// MAEC Behavior
///
/// A Behavior corresponds to the specific purpose behind a particular snippet of code,
/// as executed by a malware instance. Examples include keylogging, detecting a virtual
/// machine, and installing a backdoor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct Behavior {
    /// Common MAEC properties
    #[serde(flatten)]
    pub common: crate::common::CommonProperties,

    /// Name of the behavior
    pub name: crate::vocab_large::Behavior,

    /// Textual description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Timestamp when the behavior occurred/was observed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,

    /// Behavior attributes as key/value pairs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, serde_json::Value>>,

    /// References to actions implementing this behavior
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_refs: Vec<String>,

    /// References to techniques used (ATT&CK, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub technique_refs: Vec<ExternalReference>,
}

impl Behavior {
    /// Creates a new Behavior builder
    pub fn builder() -> BehaviorBuilder {
        BehaviorBuilder::default()
    }

    /// Creates a minimal Behavior with just a name
    pub fn new(name: crate::vocab_large::Behavior) -> Self {
        Self {
            common: crate::common::CommonProperties::new("behavior", None),
            name,
            description: None,
            timestamp: None,
            attributes: None,
            action_refs: vec![],
            technique_refs: vec![],
        }
    }

    /// Validates the Behavior structure
    pub fn validate(&self) -> Result<()> {
        if self.common.r#type != "behavior" {
            return Err(MaecError::ValidationError(format!(
                "type must be 'behavior', got '{}'",
                self.common.r#type
            )));
        }

        if !crate::common::is_valid_maec_id(&self.common.id) {
            return Err(MaecError::InvalidId(self.common.id.clone()));
        }

        Ok(())
    }
}

impl MaecObject for Behavior {
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

/// Builder for Behavior objects
#[derive(Debug, Default)]
pub struct BehaviorBuilder {
    id: Option<String>,
    name: Option<crate::vocab_large::Behavior>,
    description: Option<String>,
    timestamp: Option<DateTime<Utc>>,
    attributes: Option<HashMap<String, serde_json::Value>>,
    action_refs: Vec<String>,
    technique_refs: Vec<ExternalReference>,
}

impl BehaviorBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn name(mut self, name: crate::vocab_large::Behavior) -> Self {
        self.name = Some(name);
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn add_action_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.action_refs.push(ref_id.into());
        self
    }

    pub fn add_technique_ref(mut self, reference: ExternalReference) -> Self {
        self.technique_refs.push(reference);
        self
    }

    pub fn build(self) -> Result<Behavior> {
        let name = self.name.ok_or(MaecError::MissingField("name"))?;

        let mut common = crate::common::CommonProperties::new("behavior", None);
        if let Some(id) = self.id {
            common.id = id;
        }

        let behavior = Behavior {
            common,
            name,
            description: self.description,
            timestamp: self.timestamp,
            attributes: self.attributes,
            action_refs: self.action_refs,
            technique_refs: self.technique_refs,
        };

        behavior.validate()?;
        Ok(behavior)
    }
}
