//! MAEC Capability type implementation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::common::ExternalReference;
use crate::error::Result;

/// MAEC Capability
///
/// Captures details of a Capability that may be implemented in the malware instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Capability {
    /// Name of the capability
    pub name: String,

    /// Refined sub-capabilities
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refined_capabilities: Vec<Capability>,

    /// Textual description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Capability attributes as key/value pairs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, serde_json::Value>>,

    /// References to behaviors implementing this capability
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub behavior_refs: Vec<String>,

    /// External references (ATT&CK tactics, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<ExternalReference>,
}

impl Capability {
    /// Creates a new Capability with just a name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            refined_capabilities: vec![],
            description: None,
            attributes: None,
            behavior_refs: vec![],
            references: vec![],
        }
    }

    /// Creates a new Capability builder
    pub fn builder() -> CapabilityBuilder {
        CapabilityBuilder::default()
    }
}

/// Builder for Capability objects
#[derive(Debug, Default)]
pub struct CapabilityBuilder {
    name: Option<String>,
    refined_capabilities: Vec<Capability>,
    description: Option<String>,
    attributes: Option<HashMap<String, serde_json::Value>>,
    behavior_refs: Vec<String>,
    references: Vec<ExternalReference>,
}

impl CapabilityBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn add_refined_capability(mut self, capability: Capability) -> Self {
        self.refined_capabilities.push(capability);
        self
    }

    pub fn add_behavior_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.behavior_refs.push(ref_id.into());
        self
    }

    pub fn add_reference(mut self, reference: ExternalReference) -> Self {
        self.references.push(reference);
        self
    }

    pub fn build(self) -> Result<Capability> {
        let name = self
            .name
            .ok_or(crate::error::MaecError::MissingField("name"))?;

        Ok(Capability {
            name,
            refined_capabilities: self.refined_capabilities,
            description: self.description,
            attributes: self.attributes,
            behavior_refs: self.behavior_refs,
            references: self.references,
        })
    }
}
