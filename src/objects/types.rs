//! Supporting types for MAEC objects
//!
//! This module contains common supporting types used across multiple MAEC objects,
//! such as Name and FieldData.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::ExternalReference;

/// Captures the name of a malware instance, family, or alias
///
/// Includes the actual name value along with optional source and confidence information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Name {
    /// The actual name value
    pub value: String,

    /// Source of the name (e.g., AV vendor, researcher)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ExternalReference>,

    /// Confidence in the accuracy of the assigned name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

impl Name {
    /// Creates a new Name with just a value
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: None,
            confidence: None,
        }
    }

    /// Creates a Name with a source
    pub fn with_source(value: impl Into<String>, source: ExternalReference) -> Self {
        Self {
            value: value.into(),
            source: Some(source),
            confidence: None,
        }
    }

    /// Creates a Name with source and confidence
    pub fn with_confidence(
        value: impl Into<String>,
        source: ExternalReference,
        confidence: impl Into<String>,
    ) -> Self {
        Self {
            value: value.into(),
            source: Some(source),
            confidence: Some(confidence.into()),
        }
    }
}

impl From<String> for Name {
    fn from(value: String) -> Self {
        Name::new(value)
    }
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        Name::new(value)
    }
}

/// Field data associated with a malware instance or family
///
/// Captures temporal information and delivery vectors.
/// At least one field must be present.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct FieldData {
    /// Vectors used to distribute/deploy the malware
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_vectors: Option<Vec<String>>,

    /// When the malware was first observed (ISO 8601 format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,

    /// When the malware was last observed (ISO 8601 format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

impl FieldData {
    /// Creates a new FieldData builder
    pub fn builder() -> FieldDataBuilder {
        FieldDataBuilder::default()
    }

    /// Creates FieldData with just delivery vectors
    pub fn with_delivery_vectors(vectors: Vec<String>) -> Self {
        Self {
            delivery_vectors: Some(vectors),
            first_seen: None,
            last_seen: None,
        }
    }

    /// Creates FieldData with first/last seen dates
    pub fn with_timestamps(first_seen: DateTime<Utc>, last_seen: Option<DateTime<Utc>>) -> Self {
        Self {
            delivery_vectors: None,
            first_seen: Some(first_seen),
            last_seen,
        }
    }
}

/// Builder for FieldData
#[derive(Debug, Default)]
pub struct FieldDataBuilder {
    delivery_vectors: Option<Vec<String>>,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
}

impl FieldDataBuilder {
    pub fn delivery_vectors(mut self, vectors: Vec<String>) -> Self {
        self.delivery_vectors = Some(vectors);
        self
    }

    pub fn add_delivery_vector(mut self, vector: impl Into<String>) -> Self {
        self.delivery_vectors
            .get_or_insert_with(Vec::new)
            .push(vector.into());
        self
    }

    pub fn first_seen(mut self, timestamp: DateTime<Utc>) -> Self {
        self.first_seen = Some(timestamp);
        self
    }

    pub fn last_seen(mut self, timestamp: DateTime<Utc>) -> Self {
        self.last_seen = Some(timestamp);
        self
    }

    pub fn build(self) -> crate::error::Result<FieldData> {
        // Validate that at least one field is present
        if self.delivery_vectors.is_none() && self.first_seen.is_none() && self.last_seen.is_none()
        {
            return Err(crate::error::MaecError::ValidationError(
                "FieldData must have at least one of: delivery_vectors, first_seen, or last_seen"
                    .to_string(),
            ));
        }

        Ok(FieldData {
            delivery_vectors: self.delivery_vectors,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_new() {
        let name = Name::new("WannaCry");
        assert_eq!(name.value, "WannaCry");
        assert!(name.source.is_none());
        assert!(name.confidence.is_none());
    }

    #[test]
    fn test_name_from_string() {
        let name: Name = "Emotet".into();
        assert_eq!(name.value, "Emotet");
    }

    #[test]
    fn test_field_data_builder() {
        let field_data = FieldData::builder()
            .add_delivery_vector("email")
            .first_seen(Utc::now())
            .build()
            .unwrap();

        assert!(field_data.delivery_vectors.is_some());
        assert!(field_data.first_seen.is_some());
    }

    #[test]
    fn test_field_data_validation() {
        let result = FieldData::builder().build();
        assert!(result.is_err());

        let valid = FieldData::builder().add_delivery_vector("email").build();
        assert!(valid.is_ok());
    }
}
