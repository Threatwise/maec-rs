//! Error types for MAEC operations
//!
//! This module provides comprehensive error handling for MAEC operations
//! including validation, serialization, and builder pattern errors.

use thiserror::Error;

/// Main error type for MAEC operations
#[derive(Debug, Error)]
pub enum MaecError {
    /// Missing required field in builder
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Invalid MAEC ID format
    #[error("invalid MAEC ID: {0}")]
    InvalidId(String),

    /// Invalid reference to another object
    #[error("invalid reference: {0}")]
    InvalidReference(String),

    /// JSON serialization/deserialization error
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// XML serialization/deserialization error
    #[error("XML error: {0}")]
    XmlError(String),

    /// Quick-XML deserialization error
    #[error("XML deserialization error: {0}")]
    QuickXmlDeError(#[from] quick_xml::DeError),

    /// Quick-XML serialization error
    #[error("XML serialization error: {0}")]
    XmlSerializationError(String),

    /// Validation error
    #[error("validation error: {0}")]
    ValidationError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Specialized Result type for MAEC operations
pub type Result<T> = std::result::Result<T, MaecError>;

/// Builder error type (alias for MaecError for compatibility)
pub type BuilderError = MaecError;
