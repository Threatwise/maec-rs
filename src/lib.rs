//! maec-rs — MAEC 5.0 implementation in Rust
//!
//! This crate provides a complete implementation of MAEC (Malware Attribute Enumeration
//! and Characterization) 5.0 with:
//! - All MAEC objects (Package, MalwareFamily, MalwareInstance, Behavior, etc.)
//! - JSON and XML serialization via serde
//! - Builder pattern for ergonomic object construction
//! - Comprehensive error handling
//! - Type-safe IDs and references
//!
//! # Examples
//!
//! ```
//! use maec::{Package, MalwareFamily, Name};
//!
//! // Create a malware family
//! let family = MalwareFamily::builder()
//!     .name(Name::new("WannaCry"))
//!     .description("Ransomware family first seen in May 2017")
//!     .add_label("ransomware")
//!     .build()
//!     .unwrap();
//!
//! // Create a package containing the family
//! let package = Package::builder()
//!     .add_malware_family(family)
//!     .build()
//!     .unwrap();
//!
//! // Serialize to JSON
//! let json = serde_json::to_string_pretty(&package).unwrap();
//! println!("{}", json);
//! ```
//!
//! # STIX Integration
//!
//! MAEC complements STIX (Structured Threat Information Expression) by providing
//! detailed malware analysis data. MAEC objects can reference STIX Cyber Observable
//! Objects (files, network traffic, etc.) via the `observable_objects` field in Package.

// MIME Type Constants for MAEC and HTTP integration
/// MAEC 5.0 JSON media type for HTTP Content-Type headers
pub const MEDIA_TYPE_MAEC: &str = "application/maec+json;version=5.0";

/// Generic MAEC JSON media type (without version)
pub const MEDIA_TYPE_MAEC_GENERIC: &str = "application/maec+json";

// Module declarations
pub mod common;
pub mod error;
pub mod objects;
pub mod vocab;
pub mod vocab_large;

// Re-exports for convenient access
pub use common::{
    extract_type_from_id, generate_maec_id, is_valid_maec_id, is_valid_ref_for_type,
    CommonProperties, ExternalReference, MaecObject,
};

pub use error::{BuilderError, MaecError, Result};

pub use objects::{
    Behavior, BehaviorBuilder, Capability, CapabilityBuilder, Collection, FieldData,
    FieldDataBuilder, MaecObjectType, MalwareAction, MalwareFamily, MalwareFamilyBuilder,
    MalwareInstance, MalwareInstanceBuilder, Name, Package, PackageBuilder, Relationship,
    RelationshipBuilder,
};

pub use vocab::{
    AnalysisConclusionType, AnalysisEnvironment, AnalysisType, ConfidenceMeasure, DeliveryVector,
    EntityAssociation, MalwareLabel, ObfuscationMethod, ProcessorArchitecture,
};

pub use vocab_large::{
    Behavior as BehaviorVocab, Capability as CapabilityVocab, CommonAttribute,
    MalwareAction as MalwareActionVocab, MalwareConfigurationParameter, OsFeature,
};
