//! MAEC 5.0 Open Vocabularies
//!
//! This module provides type-safe enumerations for all MAEC 5.0 open vocabularies,
//! ensuring 100% compliance with the MAEC specification.

use serde::{Deserialize, Serialize};

/// Analysis conclusion types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisConclusionType {
    /// The analyzed entity is benign
    Benign,
    /// The analyzed entity is malicious
    Malicious,
    /// The analyzed entity is suspicious
    Suspicious,
    /// The conclusion is indeterminate
    Indeterminate,
}

/// Analysis environment properties
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisEnvironment {
    /// Operating system property
    OperatingSystem,
    /// Host VM property
    HostVm,
    /// Installed software property
    InstalledSoftware,
}

/// Malware analysis types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisType {
    /// Static analysis
    Static,
    /// Dynamic analysis
    Dynamic,
    /// Combination of static and dynamic
    Combination,
}

/// Confidence measure levels (aligned with STIX HighMediumLow vocabulary)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfidenceMeasure {
    /// Low confidence
    Low,
    /// Medium confidence
    Medium,
    /// High confidence
    High,
    /// No confidence
    None,
    /// Unknown confidence
    Unknown,
}

/// Processor architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorArchitecture {
    /// x86 32-bit architecture
    X86,
    /// x86-64 (AMD64) architecture
    #[serde(rename = "x86-64")]
    X8664,
    /// Intel IA-64 architecture
    #[serde(rename = "ia-64")]
    Ia64,
    /// PowerPC architecture
    PowerPc,
    /// ARM architecture
    Arm,
    /// Alpha architecture
    Alpha,
    /// SPARC architecture
    Sparc,
    /// MIPS architecture
    Mips,
}

/// Binary obfuscation methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfuscationMethod {
    /// Packing/compression
    Packing,
    /// Code encryption
    CodeEncryption,
    /// Dead code insertion
    DeadCodeInsertion,
    /// Entry point obfuscation
    EntryPointObfuscation,
    /// Import address table obfuscation
    ImportAddressTableObfuscation,
    /// Interleaving code
    InterleavingCode,
    /// Symbolic obfuscation
    SymbolicObfuscation,
    /// String obfuscation
    StringObfuscation,
    /// Subroutine reordering
    SubroutineReordering,
    /// Code transposition
    CodeTransposition,
    /// Instruction substitution
    InstructionSubstitution,
    /// Register reassignment
    RegisterReassignment,
}

// Helper macro for creating large string-based enums
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $value:expr
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "kebab-case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                #[serde(rename = $value)]
                $variant,
            )*
        }
    };
}

string_enum! {
    /// Delivery/infection vectors
    pub enum DeliveryVector {
        ActiveAttacker => "active-attacker",
        AutoExecutingMedia => "auto-executing-media",
        Downloader => "downloader",
        Dropper => "dropper",
        EmailAttachment => "email-attachment",
        ExploitKitLandingPage => "exploit-kit-landing-page",
        FakeWebsite => "fake-website",
        JanitorAttack => "janitor-attack",
        MaliciousIframes => "malicious-iframes",
        Malvertising => "malvertising",
        MediaBaiting => "media-baiting",
        Pharming => "pharming",
        Phishing => "phishing",
        TrojanizedLink => "trojanized-link",
        TrojanizedSoftware => "trojanized-software",
        UsbCableSyncing => "usb-cable-syncing",
        WateringHole => "watering-hole",
    }
}

string_enum! {
    /// Common malware labels
    pub enum MalwareLabel {
        Adware => "adware",
        Appender => "appender",
        Backdoor => "backdoor",
        BootSectorVirus => "boot-sector-virus",
        Bot => "bot",
        CavityFiller => "cavity-filler",
        Clicker => "clicker",
        CompanionVirus => "companion-virus",
        DataDiddler => "data-diddler",
        Downloader => "downloader",
        DropperFile => "dropper-file",
        FileInfectorVirus => "file-infector-virus",
        ForkBomb => "fork-bomb",
        Greyware => "greyware",
        Implant => "implant",
        Infector => "infector",
        JokeProgram => "joke-program",
        Keylogger => "keylogger",
        KleptographicWorm => "kleptographic-worm",
        MacroVirus => "macro-virus",
        MassMailer => "mass-mailer",
        MetamorphicVirus => "metamorphic-virus",
        MidInfector => "mid-infector",
        MobileCode => "mobile-code",
        MultipartiteVirus => "multipartite-virus",
        ParentalControl => "parental-control",
        PasswordStealer => "password-stealer",
        PolymorphicVirus => "polymorphic-virus",
        PremiumDialerOrSmser => "premium-dialer-or-smser",
        Prepender => "prepender",
        Ransomware => "ransomware",
        RogueAntiMalware => "rogue-anti-malware",
        Rootkit => "rootkit",
        Scareware => "scareware",
        SecurityAssessmentTool => "security-assessment-tool",
        Shellcode => "shellcode",
        SpaghettiPacker => "spaghetti-packer",
        Spyware => "spyware",
        Trackware => "trackware",
        TrojanHorse => "trojan-horse",
        Virus => "virus",
        WebBug => "web-bug",
        Wiper => "wiper",
        Worm => "worm",
    }
}

string_enum! {
    /// MAEC entity association types
    pub enum EntityAssociation {
        FileSystemEntities => "file-system-entities",
        NetworkEntities => "network-entities",
        ProcessEntities => "process-entities",
        MemoryEntities => "memory-entities",
        IpcEntities => "ipc-entities",
        DeviceEntities => "device-entities",
        RegistryEntities => "registry-entities",
        ServiceEntities => "service-entities",
        PotentialIndicators => "potential-indicators",
        SameMalwareFamily => "same-malware-family",
        ClusteredTogether => "clustered-together",
        ObservedTogether => "observed-together",
        PartOfIntrusionSet => "part-of-intrusion-set",
        SameMalwareToolkit => "same-malware-toolkit",
    }
}

/// Allow using string slices directly for vocabularies
impl AsRef<str> for DeliveryVector {
    fn as_ref(&self) -> &str {
        match self {
            DeliveryVector::ActiveAttacker => "active-attacker",
            DeliveryVector::AutoExecutingMedia => "auto-executing-media",
            DeliveryVector::Downloader => "downloader",
            DeliveryVector::Dropper => "dropper",
            DeliveryVector::EmailAttachment => "email-attachment",
            DeliveryVector::ExploitKitLandingPage => "exploit-kit-landing-page",
            DeliveryVector::FakeWebsite => "fake-website",
            DeliveryVector::JanitorAttack => "janitor-attack",
            DeliveryVector::MaliciousIframes => "malicious-iframes",
            DeliveryVector::Malvertising => "malvertising",
            DeliveryVector::MediaBaiting => "media-baiting",
            DeliveryVector::Pharming => "pharming",
            DeliveryVector::Phishing => "phishing",
            DeliveryVector::TrojanizedLink => "trojanized-link",
            DeliveryVector::TrojanizedSoftware => "trojanized-software",
            DeliveryVector::UsbCableSyncing => "usb-cable-syncing",
            DeliveryVector::WateringHole => "watering-hole",
        }
    }
}

impl AsRef<str> for MalwareLabel {
    fn as_ref(&self) -> &str {
        match self {
            MalwareLabel::Adware => "adware",
            MalwareLabel::Appender => "appender",
            MalwareLabel::Backdoor => "backdoor",
            MalwareLabel::BootSectorVirus => "boot-sector-virus",
            MalwareLabel::Bot => "bot",
            MalwareLabel::CavityFiller => "cavity-filler",
            MalwareLabel::Clicker => "clicker",
            MalwareLabel::CompanionVirus => "companion-virus",
            MalwareLabel::DataDiddler => "data-diddler",
            MalwareLabel::Downloader => "downloader",
            MalwareLabel::DropperFile => "dropper-file",
            MalwareLabel::FileInfectorVirus => "file-infector-virus",
            MalwareLabel::ForkBomb => "fork-bomb",
            MalwareLabel::Greyware => "greyware",
            MalwareLabel::Implant => "implant",
            MalwareLabel::Infector => "infector",
            MalwareLabel::JokeProgram => "joke-program",
            MalwareLabel::Keylogger => "keylogger",
            MalwareLabel::KleptographicWorm => "kleptographic-worm",
            MalwareLabel::MacroVirus => "macro-virus",
            MalwareLabel::MassMailer => "mass-mailer",
            MalwareLabel::MetamorphicVirus => "metamorphic-virus",
            MalwareLabel::MidInfector => "mid-infector",
            MalwareLabel::MobileCode => "mobile-code",
            MalwareLabel::MultipartiteVirus => "multipartite-virus",
            MalwareLabel::ParentalControl => "parental-control",
            MalwareLabel::PasswordStealer => "password-stealer",
            MalwareLabel::PolymorphicVirus => "polymorphic-virus",
            MalwareLabel::PremiumDialerOrSmser => "premium-dialer-or-smser",
            MalwareLabel::Prepender => "prepender",
            MalwareLabel::Ransomware => "ransomware",
            MalwareLabel::RogueAntiMalware => "rogue-anti-malware",
            MalwareLabel::Rootkit => "rootkit",
            MalwareLabel::Scareware => "scareware",
            MalwareLabel::SecurityAssessmentTool => "security-assessment-tool",
            MalwareLabel::Shellcode => "shellcode",
            MalwareLabel::SpaghettiPacker => "spaghetti-packer",
            MalwareLabel::Spyware => "spyware",
            MalwareLabel::Trackware => "trackware",
            MalwareLabel::TrojanHorse => "trojan-horse",
            MalwareLabel::Virus => "virus",
            MalwareLabel::WebBug => "web-bug",
            MalwareLabel::Wiper => "wiper",
            MalwareLabel::Worm => "worm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_conclusion_serde() {
        let conclusion = AnalysisConclusionType::Malicious;
        let json = serde_json::to_string(&conclusion).unwrap();
        assert_eq!(json, "\"malicious\"");

        let deserialized: AnalysisConclusionType = serde_json::from_str(&json).unwrap();
        assert_eq!(conclusion, deserialized);
    }

    #[test]
    fn test_delivery_vector_serde() {
        let vector = DeliveryVector::EmailAttachment;
        let json = serde_json::to_string(&vector).unwrap();
        assert_eq!(json, "\"email-attachment\"");

        let deserialized: DeliveryVector = serde_json::from_str(&json).unwrap();
        assert_eq!(vector, deserialized);
    }

    #[test]
    fn test_malware_label_serde() {
        let label = MalwareLabel::Ransomware;
        let json = serde_json::to_string(&label).unwrap();
        assert_eq!(json, "\"ransomware\"");

        let deserialized: MalwareLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(label, deserialized);
    }

    #[test]
    fn test_processor_arch_serde() {
        let arch = ProcessorArchitecture::X8664;
        let json = serde_json::to_string(&arch).unwrap();
        assert_eq!(json, "\"x86-64\"");

        let deserialized: ProcessorArchitecture = serde_json::from_str(&json).unwrap();
        assert_eq!(arch, deserialized);
    }
}
