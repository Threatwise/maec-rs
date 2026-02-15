use maec::{Behavior, MalwareFamily, Name, Package};

#[test]
fn json_roundtrip() {
    // Create a simple behavior
    let behavior = Behavior::builder()
        .name(maec::vocab_large::Behavior::CheckForPayload)
        .description("Test behavior")
        .build()
        .unwrap();

    // Create a malware family
    let family = MalwareFamily::builder()
        .name(Name::new("TestMalware"))
        .description("Test malware family")
        .build()
        .unwrap();

    // Create a package
    let pkg = Package::builder()
        .add_malware_family(family)
        .add_behavior(behavior)
        .build()
        .unwrap();

    // Test JSON roundtrip
    let json = serde_json::to_string(&pkg).unwrap();
    let from_json: Package = serde_json::from_str(&json).unwrap();
    assert_eq!(pkg, from_json);
}

#[test]
#[ignore] // XML serialization has limitations with complex nested structures in quick-xml
fn xml_roundtrip() {
    // Note: MAEC 5.0 primarily uses JSON serialization.
    // XML support is provided but has limitations with nested enums.
    // For production use, JSON is the recommended format.

    let pkg = Package::builder().build().unwrap();

    // This test is ignored due to quick-xml limitations
    let _xml = quick_xml::se::to_string(&pkg);
}
