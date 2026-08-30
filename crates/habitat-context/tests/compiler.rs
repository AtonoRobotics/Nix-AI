use habitat_context::*;

#[test]
fn bundle_is_immutable_provenance_bearing_and_separates_truth_classes() {
    let compiler = Compiler::new(4096, 1_000);
    let items = vec![
        ContextItem::new("state:7", TruthClass::AuthoritativeState, "agent available",
            Provenance::new("postgres:agents", "7", 990, 1_100), true),
        ContextItem::new("obs:2", TruthClass::RawObservation, "temperature 42",
            Provenance::new("sensor:thermal", "2", 995, 1_010), true),
        ContextItem::new("claim:3", TruthClass::InterpretedClaim, "likely nominal",
            Provenance::new("model:summary", "3", 996, 1_005), false),
    ];
    let bundle = compiler.compile("activation:01", "objective:01", None, items).unwrap();
    assert!(bundle.id.starts_with("context:sha256:"));
    assert_eq!(bundle.items[0].provenance.compiled_at, 1_000);
    assert_ne!(bundle.items[0].truth_class, bundle.items[1].truth_class);
    assert!(bundle.omissions.is_empty());
    assert_eq!(bundle, compiler.compile("activation:01", "objective:01", None,
                                        bundle.items.clone()).unwrap());
}
