use habitat_authority::*;

#[test]
fn every_request_is_authenticated_and_mediated_against_all_grant_bounds() {
    let mut authority = Authority::new("policy:v2", "generation:01", "state:7");
    let grant = Grant::builder("grant:01", "service:issuer", "activation:01", "StoreCap")
        .caller("machine:01","service:runtime")
        .operations(["read"]).target_prefix("bucket/evidence/")
        .valid_between(100, 200).generation("generation:01").build().unwrap();
    authority.issue(grant, IndependentApproval::verified("operator:01")).unwrap();
    let request = Invocation::new("command:01", MachineId::new("machine:01").unwrap(),
        ServiceId::new("service:runtime").unwrap(), ActivationId::new("activation:01").unwrap(),
        "StoreCap", "read", "bucket/evidence/a", 150, "state:7", "objective:01");
    assert!(authority.evaluate(&request).allowed);
    assert_eq!(authority.evaluate(&Invocation {
        machine:MachineId::new("machine:other").unwrap(),..request.clone()
    }).denial_code.as_deref(),Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate(&Invocation {
        service:ServiceId::new("service:other").unwrap(),..request.clone()
    }).denial_code.as_deref(),Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate(&Invocation { operation: "write".into(), ..request.clone() })
        .denial_code.as_deref(), Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate(&Invocation { generation: "generation:02".into(), ..request.clone() })
        .denial_code.as_deref(), Some("STALE"));
    assert_eq!(authority.evaluate(&Invocation { state_version: "state:stale".into(), ..request })
        .denial_code.as_deref(), Some("STALE"));
}
