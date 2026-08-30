use habitat_authority::*;

#[test]
fn every_request_is_authenticated_and_mediated_against_all_grant_bounds() {
    let mut authority = Authority::new("policy:v2", "generation:01", "state:7",150);
    let grant = Grant::builder("grant:01", "service:issuer", "activation:01", "StoreCap")
        .caller("machine:01","service:runtime")
        .operations(["read"]).target_prefix("bucket/evidence/")
        .valid_between(100, 200).generation("generation:01").build().unwrap();
    let request = Invocation::new("command:01", MachineId::new("machine:01").unwrap(),
        ServiceId::new("service:runtime").unwrap(), ActivationId::new("activation:01").unwrap(),
        "StoreCap", "read", "bucket/evidence/a", 150, "state:7", "objective:01");
    authority.bind_local_peer(&request.machine,&request.service,&request.activation).unwrap();
    authority.issue(grant, IndependentApproval::verified("operator:01")).unwrap();
    assert_eq!(authority.bind_local_peer(&MachineId::new("machine:other").unwrap(),
        &ServiceId::new("service:other").unwrap(),&ActivationId::new("activation:other").unwrap()),
        Err(AuthorityError::BindingLocked));
    assert!(authority.evaluate_local(&request).unwrap().allowed);
    assert_eq!(authority.evaluate_local(&Invocation {
        machine:MachineId::new("machine:other").unwrap(),..request.clone()
    }).unwrap().denial_code.as_deref(),Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate_local(&Invocation {
        service:ServiceId::new("service:other").unwrap(),..request.clone()
    }).unwrap().denial_code.as_deref(),Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate_local(&Invocation { operation: "write".into(), ..request.clone() }).unwrap()
        .denial_code.as_deref(), Some("UNAUTHORIZED"));
    assert_eq!(authority.evaluate_local(&Invocation { generation: "generation:02".into(), ..request.clone() }).unwrap()
        .denial_code.as_deref(), Some("STALE"));
    assert_eq!(authority.evaluate_local(&Invocation { state_version: "state:stale".into(), ..request }).unwrap()
        .denial_code.as_deref(), Some("STALE"));
}

#[test]
fn caller_timestamp_cannot_replay_an_expired_grant(){
    let mut authority=Authority::new("policy:v2","generation:01","state:1",250);
    let grant=Grant::builder("grant:expired","service:issuer","activation:1","ReadCap")
        .caller("machine:1","service:runtime").operations(["read"]).target_prefix("resource/")
        .valid_between(100,200).generation("generation:01").build().unwrap();
    let request=Invocation::new("command:1",MachineId::new("machine:1").unwrap(),
        ServiceId::new("service:runtime").unwrap(),ActivationId::new("activation:1").unwrap(),
        "ReadCap","read","resource/1",150,"state:1","objective:1");
    authority.bind_local_peer(&request.machine,&request.service,&request.activation).unwrap();
    authority.issue(grant,IndependentApproval::verified("operator:1")).unwrap();
    assert_eq!(authority.evaluate_local(&request).unwrap().denial_code.as_deref(),Some("STALE"));
}
