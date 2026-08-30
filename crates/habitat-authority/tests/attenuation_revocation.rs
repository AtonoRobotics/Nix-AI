use habitat_authority::*;

fn parent() -> Grant {
    Grant::builder("grant:parent", "service:issuer", "activation:parent", "ToolCap")
        .operations(["read", "write"]).target_prefix("resource/group/")
        .valid_between(100, 1000).generation("generation:01")
        .delegation_depth(3).quota(100).build().unwrap()
}

#[test]
fn delegation_can_only_reduce_every_parent_bound() {
    for operations in [["read"], ["write"]] {
        for expiry in [500, 999] {
            for quota in [1, 100] {
                let mut authority = Authority::new("policy:v2", "generation:01", "state:9");
                authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
                let child = Grant::builder("grant:child", "activation:parent",
                    "activation:child", "ToolCap").operations(operations)
                    .target_prefix("resource/group/item/").valid_between(100, expiry)
                    .generation("generation:01").delegation_depth(2).quota(quota).build().unwrap();
                assert!(authority.delegate("grant:parent", child).is_ok());
            }
        }
    }
    let mut authority = Authority::new("policy:v2", "generation:01", "state:9");
    authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
    let widened = Grant::builder("grant:widened", "activation:parent", "activation:child",
        "ToolCap").operations(["delete"]).target_prefix("resource/")
        .valid_between(50, 2000).generation("generation:01")
        .delegation_depth(4).quota(101).build().unwrap();
    assert_eq!(authority.delegate("grant:parent", widened),
               Err(AuthorityError::AttenuationViolation));
}

#[test]
fn revocation_outage_self_authority_and_enforcement_bypass_fail_closed() {
    let temp = tempfile::TempDir::new().unwrap();
    let ledger = temp.path().join("authority.json");
    let mut authority = Authority::open(&ledger, "policy:v2", "generation:01", "state:9").unwrap();
    assert_eq!(authority.issue(parent(), IndependentApproval::verified("activation:parent")),
               Err(AuthorityError::SelfAuthority));
    authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
    let request = Invocation::new("command:01", MachineId::new("machine:01").unwrap(),
        ServiceId::new("service:runtime").unwrap(), ActivationId::new("activation:parent").unwrap(),
        "ToolCap", "write", "resource/group/item/1", 200, "state:9", "objective:01");
    assert_eq!(authority.evaluate(&request).denial_code.as_deref(),
               Some("UNAUTHORIZED"));
    let enforced = request.clone().with_enforcement(EnforcementProof::verified("lsm:habitat"));
    assert!(authority.evaluate(&enforced).allowed);
    assert!(authority.revoke("grant:parent"));
    let child = Grant::builder("grant:late", "activation:parent", "activation:child", "ToolCap")
        .operations(["read"]).target_prefix("resource/group/item/")
        .valid_between(100, 500).generation("generation:01").delegation_depth(2).build().unwrap();
    assert_eq!(authority.delegate("grant:parent", child), Err(AuthorityError::ParentInactive));
    drop(authority);
    let mut authority = Authority::open(&ledger, "policy:v2", "generation:01", "state:9").unwrap();
    assert_eq!(authority.evaluate(&enforced).denial_code.as_deref(), Some("UNAUTHORIZED"));
    authority.set_available(false);
    assert_eq!(authority.evaluate(&enforced).denial_code.as_deref(), Some("UNAVAILABLE"));
    let audit = authority.audit().last().unwrap();
    assert_eq!((&audit.subject, &audit.objective, &audit.target, &audit.operation),
               (&"activation:parent".into(), &"objective:01".into(),
                &"resource/group/item/1".into(), &"write".into()));
    assert!(!audit.result_evidence.is_empty());
}

#[test]
fn a_revoked_matching_grant_cannot_mask_an_independent_current_grant() {
    let mut authority=Authority::new("policy:v2","generation:01","state:1");
    for id in ["grant:a-revoked","grant:b-current"] {
        let grant=Grant::builder(id,"service:issuer","activation:subject","ReadCap")
            .operations(["read"]).target_prefix("opaque/").valid_between(1,100)
            .generation("generation:01").build().unwrap();
        authority.issue(grant,IndependentApproval::verified("operator:01")).unwrap();
    }
    authority.revoke("grant:a-revoked");
    let request=Invocation::new("command:1",MachineId::new("machine:1").unwrap(),
        ServiceId::new("service:1").unwrap(),ActivationId::new("activation:subject").unwrap(),
        "ReadCap","read","opaque/item",10,"state:1","objective:1");
    let decision=authority.evaluate(&request);
    assert!(decision.allowed);
    assert_eq!(decision.grant_id.as_deref(),Some("grant:b-current"));
}
