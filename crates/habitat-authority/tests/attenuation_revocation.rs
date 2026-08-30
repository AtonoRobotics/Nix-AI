use habitat_authority::*;

fn parent() -> Grant {
    Grant::builder("grant:parent", "service:issuer", "activation:parent", "ToolCap")
        .operations(["read", "write"]).target_prefix("robot/arm/")
        .valid_between(100, 1000).generation("generation:01")
        .delegation_depth(3).quota(100).build().unwrap()
}

#[test]
fn delegation_can_only_reduce_every_parent_bound() {
    for operations in [["read"], ["write"]] {
        for expiry in [500, 999] {
            for quota in [1, 100] {
                let mut authority = Authority::new("policy:v1", "generation:01");
                authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
                let child = Grant::builder("grant:child", "activation:parent",
                    "activation:child", "ToolCap").operations(operations)
                    .target_prefix("robot/arm/joint/").valid_between(100, expiry)
                    .generation("generation:01").delegation_depth(2).quota(quota).build().unwrap();
                assert!(authority.delegate("grant:parent", child).is_ok());
            }
        }
    }
    let mut authority = Authority::new("policy:v1", "generation:01");
    authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
    let widened = Grant::builder("grant:widened", "activation:parent", "activation:child",
        "ToolCap").operations(["delete"]).target_prefix("robot/")
        .valid_between(50, 2000).generation("generation:01")
        .delegation_depth(4).quota(101).build().unwrap();
    assert_eq!(authority.delegate("grant:parent", widened),
               Err(AuthorityError::AttenuationViolation));
}

#[test]
fn revocation_outage_self_authority_and_physical_bypass_fail_closed() {
    let temp = tempfile::TempDir::new().unwrap();
    let ledger = temp.path().join("authority.json");
    let mut authority = Authority::open(&ledger, "policy:v1", "generation:01").unwrap();
    assert_eq!(authority.issue(parent(), IndependentApproval::verified("activation:parent")),
               Err(AuthorityError::SelfAuthority));
    authority.issue(parent(), IndependentApproval::verified("operator:01")).unwrap();
    let request = Invocation::new("command:01", MachineId::new("machine:01").unwrap(),
        ServiceId::new("service:runtime").unwrap(), ActivationId::new("activation:parent").unwrap(),
        "ToolCap", "write", "robot/arm/joint/1", 200, "state:9", "objective:01");
    assert_eq!(authority.evaluate(&request).denial_code.as_deref(),
               Some("PHYSICAL_ENFORCEMENT_UNVERIFIED"));
    let enforced = request.clone().with_enforcement(EnforcementProof::verified("lsm:habitat"));
    assert!(authority.evaluate(&enforced).allowed);
    assert!(authority.revoke("grant:parent"));
    drop(authority);
    let mut authority = Authority::open(&ledger, "policy:v1", "generation:01").unwrap();
    assert_eq!(authority.evaluate(&enforced).denial_code.as_deref(), Some("GRANT_REVOKED"));
    authority.set_available(false);
    assert_eq!(authority.evaluate(&enforced).denial_code.as_deref(), Some("AUTHORITY_UNAVAILABLE"));
    let audit = authority.audit().last().unwrap();
    assert_eq!((&audit.subject, &audit.objective, &audit.target, &audit.operation),
               (&"activation:parent".into(), &"objective:01".into(),
                &"robot/arm/joint/1".into(), &"write".into()));
    assert!(!audit.result_evidence.is_empty());
}
