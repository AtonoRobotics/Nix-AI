use ed25519_dalek::{Signer, SigningKey};
use habitat_packages::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

struct Probe;
impl ProbeExecutor for Probe {
    fn execute(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, String> {
        Ok(b"live observation".to_vec())
    }
}
fn hash(v: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(v))
}
fn setup() -> (PackageController, SigningKey, AdmissionPolicy) {
    let k = SigningKey::from_bytes(&[9; 32]);
    let mut t = TrustStore::new();
    t.trust("publisher:trusted", k.verifying_key());
    (
        PackageController::new(t),
        k,
        AdmissionPolicy::strict(&[], 128 * 1024 * 1024, 2_000, &["isolated"]),
    )
}
fn package(id: &str, version: &str, byte: u8) -> BundleSubmission {
    let bundle = vec![byte; 8];
    let sbom = b"sbom".to_vec();
    let m = PackageManifest::builder(id, version, "publisher:trusted", &hash(&bundle))
        .artifact(&format!("oci@{}", hash(&bundle)))
        .supply_chain(
            "source",
            "lock",
            "build",
            &hash(&sbom),
            "vuln:passed",
            "yes",
        )
        .build();
    let provenance = br#"{"source":"source","lock":"lock","builder":"build"}"#.to_vec();
    BundleSubmission::unsigned(m, bundle, provenance, sbom, vec![])
}
fn admit(c: &mut PackageController, k: &SigningKey, mut s: BundleSubmission, p: &AdmissionPolicy) {
    s.signature = k.sign(&s.bytes_to_sign()).to_bytes();
    c.admit_bundle(s, p, &mut Probe).unwrap();
}

#[test]
fn activation_is_content_bound_and_rollback_preserves_work_binding() {
    let (mut c, k, p) = setup();
    admit(&mut c, &k, package("package:v1", "1", 1), &p);
    let env = HostProfile::new(&[], &[]);
    let first = c
        .qualify_and_activate(&["package:v1"], &env, "ignored")
        .unwrap();
    let work = c.bind("work:1").unwrap();
    admit(&mut c, &k, package("package:v2", "2", 2), &p);
    c.qualify_and_activate(&["package:v2"], &env, "ignored")
        .unwrap();
    assert_eq!(c.binding("work:1").unwrap(), &work);
    assert_eq!(c.rollback().unwrap().id, first.id);
}

fn proposal() -> ChangeProposal {
    ChangeProposal {
        id: "change:1".into(),
        source_digest: "sha256:source".into(),
        dependency_closure_digest: "sha256:closure".into(),
        contract_version: CONTRACT_VERSION.into(),
        tests_digest: "sha256:tests".into(),
        threshold: 90,
        evaluator: "service:evaluator".into(),
        evaluator_closure: "nix:immutable-evaluator".into(),
        target_generation: 2,
        rollback_generation: 1,
        requested_authority: BTreeSet::new(),
    }
}

#[test]
fn governed_change_is_durable_from_proposal_through_confirmation() {
    let mut j = ChangeJournal::new("service:evaluator", "nix:immutable-evaluator", &[], &[1]);
    j.propose(proposal()).unwrap();
    j.built("change:1", "build evidence").unwrap();
    j.evaluated(
        "change:1",
        "service:evaluator",
        "nix:immutable-evaluator",
        95,
        "evaluation",
    )
    .unwrap();
    j.signed("change:1", "detached signature").unwrap();
    j.staged("change:1", "staging").unwrap();
    j.activated("change:1", "boot-counted activation").unwrap();
    let bytes = j.snapshot();
    let mut restored = ChangeJournal::restore(&bytes).unwrap();
    restored
        .confirmed("change:1", "service:health", true, true, "live health")
        .unwrap();
    assert_eq!(
        restored.record("change:1").unwrap().state,
        ChangeState::Confirmed
    );
    assert_eq!(restored.record("change:1").unwrap().evidence.len(), 6);
}

#[test]
fn evaluator_capture_threshold_failure_self_confirmation_and_rollback_are_enforced() {
    let mut j = ChangeJournal::new("service:evaluator", "nix:immutable-evaluator", &[], &[1]);
    let mut captured = proposal();
    captured.evaluator = "candidate".into();
    assert_eq!(j.propose(captured), Err(ChangeError::EvaluatorCapture));
    j.propose(proposal()).unwrap();
    j.built("change:1", "build").unwrap();
    assert_eq!(
        j.evaluated(
            "change:1",
            "candidate",
            "nix:immutable-evaluator",
            100,
            "fake"
        ),
        Err(ChangeError::EvaluatorCapture)
    );
    j.evaluated(
        "change:1",
        "service:evaluator",
        "nix:immutable-evaluator",
        95,
        "evaluation",
    )
    .unwrap();
    j.signed("change:1", "signature").unwrap();
    j.staged("change:1", "stage").unwrap();
    j.activated("change:1", "activate").unwrap();
    assert_eq!(
        j.confirmed("change:1", "service:evaluator", true, true, "self"),
        Err(ChangeError::SelfConfirmation)
    );
    assert_eq!(
        j.confirmed("change:1", "service:health", false, true, "bad"),
        Err(ChangeError::HealthGateFailed)
    );
    j.quarantine("change:1", "failed confirmation").unwrap();
    assert_eq!(j.rollback("change:1", "automatic rollback").unwrap(), 1);
    assert_eq!(j.record("change:1").unwrap().state, ChangeState::RolledBack);
}

#[test]
fn low_score_rejects_and_authority_or_rollback_tampering_never_enters_journal() {
    let mut j = ChangeJournal::new("service:evaluator", "nix:immutable-evaluator", &[], &[1]);
    let mut widened = proposal();
    widened.requested_authority.insert("root".into());
    assert_eq!(j.propose(widened), Err(ChangeError::AuthorityWidened));
    let mut missing = proposal();
    missing.rollback_generation = 99;
    assert_eq!(j.propose(missing), Err(ChangeError::RollbackTargetMissing));
    j.propose(proposal()).unwrap();
    j.built("change:1", "build").unwrap();
    j.evaluated(
        "change:1",
        "service:evaluator",
        "nix:immutable-evaluator",
        89,
        "failed evaluation",
    )
    .unwrap();
    assert_eq!(j.record("change:1").unwrap().state, ChangeState::Rejected);
}
