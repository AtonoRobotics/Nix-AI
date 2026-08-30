use ed25519_dalek::{Signer, SigningKey};
use habitat_packages::*;
use sha2::{Digest, Sha256};

struct Probe {
    fail: bool,
    calls: usize,
}
impl ProbeExecutor for Probe {
    fn execute(&mut self, contract: &str, bundle: &[u8]) -> Result<Vec<u8>, String> {
        self.calls += 1;
        if self.fail || contract != "probe:weather" || bundle != b"immutable bundle" {
            return Err("probe failed".into());
        }
        Ok(b"observed weather response".to_vec())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn fixture() -> (
    PackageController,
    SigningKey,
    BundleSubmission,
    AdmissionPolicy,
    Probe,
) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut trust = TrustStore::new();
    trust.trust("publisher:trusted", key.verifying_key());
    let bundle = b"immutable bundle".to_vec();
    let sbom = b"cyclonedx sbom".to_vec();
    let manifest = PackageManifest::builder(
        "package:weather",
        "1.0.0",
        "publisher:trusted",
        &hash(&bundle),
    )
    .artifact(&format!("oci@{}", hash(&bundle)))
    .provides("weather.read", "1.0.0")
    .supply_chain(
        "source:git:abc",
        "lock:sha256:def",
        "build:nix:ghi",
        &hash(&sbom),
        "vuln:passed",
        "reproducible:yes",
    )
    .policy(PackagePolicy {
        authority: &["weather.read"],
        memory_limit_bytes: 1024,
        cpu_limit_millis: 100,
        execution_profile: "isolated",
        abi_version: CONTRACT_VERSION,
        migration_contract: "migration:stateless",
        live_verification_contract: "probe:weather",
    })
    .build();
    let provenance =
        br#"{"source":"source:git:abc","lock":"lock:sha256:def","builder":"build:nix:ghi"}"#
            .to_vec();
    let mut submission = BundleSubmission::unsigned(manifest, bundle, provenance, sbom, vec![]);
    submission.signature = key.sign(&submission.bytes_to_sign()).to_bytes();
    (
        PackageController::new(trust),
        key,
        submission,
        AdmissionPolicy::strict(&["weather.read"], 2048, 200, &["isolated"]),
        Probe {
            fail: false,
            calls: 0,
        },
    )
}

#[test]
fn admission_verifies_bytes_detached_material_policy_and_runs_probe() {
    let (mut controller, _, submission, policy, mut probe) = fixture();
    let admitted = controller
        .admit_bundle(submission, &policy, &mut probe)
        .unwrap();
    assert_eq!(admitted.state, ProviderState::Admitted);
    assert_eq!(probe.calls, 1);
    assert!(!admitted.provider_authority && !admitted.agent_authority);
    assert!(admitted.admission_evidence.starts_with("sha256:"));
}

#[test]
fn tampering_and_failed_probe_fail_closed_without_mutation() {
    type TamperCase = (fn(&mut BundleSubmission), PackageError);
    let cases: Vec<TamperCase> = vec![
        (|s| s.bundle.push(0), PackageError::SignatureInvalid),
        (|s| s.signature[0] ^= 1, PackageError::SignatureInvalid),
        (|s| s.provenance.clear(), PackageError::SignatureInvalid),
        (|s| s.sbom.clear(), PackageError::SignatureInvalid),
        (
            |s| s.dependency_closure.push("extra@1".into()),
            PackageError::SignatureInvalid,
        ),
    ];
    for (alter, expected) in cases {
        let (mut c, _, mut s, p, mut probe) = fixture();
        alter(&mut s);
        assert_eq!(c.admit_bundle(s, &p, &mut probe), Err(expected));
        assert_eq!(c.package_count(), 0);
    }
    let (mut c, key, mut s, p, mut probe) = fixture();
    s.manifest.requested_authority.push("root".into());
    s.signature = key.sign(&s.bytes_to_sign()).to_bytes();
    assert_eq!(
        c.admit_bundle(s, &p, &mut probe),
        Err(PackageError::AuthorityExceeded)
    );
    let (mut c, key, mut s, p, mut probe) = fixture();
    s.manifest.memory_limit_bytes = 9999;
    s.signature = key.sign(&s.bytes_to_sign()).to_bytes();
    assert_eq!(
        c.admit_bundle(s, &p, &mut probe),
        Err(PackageError::ResourcesExceeded)
    );
    let (mut c, key, mut s, p, mut probe) = fixture();
    s.manifest.abi_version = "V9".into();
    s.signature = key.sign(&s.bytes_to_sign()).to_bytes();
    assert_eq!(
        c.admit_bundle(s, &p, &mut probe),
        Err(PackageError::AbiIncompatible)
    );
    let (mut c, key, mut s, p, mut probe) = fixture();
    s.manifest.migration_contract.clear();
    s.signature = key.sign(&s.bytes_to_sign()).to_bytes();
    assert_eq!(
        c.admit_bundle(s, &p, &mut probe),
        Err(PackageError::MigrationContractMissing)
    );
    let (mut c, _, s, p, mut probe) = fixture();
    probe.fail = true;
    assert_eq!(
        c.admit_bundle(s, &p, &mut probe),
        Err(PackageError::BehavioralProbeFailed)
    );
    assert_eq!(c.package_count(), 0);
}

#[test]
fn duplicate_package_is_a_staging_race() {
    let (mut c, key, s, p, mut probe) = fixture();
    c.admit_bundle(s.clone(), &p, &mut probe).unwrap();
    let mut again = s;
    again.signature = key.sign(&again.bytes_to_sign()).to_bytes();
    assert_eq!(
        c.admit_bundle(again, &p, &mut probe),
        Err(PackageError::StagingRace)
    );
}
