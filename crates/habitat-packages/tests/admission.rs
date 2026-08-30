use ed25519_dalek::{Signer,SigningKey};
use habitat_packages::*;

fn manifest()->PackageManifest{PackageManifest::builder("package:weather","1.0.0","publisher:trusted",
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .artifact("oci@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .provides("weather.read","1.0.0").supply_chain("source:git:abc","lock:sha256:def",
        "build:nix:ghi","sbom:sha256:jkl","vuln:passed","reproducible:yes").build()}

#[test]
fn signed_digest_addressed_package_is_admitted_without_granting_authority(){
    let signing=SigningKey::from_bytes(&[7;32]);let mut trust=TrustStore::new();
    trust.trust("publisher:trusted",signing.verifying_key());
    let mut controller=PackageController::new(trust);let manifest=manifest();
    let signature=signing.sign(&manifest.signing_bytes()).to_bytes();
    let admitted=controller.admit(manifest,signature).unwrap();
    assert_eq!(admitted.state,ProviderState::Admitted);
    assert!(!admitted.provider_authority&&!admitted.agent_authority);
    assert_eq!(controller.package_count(),1);
}
