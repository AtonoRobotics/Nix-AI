use ed25519_dalek::{Signer,SigningKey};
use habitat_packages::*;

fn controller()->(PackageController,SigningKey){let key=SigningKey::from_bytes(&[9;32]);let mut trust=TrustStore::new();
    trust.trust("publisher:trusted",key.verifying_key());(PackageController::new(trust),key)}
fn package(id:&str,version:&str,artifact_char:char)->PackageManifest{
    PackageManifest::builder(id,version,"publisher:trusted",&format!("sha256:{}",artifact_char.to_string().repeat(64)))
    .artifact(&format!("oci@sha256:{}",artifact_char.to_string().repeat(64)))
    .provides(id.trim_start_matches("package:"),version).supply_chain("source:git:abc","lock:sha256:def",
        "build:nix:ghi","sbom:sha256:jkl","vuln:passed","reproducible:yes").build()}
fn admit(controller:&mut PackageController,key:&SigningKey,manifest:PackageManifest){let sig=key.sign(&manifest.signing_bytes()).to_bytes();
    controller.admit(manifest,sig).unwrap();}

#[test]
fn dependency_closure_and_behavioral_probe_gate_immutable_activation_set(){
    let (mut controller,key)=controller();let storage=package("package:storage","1.0.0",'a');
    let app=package("package:app","1.0.0",'b').requires("storage","1.0.0").requirements(
        &["gpu:rtx"],&["isolation:oci"],"state:v1");
    admit(&mut controller,&key,storage);admit(&mut controller,&key,app);
    let env=HostProfile::new(&["gpu:rtx"],&["isolation:oci"]);
    let resolved=controller.resolve(&["package:app"],&env).unwrap();
    controller.stage(&resolved).unwrap();
    assert_eq!(controller.activate(&resolved),Err(PackageError::LiveVerificationRequired));
    controller.verify(&resolved,BehavioralProbe::passed("weather-contract","evidence:probe")).unwrap();
    let set=controller.activate(&resolved).unwrap();
    assert!(set.id.starts_with("activation-set:sha256:"));assert_eq!(set.entries.len(),2);
    assert!(set.entries.iter().all(|e|e.artifact_ref.contains("@sha256:")));
}

#[test]
fn replacement_drains_new_binding_while_existing_work_stays_pinned_and_rollback_is_exact(){
    let (mut controller,key)=controller();let v1=package("package:weather-v1","1.0.0",'c');
    admit(&mut controller,&key,v1);let env=HostProfile::new(&[],&[]);
    let first=controller.qualify_and_activate(&["package:weather-v1"],&env,"evidence:v1").unwrap();
    let work=controller.bind("activation:work-1").unwrap();
    let v2=package("package:weather-v2","2.0.0",'d');admit(&mut controller,&key,v2);
    let second=controller.qualify_and_activate(&["package:weather-v2"],&env,"evidence:v2").unwrap();
    controller.drain("package:weather-v1").unwrap();
    assert_eq!(controller.binding("activation:work-1").unwrap().activation_set_id,first.id);
    assert_eq!(controller.bind("activation:work-2").unwrap().activation_set_id,second.id);
    let rolled_back=controller.rollback().unwrap();assert_eq!(rolled_back.id,first.id);
    assert_eq!(work.activation_set_id,first.id);
}

#[test]
fn revocation_and_migration_fail_closed_with_recovery_evidence(){
    let (mut controller,key)=controller();let stateful=package("package:stateful","1.0.0",'e');
    admit(&mut controller,&key,stateful);let env=HostProfile::new(&[],&[]);
    controller.qualify_and_activate(&["package:stateful"],&env,"evidence:stateful").unwrap();
    let migration=MigrationContract{from:"state:v1".into(),to:"state:v2".into(),direction:MigrationDirection::ForwardOnly,
        interruption:"requires-drain".into(),rollback_limit:"none".into(),destructive:true,evidence:None};
    assert_eq!(controller.migrate("package:stateful",migration),Err(PackageError::DestructiveMigrationUnproven));
    let recovery=controller.revoke("package:stateful",&["effect:unknown"],&["objective:dependent"]).unwrap();
    assert_eq!(recovery.unresolved_effects,vec!["effect:unknown"]);assert_eq!(recovery.recovery_wakes.len(),1);
}
