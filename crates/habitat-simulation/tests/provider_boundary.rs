use habitat_simulation::{
    CompatibilityCapsule, GpuFeature, GpuIsolationBoundary, QualificationReport,
    SimulationCapability, SimulationCommand, SimulationProvider,
};

#[test]
fn admits_only_digest_pinned_capsules_matching_the_gpu_profile() {
    let provider = SimulationProvider::new(
        "generic-x86_64-nvidia",
        "RTX 6000 Ada",
        "550.127.05",
        24_576,
    );
    let capsule=CompatibilityCapsule::new(
        "nvcr.io/nvidia/isaac-sim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "RTX 6000 Ada","550.127.05",16_384,[GpuFeature::Rtx,GpuFeature::IsaacSim]);
    let admission = provider.admit(&capsule).unwrap();
    assert_eq!(admission.profile_id, "generic-x86_64-nvidia");
    assert_eq!(admission.device_nodes, ["/dev/nvidia0", "/dev/nvidiactl"]);
    assert!(admission.environment.is_empty());

    assert!(provider
        .admit(&CompatibilityCapsule::new(
            "nvcr.io/nvidia/isaac-sim:latest",
            "RTX 6000 Ada",
            "550.127.05",
            16_384,
            [GpuFeature::Rtx, GpuFeature::IsaacSim]
        ))
        .is_err());
}

#[test]
fn qualification_report_exposes_all_required_digest_addressed_evidence() {
    let report = QualificationReport::passed(
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "generic-x86_64-nvidia",
        "RTX 6000 Ada",
        "550.127.05",
        "effect:sha256:effect",
        "evidence:sha256:observation",
    );
    let evidence = report.evidence();
    assert_eq!(evidence.len(), 3);
    for name in [
        "rtx-isaac-live-report",
        "simulation-effect-report",
        "gpu-isolation-report",
    ] {
        let item = evidence.get(name).unwrap();
        assert_eq!(item.outcome, "passed");
        assert!(item.artifact_digest.starts_with("sha256:"));
        assert!(!item.observations.is_empty());
    }
}

#[test]
fn gpu_nodes_are_lease_scoped_and_direct_host_access_is_denied() {
    let provider = SimulationProvider::new(
        "generic-x86_64-nvidia",
        "RTX 6000 Ada",
        "550.127.05",
        24_576,
    );
    let admission=provider.admit(&CompatibilityCapsule::new(
        "nvcr.io/nvidia/isaac-sim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "RTX 6000 Ada","550.127.05",16_384,[GpuFeature::Rtx,GpuFeature::IsaacSim])).unwrap();
    let mut boundary = GpuIsolationBoundary::new(admission);
    let sandbox = boundary.acquire("activation:12", "lease:gpu:12").unwrap();
    assert_eq!(sandbox.device_nodes, ["/dev/nvidia0", "/dev/nvidiactl"]);
    assert!(sandbox.clear_environment);
    assert!(sandbox.read_only_host);
    assert!(boundary.open_device("lease:gpu:12", "/dev/nvidia0").is_ok());
    assert!(boundary
        .open_device("lease:gpu:12", "/dev/nvidia1")
        .is_err());
    assert!(boundary.open_device("ambient", "/dev/nvidia0").is_err());
    boundary.release("lease:gpu:12").unwrap();
    assert!(boundary
        .open_device("lease:gpu:12", "/dev/nvidia0")
        .is_err());
}

#[test]
fn authorized_simulation_commands_return_idempotent_typed_effects() {
    let provider = SimulationProvider::new(
        "generic-x86_64-nvidia",
        "RTX 6000 Ada",
        "550.127.05",
        24_576,
    );
    let admission=provider.admit(&CompatibilityCapsule::new(
        "nvcr.io/nvidia/isaac-sim@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "RTX 6000 Ada","550.127.05",16_384,[GpuFeature::Rtx,GpuFeature::IsaacSim])).unwrap();
    let mut capability = SimulationCapability::new(admission, &["simulation.step"]);
    let command = SimulationCommand::new(
        "command:12",
        "activation:12",
        "objective:12",
        "simulation.step",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "idempotency:12",
    );
    let first = capability
        .execute(command.clone(), "authority:decision:allow")
        .unwrap();
    let replay = capability
        .execute(command, "authority:decision:allow")
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.state, "OBSERVED_SUCCEEDED");
    assert_eq!(first.authority_decision, "authority:decision:allow");
    assert!(first.effect_id.starts_with("effect:sha256:"));
    assert!(first.evidence_ref.starts_with("evidence:sha256:"));
}
