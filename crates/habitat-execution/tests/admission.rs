use habitat_execution::*;

#[test]
fn profile_must_admit_runtime_and_resources_before_execution() {
    let profile = HardwareProfile::qemu_conformance();
    let native = IsolationRequest::new(Runtime::Native, 1, 256, 64, 8, 30);
    assert!(profile.admit(&native).is_ok());
    assert_eq!(
        profile.admit(&IsolationRequest {
            cpu_cores: 3,
            ..native.clone()
        }),
        Err(AdmissionError::CapacityExceeded)
    );
    assert_eq!(
        profile.admit(&IsolationRequest {
            runtime: Runtime::Wasi,
            ..native.clone()
        }),
        Err(AdmissionError::RuntimeUnsupported)
    );
}

#[test]
fn native_and_oci_boundaries_are_default_deny_by_construction() {
    let spec = NativeSandbox::new("/activation/work").command("/nix/store/tool/bin/worker");
    assert!(spec.unshare_network && spec.clear_environment && spec.read_only_nix_store);
    assert_eq!(spec.writable_paths, vec!["/activation/work"]);
    assert!(spec.device_allowlist.is_empty());
    assert!(!spec
        .mounts
        .iter()
        .any(|path| path.contains("provider") || path.contains("evidence")));
    assert_eq!(
        OciImage::parse("registry/image:latest"),
        Err(ImageError::DigestRequired)
    );
    assert!(OciImage::parse(
        "registry/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    .is_ok());
}
