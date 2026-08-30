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
    assert_eq!(
        profile.admit(&IsolationRequest {
            process_limit: 65,
            ..native.clone()
        }),
        Err(AdmissionError::CapacityExceeded)
    );
    assert_eq!(
        profile.admit(&IsolationRequest {
            timeout_seconds: 301,
            ..native.clone()
        }),
        Err(AdmissionError::CapacityExceeded)
    );
}

#[test]
fn native_and_oci_boundaries_are_default_deny_by_construction() {
    let request = IsolationRequest::new(Runtime::Native, 1, 256, 64, 8, 30);
    let profile = HardwareProfile::qemu_conformance();
    profile.admit(&request).unwrap();
    let spec =
        NativeSandbox::new("/activation/work").command("/nix/store/tool/bin/worker", &request);
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
    assert_eq!(
        (spec.cpu_cores, spec.memory_mib, spec.storage_mib),
        (1, 256, 64)
    );
    assert_eq!((spec.process_limit, spec.timeout_seconds), (8, 30));
    assert!(OciImage::parse(
        "registry/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    .is_ok());
}
