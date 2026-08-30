use habitat_abi::{negotiate_version, VersionError, ABI_VERSION};

#[test]
fn compatible_minor_is_accepted_and_unknown_major_is_rejected() {
    assert_eq!(ABI_VERSION, "1.0");
    assert_eq!(negotiate_version("1.7").unwrap(), "1.0");
    assert_eq!(negotiate_version("2.0"), Err(VersionError::UnsupportedMajor));
    assert_eq!(negotiate_version("invalid"), Err(VersionError::Invalid));
}
