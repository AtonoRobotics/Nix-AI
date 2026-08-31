use habitat_uds::{
    connect, publish_readiness, read_frame, read_readiness, write_frame, write_readiness,
    AuthenticatedListener, FrameConfig, JsonTransport, ObservedPeer, PeerAllowlist, PeerPrincipal,
    Readiness, ServiceAllowlist, ServiceCommandPolicy, ServicePrincipal, SocketPermissions,
    StreamTimeouts, TransportError,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum TestCommand {
    Inspect,
    Mutate,
}

#[test]
fn command_policy_denies_an_allowlisted_service_crossing_role_boundaries() {
    let runtime = ServicePrincipal::new("service:runtime", 1001, 1001).unwrap();
    let operator = ServicePrincipal::new("service:operator", 1002, 1002).unwrap();
    let policy = ServiceCommandPolicy::new([
        (
            runtime.clone(),
            vec![TestCommand::Inspect, TestCommand::Mutate],
        ),
        (operator.clone(), vec![TestCommand::Inspect]),
    ]);

    assert!(policy.authorize(&runtime, &TestCommand::Mutate).is_ok());
    assert!(matches!(
        policy.authorize(&operator, &TestCommand::Mutate),
        Err(TransportError::CommandDenied(service)) if service == "service:operator"
    ));
}
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Cursor, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    thread,
    time::Duration,
};

fn timeouts() -> StreamTimeouts {
    StreamTimeouts::new(Duration::from_millis(250), Duration::from_millis(250)).unwrap()
}

#[test]
fn bounded_frame_round_trips() {
    let config = FrameConfig::new(16).unwrap();
    let mut wire = Vec::new();
    write_frame(&mut wire, b"hello", config).unwrap();
    assert_eq!(
        read_frame(&mut Cursor::new(wire), config).unwrap(),
        b"hello"
    );
}

#[test]
fn oversized_frames_are_rejected_before_payload_read() {
    let config = FrameConfig::new(4).unwrap();
    let error = read_frame(&mut Cursor::new(5_u32.to_be_bytes()), config).unwrap_err();
    assert!(matches!(
        error,
        TransportError::FrameTooLarge {
            length: 5,
            maximum: 4
        }
    ));
    let error = write_frame(&mut Vec::new(), b"12345", config).unwrap_err();
    assert!(matches!(error, TransportError::FrameTooLarge { .. }));
}

#[test]
fn partial_header_and_payload_are_disconnect_errors() {
    let config = FrameConfig::new(8).unwrap();
    for wire in [vec![0, 0], vec![0, 0, 0, 4, b'a', b'b']] {
        let error = read_frame(&mut Cursor::new(wire), config).unwrap_err();
        assert!(
            matches!(error, TransportError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Request {
    claimed: PeerPrincipal,
    operation: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Response {
    accepted: bool,
}

#[test]
fn typed_json_transport_rejects_malformed_utf8_and_json() {
    let config = FrameConfig::new(128).unwrap();
    let mut utf8 = Vec::new();
    write_frame(&mut utf8, &[0xff], config).unwrap();
    let mut transport = JsonTransport::<_, Request, Response>::new(Cursor::new(utf8), config);
    assert!(matches!(
        transport.receive_request(),
        Err(TransportError::InvalidUtf8(_))
    ));

    let mut json = Vec::new();
    write_frame(&mut json, b"{broken", config).unwrap();
    let mut transport = JsonTransport::<_, Request, Response>::new(Cursor::new(json), config);
    assert!(matches!(
        transport.receive_request(),
        Err(TransportError::InvalidJson(_))
    ));
}

#[test]
fn typed_request_and_response_round_trip() {
    let config = FrameConfig::new(256).unwrap();
    let (client, server) = UnixStream::pair().unwrap();
    let worker = thread::spawn(move || {
        let mut transport = JsonTransport::<_, Request, Response>::new(server, config);
        let request = transport.receive_request().unwrap();
        assert_eq!(request.operation, "inspect");
        transport
            .send_response(&Response { accepted: true })
            .unwrap();
    });
    let mut transport = JsonTransport::<_, Request, Response>::new(client, config);
    transport
        .send_request(&Request {
            claimed: PeerPrincipal {
                pid: 1,
                uid: 2,
                gid: 3,
            },
            operation: "inspect".into(),
        })
        .unwrap();
    assert_eq!(
        transport.receive_response().unwrap(),
        Response { accepted: true }
    );
    worker.join().unwrap();
}

#[test]
fn allowlisted_principal_is_observed_and_cannot_be_forged_in_payload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let observed = PeerPrincipal::current_process();
    let listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o660).unwrap(),
        PeerAllowlist::principals([observed]),
        timeouts(),
    )
    .unwrap();
    let client = UnixStream::connect(&path).unwrap();
    let authenticated = listener.accept().unwrap();
    assert_eq!(authenticated.principal(), observed);

    let forged = PeerPrincipal {
        pid: observed.pid.saturating_add(10_000),
        uid: observed.uid.saturating_add(1),
        gid: observed.gid.saturating_add(1),
    };
    let config = FrameConfig::new(256).unwrap();
    let mut client = JsonTransport::<_, Request, Response>::new(client, config);
    client
        .send_request(&Request {
            claimed: forged,
            operation: "inspect".into(),
        })
        .unwrap();
    let mut server = authenticated.into_transport::<Request, Response>(config);
    assert_eq!(server.receive_request().unwrap().claimed, forged);
    assert_ne!(observed, forged);
}

#[test]
fn disallowed_authenticated_peer_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::denies_all(),
        timeouts(),
    )
    .unwrap();
    let _client = UnixStream::connect(&path).unwrap();
    assert!(matches!(
        listener.accept(),
        Err(TransportError::PeerDenied(_))
    ));
}

#[test]
fn any_authenticated_mode_still_extracts_kernel_principal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .unwrap();
    let _client = UnixStream::connect(&path).unwrap();
    assert_eq!(
        listener.accept().unwrap().principal(),
        PeerPrincipal::current_process()
    );
}

#[test]
fn typed_client_connects_through_the_public_transport_seam() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .unwrap();
    let config = FrameConfig::new(256).unwrap();
    let mut client = connect::<Request, Response>(&path, config).unwrap();
    let authenticated = listener.accept().unwrap();
    let worker = thread::spawn(move || {
        let mut server = authenticated.into_transport::<Request, Response>(config);
        let request = server.receive_request().unwrap();
        server
            .send_response(&Response {
                accepted: request.operation == "status",
            })
            .unwrap();
    });
    client
        .send_request(&Request {
            claimed: PeerPrincipal::current_process(),
            operation: "status".into(),
        })
        .unwrap();
    assert!(client.receive_response().unwrap().accepted);
    worker.join().unwrap();
}

#[test]
fn stale_socket_is_replaced_but_live_socket_and_regular_file_are_safe() {
    let directory = tempfile::tempdir().unwrap();
    let stale_path = directory.path().join("stale.sock");
    let stale = std::os::unix::net::UnixListener::bind(&stale_path).unwrap();
    drop(stale);
    let replacement = AuthenticatedListener::bind(
        &stale_path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .unwrap();
    drop(replacement);

    let live_path = directory.path().join("live.sock");
    let live = std::os::unix::net::UnixListener::bind(&live_path).unwrap();
    assert!(AuthenticatedListener::bind(
        &live_path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .is_err());
    assert!(live.local_addr().is_ok());

    let file_path = directory.path().join("important");
    fs::write(&file_path, "keep me").unwrap();
    assert!(AuthenticatedListener::bind(
        &file_path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .is_err());
    assert_eq!(fs::read_to_string(file_path).unwrap(), "keep me");
}

#[test]
fn socket_mode_is_applied_and_world_permissive_modes_are_rejected() {
    assert!(SocketPermissions::new(0o666).is_err());
    assert!(SocketPermissions::new(0o606).is_err());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let _listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o660).unwrap(),
        PeerAllowlist::any_authenticated(),
        timeouts(),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o660
    );
}

#[test]
fn readiness_uses_the_same_bounded_frame_contract() {
    let config = FrameConfig::new(128).unwrap();
    let expected = Readiness::Operational { pid: 42 };
    let mut wire = Vec::new();
    write_readiness(&mut wire, expected, config).unwrap();
    assert_eq!(
        read_readiness(&mut Cursor::new(wire), config).unwrap(),
        expected
    );
}

#[test]
fn readiness_publication_atomically_replaces_and_leaves_no_partial_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("readiness");
    let frames = FrameConfig::new(128).unwrap();
    publish_readiness(&path, Readiness::Recovering { pid: 7 }, frames).unwrap();
    publish_readiness(&path, Readiness::Operational { pid: 8 }, frames).unwrap();
    assert_eq!(
        read_readiness(&mut fs::File::open(&path).unwrap(), frames).unwrap(),
        Readiness::Operational { pid: 8 }
    );
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn peer_disconnect_is_reported_without_a_default_response() {
    let config = FrameConfig::new(128).unwrap();
    let (client, mut server) = UnixStream::pair().unwrap();
    server.write_all(&4_u32.to_be_bytes()).unwrap();
    server.write_all(b"{}").unwrap();
    drop(server);
    let mut transport = JsonTransport::<_, Request, Response>::new(client, config);
    assert!(matches!(
        transport.receive_response(),
        Err(TransportError::Io(ref io)) if io.kind() == std::io::ErrorKind::UnexpectedEof
    ));
}

fn service(service_id: &str, uid: u32, gid: u32) -> ServicePrincipal {
    ServicePrincipal::new(service_id, uid, gid).unwrap()
}

#[test]
fn service_allowlist_requires_exact_uid_gid_and_systemd_unit() {
    let allowlist = ServiceAllowlist::new([service("service:runtime", 1001, 2001)]);
    let observed = PeerPrincipal {
        pid: 42,
        uid: 1001,
        gid: 2001,
    };
    assert_eq!(
        allowlist
            .admit(observed, "0::/system.slice/habitat-runtime.service\n")
            .unwrap()
            .service_id,
        "service:runtime"
    );
    assert!(matches!(
        allowlist.admit(observed, "0::/system.slice/habitat-effects.service\n"),
        Err(TransportError::PeerDenied(_))
    ));
    for wrong in [
        PeerPrincipal {
            uid: 1002,
            ..observed
        },
        PeerPrincipal {
            gid: 2002,
            ..observed
        },
    ] {
        assert!(matches!(
            allowlist.admit(wrong, "0::/system.slice/habitat-runtime.service\n"),
            Err(TransportError::PeerDenied(_))
        ));
    }
}

#[test]
fn service_allowlist_rejects_malformed_cgroup() {
    let allowlist = ServiceAllowlist::new([service("service:runtime", 1001, 2001)]);
    let missing = PeerPrincipal {
        pid: i32::MAX,
        uid: 1001,
        gid: 2001,
    };
    for malformed in ["", "not:cgroup", "x::/unit", "0::relative", "0:/cpu//unit"] {
        assert!(matches!(
            allowlist.admit(missing, malformed),
            Err(TransportError::InvalidCgroup)
        ));
    }
}

#[test]
fn accepted_stream_enforces_partial_frame_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("deadline.sock");
    let listener = AuthenticatedListener::bind(
        &path,
        SocketPermissions::new(0o600).unwrap(),
        PeerAllowlist::principals([PeerPrincipal::current_process()]),
        StreamTimeouts::new(Duration::from_millis(40), Duration::from_millis(40)).unwrap(),
    )
    .unwrap();
    let mut client = UnixStream::connect(&path).unwrap();
    let authenticated = listener.accept().unwrap();
    client.write_all(&16_u32.to_be_bytes()).unwrap();
    let mut transport =
        authenticated.into_transport::<Request, Response>(FrameConfig::new(64).unwrap());
    let started = std::time::Instant::now();
    let error = transport.receive_request().unwrap_err();
    assert!(matches!(error, TransportError::Io(ref io)
        if matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn pidfd_observation_rejects_a_peer_that_exited_before_identity_read() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pidfd.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let _stream = UnixStream::connect(&path).unwrap();
        unsafe { libc::_exit(0) };
    }
    let (stream, _) = listener.accept().unwrap();
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
    assert!(matches!(
        ObservedPeer::from_stream(&stream),
        Err(TransportError::PeerProcessChanged) | Err(TransportError::Io(_))
    ));
}
