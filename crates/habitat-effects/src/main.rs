use habitat_authority::RuntimeAuthorityDecision;
use habitat_effects::{admit_runtime_effect, RuntimeEffectRequest};
use std::{
    env, fs,
    io::{self, BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
};

fn query(socket: &Path, request: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    Ok(response.trim().into())
}

fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credential = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credential.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { credential.assume_init() }.uid)
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let socket = PathBuf::from(args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-effects SOCKET STATE_SOCKET AUTHORITY_SOCKET ALLOWED_UID",
        )
    })?);
    let state_socket = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing state socket"))?,
    );
    let authority_socket =
        PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing authority socket")
        })?);
    let allowed_uid: u32 = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing allowed uid"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid allowed uid"))?;
    if args.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unexpected argument",
        ));
    }
    if socket.exists() {
        if !socket.metadata()?.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path is not a socket",
            ));
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        let peer_allowed = peer_uid(&stream)? == allowed_uid;
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        if peer_allowed && line.trim() == "STATUS" {
            stream.write_all(
                b"READY migrations=1 leases_fenced=1 effects_classified=1 wakes_redelivered=0\n",
            )?;
            continue;
        }
        let response = if !peer_allowed {
            "{\"schema_version\":\"2.0\",\"state\":\"REJECTED\",\"code\":\"UNAUTHORIZED_PEER\"}"
                .into()
        } else {
            match serde_json::from_str::<RuntimeEffectRequest>(&line) {
                Ok(request) => {
                    let authority = serde_json::to_string(&request.authority_request)
                        .map_err(io::Error::other)
                        .and_then(|wire| query(&authority_socket, &wire))
                        .ok()
                        .and_then(|wire| {
                            serde_json::from_str::<RuntimeAuthorityDecision>(&wire).ok()
                        });
                    let mut admission = match authority {
                        Some(decision) => admit_runtime_effect(&request, &decision),
                        None => habitat_effects::RuntimeEffectAdmission {
                            schema_version: "2.0".into(),
                            command_id: request.command_id.clone(),
                            objective_id: request.objective_id.clone(),
                            state: "REJECTED".into(),
                            code: "AUTHORITY_UNAVAILABLE".into(),
                        },
                    };
                    if admission.state == "RESERVED" {
                        match query(
                            &state_socket,
                            &format!("RECORD_EFFECT {}", request.objective_id),
                        ) {
                            Ok(value) if value == "COMMITTED" => {
                                admission.state = "COMMITTED".into();
                                admission.code = "COMMITTED".into();
                            }
                            _ => {
                                admission.state = "OUTCOME_UNKNOWN".into();
                                admission.code = "RECONCILIATION_REQUIRED".into();
                            }
                        }
                    }
                    serde_json::to_string(&admission).map_err(io::Error::other)?
                }
                Err(_) => {
                    "{\"schema_version\":\"2.0\",\"state\":\"REJECTED\",\"code\":\"INVALID\"}"
                        .into()
                }
            }
        };
        writeln!(stream, "{response}")?;
    }
    Ok(())
}
