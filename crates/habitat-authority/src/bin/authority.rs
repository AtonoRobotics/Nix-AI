use habitat_authority::{evaluate_runtime_request, RuntimeAuthorityRequest, RuntimeGrant};
use std::{
    env, fs,
    fs::{OpenOptions, Permissions},
    io::{self, BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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

fn replace_socket(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        if !path.metadata()?.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path is not a socket",
            ));
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let socket = PathBuf::from(args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: habitat-authority SOCKET GRANTS DECISIONS ALLOWED_UID...",
        )
    })?);
    let grants_path = args
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing grants"))?;
    let decisions_path = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing decisions"))?,
    );
    let allowed_uids = args
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid allowed uid"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    if allowed_uids.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing allowed uid",
        ));
    }
    let grants: Vec<RuntimeGrant> = serde_json::from_slice(&fs::read(grants_path)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let listener = replace_socket(&socket)?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        let peer_allowed = allowed_uids.contains(&peer_uid(&stream)?);
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        if peer_allowed && line.trim() == "STATUS" {
            stream.write_all(
                b"READY migrations=1 leases_fenced=1 effects_classified=1 wakes_redelivered=0\n",
            )?;
            continue;
        }
        let decision = if !peer_allowed {
            None
        } else {
            serde_json::from_str::<RuntimeAuthorityRequest>(&line)
                .ok()
                .map(|request| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    evaluate_runtime_request(&grants, &request, now)
                })
        };
        match decision {
            Some(decision) => {
                let encoded = serde_json::to_vec(&decision).map_err(io::Error::other)?;
                let mut ledger = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&decisions_path)?;
                ledger.write_all(&encoded)?;
                ledger.write_all(b"\n")?;
                ledger.sync_data()?;
                stream.write_all(&encoded)?;
                stream.write_all(b"\n")?;
            }
            None => stream.write_all(
                b"{\"schema_version\":\"2.0\",\"allowed\":false,\"code\":\"UNAUTHORIZED\"}\n",
            )?,
        }
    }
    Ok(())
}
