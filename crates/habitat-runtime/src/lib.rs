use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub const COMPONENTS: [&str; 6] = [
    "state",
    "scheduler",
    "authority",
    "effects",
    "abi",
    "runtime",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    pub migrations: bool,
    pub leases_fenced: bool,
    pub effects_classified: bool,
    pub wakes_redelivered: usize,
}

impl RecoveryReport {
    pub fn operational(&self) -> bool {
        self.migrations && self.leases_fenced && self.effects_classified
    }

    fn wire(&self) -> String {
        format!(
            "READY migrations={} leases_fenced={} effects_classified={} wakes_redelivered={}",
            self.migrations as u8,
            self.leases_fenced as u8,
            self.effects_classified as u8,
            self.wakes_redelivered
        )
    }
}

pub struct DurableState {
    root: PathBuf,
}

impl DurableState {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    fn append(&self, name: &str, record: &str) -> io::Result<()> {
        let path = self.root.join(name);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{}", record.replace('\n', " "))?;
        file.sync_data()
    }

    fn rewrite_lines(&self, name: &str, transform: impl Fn(&str) -> String) -> io::Result<usize> {
        let path = self.root.join(name);
        if !path.exists() {
            File::create(path)?.sync_all()?;
            return Ok(0);
        }
        let lines: Vec<String> = BufReader::new(File::open(&path)?)
            .lines()
            .collect::<Result<_, _>>()?;
        let transformed: Vec<String> = lines.iter().map(|line| transform(line)).collect();
        let changed = lines
            .iter()
            .zip(&transformed)
            .filter(|(a, b)| a != b)
            .count();
        let temporary = path.with_extension("next");
        {
            let mut output = File::create(&temporary)?;
            for line in transformed {
                writeln!(output, "{line}")?;
            }
            output.sync_all()?;
        }
        fs::rename(temporary, path)?;
        Ok(changed)
    }

    pub fn recover(&self) -> io::Result<RecoveryReport> {
        let schema = self.root.join("schema-version");
        fs::write(&schema, b"2\n")?;
        File::open(schema)?.sync_all()?;
        self.rewrite_lines("leases", |line| {
            if line.contains(" ACTIVE") {
                line.replace(" ACTIVE", " FENCED")
            } else {
                line.into()
            }
        })?;
        self.rewrite_lines("effects", |line| {
            if line.contains(" EXECUTING") {
                line.replace(" EXECUTING", " RECONCILE")
            } else {
                line.into()
            }
        })?;
        let redelivered = self.rewrite_lines("wakes", |line| {
            if line.contains(" COMMITTED") {
                line.replace(" COMMITTED", " REDELIVERED")
            } else {
                line.into()
            }
        })?;
        self.append(
            "events",
            &format!("{} RECOVERY_COMPLETE wakes={redelivered}", now()),
        )?;
        Ok(RecoveryReport {
            migrations: true,
            leases_fenced: true,
            effects_classified: true,
            wakes_redelivered: redelivered,
        })
    }

    pub fn schedule(&self, objective: &str) -> io::Result<()> {
        validate_id(objective)?;
        self.append("objectives", &format!("{} {objective} CLAIMED", now()))?;
        self.append("wakes", &format!("{} wake:{objective} COMMITTED", now()))
    }

    pub fn complete_next(&self) -> io::Result<bool> {
        let changed = self.rewrite_lines("wakes", |line| {
            if line.contains(" COMMITTED") || line.contains(" REDELIVERED") {
                line.replace(" COMMITTED", " ACKED")
                    .replace(" REDELIVERED", " ACKED")
            } else {
                line.into()
            }
        })?;
        if changed > 0 {
            self.append(
                "events",
                &format!("{} OBJECTIVE_COMPLETED count={changed}", now()),
            )?;
        }
        Ok(changed > 0)
    }

    pub fn read(&self, name: &str) -> io::Result<String> {
        fs::read_to_string(self.root.join(name))
    }
}

fn validate_id(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:/.".contains(&b))
    {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid identifier",
        ))
    } else {
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn query(socket: &Path, request: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.write_all(request.as_bytes())?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    Ok(response.trim().into())
}

pub fn serve_component(
    component: &str,
    socket: &Path,
    state: Arc<Mutex<DurableState>>,
    report: RecoveryReport,
) -> io::Result<()> {
    if !COMPONENTS.contains(&component) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown component",
        ));
    }
    if socket.exists() {
        fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o660))?;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        let peer = peer_principal(&stream)?;
        if peer.uid != unsafe { process_euid() } && peer.gid != unsafe { process_egid() } {
            writeln!(stream, "UNAUTHORIZED")?;
            continue;
        }
        let mut request = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut request)?;
        let request = request.trim();
        let response = if request == "STATUS" {
            report.wire()
        } else if component == "scheduler" && request.starts_with("SCHEDULE ") {
            state
                .lock()
                .unwrap()
                .schedule(&request[9..])
                .map(|_| "ACCEPTED".into())
                .unwrap_or_else(|_| "INVALID".into())
        } else if component == "scheduler" && request == "TICK" {
            if state.lock().unwrap().complete_next()? {
                "COMPLETED".into()
            } else {
                "IDLE".into()
            }
        } else {
            "INVALID".into()
        };
        writeln!(stream, "{response}")?;
    }
    Ok(())
}

#[repr(C)]
struct PeerPrincipal {
    pid: i32,
    uid: u32,
    gid: u32,
}

fn peer_principal(stream: &UnixStream) -> io::Result<PeerPrincipal> {
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let mut principal = PeerPrincipal {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<PeerPrincipal>() as u32;
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            &mut principal as *mut _ as *mut u8,
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<PeerPrincipal>() {
        Err(io::Error::last_os_error())
    } else {
        Ok(principal)
    }
}

extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
    fn getsockopt(fd: i32, level: i32, option: i32, value: *mut u8, length: *mut u32) -> i32;
}
unsafe fn process_euid() -> u32 {
    geteuid()
}
unsafe fn process_egid() -> u32 {
    getegid()
}

pub fn dependencies_operational(run_dir: &Path, component: &str) -> io::Result<bool> {
    let dependencies: &[&str] = match component {
        "state" => &[],
        "scheduler" => &["state"],
        "authority" | "effects" => &["state", "scheduler"],
        "abi" => &["state", "scheduler", "authority", "effects"],
        "runtime" => &["state", "scheduler", "authority", "effects", "abi"],
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown component",
            ))
        }
    };
    Ok(dependencies.iter().all(|name| {
        query(&run_dir.join(format!("{name}.sock")), "STATUS")
            .map(|s| s.starts_with("READY "))
            .unwrap_or(false)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    fn temporary() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "habitat-runtime-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn cold_boot_recovers_and_scheduler_continues() {
        let root = temporary();
        let store = DurableState::open(root.join("state")).unwrap();
        store
            .append("leases", "activation:1 worker:old ACTIVE")
            .unwrap();
        store.append("effects", "effect:1 EXECUTING").unwrap();
        store
            .append("wakes", "wake:lost objective:1 COMMITTED")
            .unwrap();
        let recovery = store.recover().unwrap();
        assert!(recovery.operational());
        assert_eq!(recovery.wakes_redelivered, 1);
        assert!(store.read("leases").unwrap().contains("FENCED"));
        assert!(store.read("effects").unwrap().contains("RECONCILE"));
        assert!(store.complete_next().unwrap());
        store.schedule("objective:2").unwrap();
        assert!(store.complete_next().unwrap());
        assert!(
            store
                .read("events")
                .unwrap()
                .matches("OBJECTIVE_COMPLETED")
                .count()
                >= 2
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protected_socket_reports_recovery_and_rejects_bad_commands() {
        let root = temporary();
        let socket = root.join("state.sock");
        let state = Arc::new(Mutex::new(DurableState::open(root.join("data")).unwrap()));
        let report = state.lock().unwrap().recover().unwrap();
        let thread_socket = socket.clone();
        thread::spawn(move || {
            let _ = serve_component("state", &thread_socket, state, report);
        });
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(query(&socket, "STATUS")
            .unwrap()
            .starts_with("READY migrations=1"));
        assert_eq!(query(&socket, "SCHEDULE no").unwrap(), "INVALID");
        fs::remove_file(socket).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
