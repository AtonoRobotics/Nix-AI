//! Authenticated, bounded, typed transport over Unix-domain sockets.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashSet,
    fmt,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    marker::PhantomData,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

pub const DEFAULT_MAX_PAYLOAD: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamTimeouts {
    read: Duration,
    write: Duration,
}

impl StreamTimeouts {
    pub fn new(read: Duration, write: Duration) -> Result<Self, TransportError> {
        if read.is_zero() || write.is_zero() {
            return Err(TransportError::InvalidConfiguration(
                "stream timeouts must be non-zero",
            ));
        }
        Ok(Self { read, write })
    }

    fn apply(self, stream: &UnixStream) -> io::Result<()> {
        stream.set_read_timeout(Some(self.read))?;
        stream.set_write_timeout(Some(self.write))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameConfig {
    max_payload: usize,
}

impl FrameConfig {
    pub fn new(max_payload: usize) -> Result<Self, TransportError> {
        if max_payload == 0 || max_payload > u32::MAX as usize {
            return Err(TransportError::InvalidConfiguration(
                "frame bound must be between 1 and u32::MAX",
            ));
        }
        Ok(Self { max_payload })
    }

    pub fn max_payload(self) -> usize {
        self.max_payload
    }
}

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    FrameTooLarge { length: usize, maximum: usize },
    InvalidUtf8(std::str::Utf8Error),
    InvalidJson(serde_json::Error),
    PeerDenied(PeerPrincipal),
    InvalidCgroup,
    PeerProcessChanged,
    CommandDenied(String),
    InvalidConfiguration(&'static str),
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Unix transport I/O: {error}"),
            Self::FrameTooLarge { length, maximum } => {
                write!(formatter, "frame length {length} exceeds maximum {maximum}")
            }
            Self::InvalidUtf8(error) => write!(formatter, "frame is not UTF-8: {error}"),
            Self::InvalidJson(error) => write!(formatter, "frame is not valid JSON: {error}"),
            Self::PeerDenied(peer) => write!(formatter, "peer {peer:?} is not allowlisted"),
            Self::InvalidCgroup => write!(formatter, "peer cgroup data is malformed"),
            Self::PeerProcessChanged => write!(
                formatter,
                "peer exited or changed identity during authentication"
            ),
            Self::CommandDenied(service) => {
                write!(formatter, "service {service} is not authorized for command")
            }
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid configuration: {message}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

impl TransportError {
    pub fn is_peer_rejection(&self) -> bool {
        matches!(
            self,
            Self::PeerDenied(_) | Self::InvalidCgroup | Self::PeerProcessChanged
        ) || matches!(self, Self::Io(error) if error.kind() == io::ErrorKind::NotFound)
    }

    pub fn is_connection_fault(&self) -> bool {
        matches!(
            self,
            Self::FrameTooLarge { .. } | Self::InvalidUtf8(_) | Self::InvalidJson(_)
        ) || matches!(self, Self::Io(error) if matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe))
    }
}

#[derive(Clone, Debug)]
pub struct ServiceCommandPolicy<Command: Eq + std::hash::Hash> {
    allowed: std::collections::HashMap<String, HashSet<Command>>,
}

impl<Command: Clone + Eq + std::hash::Hash> ServiceCommandPolicy<Command> {
    pub fn new(entries: impl IntoIterator<Item = (ServicePrincipal, Vec<Command>)>) -> Self {
        let mut allowed = std::collections::HashMap::new();
        for (service, commands) in entries {
            allowed.insert(service.service_id, commands.into_iter().collect());
        }
        Self { allowed }
    }

    pub fn authorize(
        &self,
        service: &ServicePrincipal,
        command: &Command,
    ) -> Result<(), TransportError> {
        if self
            .allowed
            .get(&service.service_id)
            .is_some_and(|commands| commands.contains(command))
        {
            Ok(())
        } else {
            Err(TransportError::CommandDenied(service.service_id.clone()))
        }
    }
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    config: FrameConfig,
) -> Result<(), TransportError> {
    if payload.len() > config.max_payload {
        return Err(TransportError::FrameTooLarge {
            length: payload.len(),
            maximum: config.max_payload,
        });
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R, config: FrameConfig) -> Result<Vec<u8>, TransportError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > config.max_payload {
        return Err(TransportError::FrameTooLarge {
            length,
            maximum: config.max_payload,
        });
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

pub struct JsonTransport<S, Request, Response> {
    stream: S,
    frames: FrameConfig,
    message_types: PhantomData<fn(Request) -> Response>,
}

pub fn connect<Request, Response>(
    path: impl AsRef<Path>,
    frames: FrameConfig,
) -> Result<JsonTransport<UnixStream, Request, Response>, TransportError> {
    Ok(JsonTransport::new(UnixStream::connect(path)?, frames))
}

pub fn connect_with_timeouts<Request, Response>(
    path: impl AsRef<Path>,
    frames: FrameConfig,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<JsonTransport<UnixStream, Request, Response>, TransportError> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(write_timeout))?;
    Ok(JsonTransport::new(stream, frames))
}

impl<S, Request, Response> JsonTransport<S, Request, Response> {
    pub fn new(stream: S, frames: FrameConfig) -> Self {
        Self {
            stream,
            frames,
            message_types: PhantomData,
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write, Request, Response> JsonTransport<S, Request, Response> {
    pub fn send_request(&mut self, request: &Request) -> Result<(), TransportError>
    where
        Request: Serialize,
    {
        self.write_json(request)
    }

    pub fn receive_request(&mut self) -> Result<Request, TransportError>
    where
        Request: DeserializeOwned,
    {
        self.read_json()
    }

    pub fn send_response(&mut self, response: &Response) -> Result<(), TransportError>
    where
        Response: Serialize,
    {
        self.write_json(response)
    }

    pub fn receive_response(&mut self) -> Result<Response, TransportError>
    where
        Response: DeserializeOwned,
    {
        self.read_json()
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> Result<(), TransportError> {
        let payload = serde_json::to_vec(value).map_err(TransportError::InvalidJson)?;
        write_frame(&mut self.stream, &payload, self.frames)
    }

    fn read_json<T: DeserializeOwned>(&mut self) -> Result<T, TransportError> {
        let payload = read_frame(&mut self.stream, self.frames)?;
        let text = std::str::from_utf8(&payload).map_err(TransportError::InvalidUtf8)?;
        serde_json::from_str(text).map_err(TransportError::InvalidJson)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PeerPrincipal {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl PeerPrincipal {
    pub fn current_process() -> Self {
        Self {
            pid: std::process::id() as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    pub fn from_stream(stream: &UnixStream) -> io::Result<Self> {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SO_PEERCRED returned an unexpected credential size",
            ));
        }
        let credentials = unsafe { credentials.assume_init() };
        Ok(Self {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerAllowlist {
    AnyAuthenticated,
    Principals(HashSet<PeerPrincipal>),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ServicePrincipal {
    pub service_id: String,
    pub uid: u32,
    pub gid: u32,
}

impl ServicePrincipal {
    pub fn new(service_id: impl Into<String>, uid: u32, gid: u32) -> Result<Self, TransportError> {
        let service_id = service_id.into();
        let name =
            service_id
                .strip_prefix("service:")
                .ok_or(TransportError::InvalidConfiguration(
                    "service ID must start with service:",
                ))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(TransportError::InvalidConfiguration(
                "service ID contains invalid unit-name characters",
            ));
        }
        Ok(Self {
            service_id,
            uid,
            gid,
        })
    }

    pub fn systemd_unit(&self) -> String {
        format!(
            "habitat-{}.service",
            self.service_id.trim_start_matches("service:")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAllowlist {
    services: Vec<ServicePrincipal>,
}

impl ServiceAllowlist {
    pub fn new(services: impl IntoIterator<Item = ServicePrincipal>) -> Self {
        Self {
            services: services.into_iter().collect(),
        }
    }

    pub fn admit(
        &self,
        observed: PeerPrincipal,
        cgroup: &str,
    ) -> Result<ServicePrincipal, TransportError> {
        let units = parse_cgroup_units(cgroup)?;
        self.services
            .iter()
            .find(|service| {
                service.uid == observed.uid
                    && service.gid == observed.gid
                    && units.contains(&service.systemd_unit())
            })
            .cloned()
            .ok_or(TransportError::PeerDenied(observed))
    }

    pub fn admit_stream(&self, stream: &UnixStream) -> Result<ServicePrincipal, TransportError> {
        let observed = ObservedPeer::from_stream(stream)?;
        self.admit(observed.principal, &observed.cgroup)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedPeer {
    pub principal: PeerPrincipal,
    pub start_time_ticks: u64,
    pub cgroup: String,
}

impl ObservedPeer {
    pub fn from_stream(stream: &UnixStream) -> Result<Self, TransportError> {
        const SO_PEERPIDFD: libc::c_int = 77;
        let principal = PeerPrincipal::from_stream(stream)?;
        let mut raw_pidfd = -1_i32;
        let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut raw_pidfd as *mut i32).cast(),
                &mut length,
            )
        };
        if result != 0 || raw_pidfd < 0 || length as usize != std::mem::size_of::<i32>() {
            return Err(io::Error::last_os_error().into());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
        let first = process_start_time(principal.pid)?;
        ensure_pidfd_alive(&pidfd)?;
        let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", principal.pid))?;
        let second = process_start_time(principal.pid)?;
        ensure_pidfd_alive(&pidfd)?;
        if first != second {
            return Err(TransportError::PeerProcessChanged);
        }
        Ok(Self {
            principal,
            start_time_ticks: first,
            cgroup,
        })
    }
}

fn process_start_time(pid: i32) -> Result<u64, TransportError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat.rfind(')').ok_or(TransportError::PeerProcessChanged)?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    fields
        .get(19)
        .ok_or(TransportError::PeerProcessChanged)?
        .parse()
        .map_err(|_| TransportError::PeerProcessChanged)
}

fn ensure_pidfd_alive(pidfd: &OwnedFd) -> Result<(), TransportError> {
    let mut descriptor = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if result != 0 || descriptor.revents != 0 {
        return Err(TransportError::PeerProcessChanged);
    }
    Ok(())
}

fn parse_cgroup_units(cgroup: &str) -> Result<HashSet<String>, TransportError> {
    let mut units = HashSet::new();
    if cgroup.is_empty() {
        return Err(TransportError::InvalidCgroup);
    }
    for line in cgroup.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().ok_or(TransportError::InvalidCgroup)?;
        let controllers = fields.next().ok_or(TransportError::InvalidCgroup)?;
        let path = fields.next().ok_or(TransportError::InvalidCgroup)?;
        if hierarchy.parse::<u32>().is_err()
            || controllers.contains('/')
            || !path.starts_with('/')
            || path.contains("//")
        {
            return Err(TransportError::InvalidCgroup);
        }
        if let Some(unit) = path.rsplit('/').find(|part| !part.is_empty()) {
            units.insert(unit.to_owned());
        }
    }
    Ok(units)
}

impl PeerAllowlist {
    pub fn any_authenticated() -> Self {
        Self::AnyAuthenticated
    }

    pub fn principals(principals: impl IntoIterator<Item = PeerPrincipal>) -> Self {
        Self::Principals(principals.into_iter().collect())
    }

    pub fn denies_all() -> Self {
        Self::Principals(HashSet::new())
    }

    pub fn permits(&self, principal: PeerPrincipal) -> bool {
        match self {
            Self::AnyAuthenticated => true,
            Self::Principals(principals) => principals.contains(&principal),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketPermissions(u32);

impl SocketPermissions {
    pub fn new(mode: u32) -> Result<Self, TransportError> {
        if mode & !0o777 != 0 {
            return Err(TransportError::InvalidConfiguration(
                "invalid permission bits",
            ));
        }
        if mode & 0o007 != 0 {
            return Err(TransportError::InvalidConfiguration(
                "socket permissions may not grant access to other users",
            ));
        }
        Ok(Self(mode))
    }

    pub fn mode(self) -> u32 {
        self.0
    }
}

pub struct AuthenticatedListener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    allowlist: PeerAllowlist,
    timeouts: StreamTimeouts,
}

impl AuthenticatedListener {
    pub fn bind(
        path: impl AsRef<Path>,
        permissions: SocketPermissions,
        allowlist: PeerAllowlist,
        timeouts: StreamTimeouts,
    ) -> Result<Self, TransportError> {
        let (listener, path, identity) = bind_socket(path.as_ref(), permissions)?;
        Ok(Self {
            listener,
            path,
            identity,
            allowlist,
            timeouts,
        })
    }

    pub fn accept(&self) -> Result<AuthenticatedStream, TransportError> {
        let (stream, _) = self.listener.accept()?;
        self.timeouts.apply(&stream)?;
        let principal = PeerPrincipal::from_stream(&stream)?;
        if !self.allowlist.permits(principal) {
            return Err(TransportError::PeerDenied(principal));
        }
        Ok(AuthenticatedStream { stream, principal })
    }

    pub fn local_path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AuthenticatedListener {
    fn drop(&mut self) {
        remove_owned_socket(&self.path, self.identity);
    }
}

pub struct ServiceListener {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    allowlist: ServiceAllowlist,
    timeouts: StreamTimeouts,
}

impl ServiceListener {
    pub fn bind(
        path: impl AsRef<Path>,
        permissions: SocketPermissions,
        allowlist: ServiceAllowlist,
        timeouts: StreamTimeouts,
    ) -> Result<Self, TransportError> {
        let (listener, path, identity) = bind_socket(path.as_ref(), permissions)?;
        Ok(Self {
            listener,
            path,
            identity,
            allowlist,
            timeouts,
        })
    }

    pub fn accept(&self) -> Result<AuthenticatedServiceStream, TransportError> {
        let (stream, _) = self.listener.accept()?;
        self.timeouts.apply(&stream)?;
        let observed = ObservedPeer::from_stream(&stream)?;
        let peer = observed.principal;
        let service = self.allowlist.admit(peer, &observed.cgroup)?;
        Ok(AuthenticatedServiceStream {
            stream,
            peer,
            service,
        })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }
}

impl Drop for ServiceListener {
    fn drop(&mut self) {
        remove_owned_socket(&self.path, self.identity);
    }
}

pub struct AuthenticatedServiceStream {
    stream: UnixStream,
    peer: PeerPrincipal,
    service: ServicePrincipal,
}

impl AuthenticatedServiceStream {
    pub fn peer_principal(&self) -> PeerPrincipal {
        self.peer
    }

    pub fn service_principal(&self) -> &ServicePrincipal {
        &self.service
    }

    pub fn into_transport<Request, Response>(
        self,
        frames: FrameConfig,
    ) -> JsonTransport<UnixStream, Request, Response> {
        JsonTransport::new(self.stream, frames)
    }
}

pub struct AuthenticatedStream {
    stream: UnixStream,
    principal: PeerPrincipal,
}

impl AuthenticatedStream {
    pub fn principal(&self) -> PeerPrincipal {
        self.principal
    }

    pub fn into_transport<Request, Response>(
        self,
        frames: FrameConfig,
    ) -> JsonTransport<UnixStream, Request, Response> {
        JsonTransport::new(self.stream, frames)
    }
}

fn bind_socket(
    path: &Path,
    permissions: SocketPermissions,
) -> Result<(UnixListener, PathBuf, (u64, u64)), TransportError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    remove_stale_socket(path)?;
    let listener = UnixListener::bind(path)?;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(permissions.mode())) {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    let metadata = fs::symlink_metadata(path)?;
    Ok((listener, path.to_owned(), (metadata.dev(), metadata.ino())))
}

fn remove_owned_socket(path: &Path, identity: (u64, u64)) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == identity {
            let _ = fs::remove_file(path);
        }
    }
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let initial = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !initial.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket path exists and is not a socket",
        ));
    }
    match socket_is_live(path, Duration::from_millis(250)) {
        Ok(true) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "socket already has a live listener",
        )),
        Ok(false) => {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || (current.dev(), current.ino()) != (initial.dev(), initial.ino())
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "socket path changed during stale-socket check",
                ));
            }
            fs::remove_file(path)
        }
        Err(error) => Err(error),
    }
}

fn socket_is_live(path: &Path, timeout: Duration) -> io::Result<bool> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket path is too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    let connected = unsafe {
        libc::connect(
            descriptor.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            length,
        )
    };
    if connected == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
    ) {
        return Ok(false);
    }
    if error.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(error);
    }
    let timeout_ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "socket liveness probe timed out",
        ));
    }
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut socket_error: libc::c_int = 0;
    let mut socket_error_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut socket_error).cast(),
            &raw mut socket_error_len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    match socket_error {
        0 => Ok(true),
        libc::ECONNREFUSED | libc::ENOENT => Ok(false),
        code => Err(io::Error::from_raw_os_error(code)),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Readiness {
    Recovering { pid: u32 },
    Operational { pid: u32 },
}

pub fn write_readiness<W: Write>(
    writer: &mut W,
    readiness: Readiness,
    frames: FrameConfig,
) -> Result<(), TransportError> {
    let payload = serde_json::to_vec(&readiness).map_err(TransportError::InvalidJson)?;
    write_frame(writer, &payload, frames)
}

pub fn read_readiness<R: Read>(
    reader: &mut R,
    frames: FrameConfig,
) -> Result<Readiness, TransportError> {
    let payload = read_frame(reader, frames)?;
    let text = std::str::from_utf8(&payload).map_err(TransportError::InvalidUtf8)?;
    serde_json::from_str(text).map_err(TransportError::InvalidJson)
}

pub fn publish_readiness(
    path: impl AsRef<Path>,
    readiness: Readiness,
    frames: FrameConfig,
) -> Result<(), TransportError> {
    let path = path.as_ref();
    let parent = path.parent().ok_or(TransportError::InvalidConfiguration(
        "readiness path must have a parent",
    ))?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .ok_or(TransportError::InvalidConfiguration(
            "readiness path must have a file name",
        ))?;
    let temporary = parent.join(format!(
        ".{}.{}.new",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> Result<(), TransportError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        write_readiness(&mut file, readiness, frames)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
