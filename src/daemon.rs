use std::{
    ffi::CString,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};

use crate::{
    bridge::{Bridge, BusOptions},
    frame::Frame,
    interface::{Direction, Link},
    ipc, shutdown,
};

const MAX_CLIENTS: usize = 64;
const MAX_REQUEST: usize = 128;
const MAX_OUTPUT: usize = 32 * 1024;
const RETRY: Duration = Duration::from_secs(1);

struct Server {
    listener: UnixListener,
    _lock: File,
}

impl Server {
    fn bind(owner: u32) -> Result<Self> {
        let mut directory = fs::DirBuilder::new();
        directory.mode(0o755);
        match directory.create(ipc::DIRECTORY) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error).context("create macan runtime directory"),
        }
        let metadata = fs::symlink_metadata(ipc::DIRECTORY)?;
        ensure!(metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0, "unsafe macan runtime directory");

        let lock = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(format!("{}/lock", ipc::DIRECTORY))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error()).context("lock macan daemon (is it already running?)");
        }
        match fs::remove_file(ipc::SOCKET) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error).context("remove stale macan socket"),
        }
        let listener = UnixListener::bind(ipc::SOCKET).context("bind macan socket")?;
        let server = Self { listener, _lock: lock };
        fs::set_permissions(ipc::SOCKET, Permissions::from_mode(0o600))?;
        let path = CString::new(ipc::SOCKET)?;
        if unsafe { libc::chown(path.as_ptr(), owner, 0) } != 0 {
            return Err(io::Error::last_os_error()).context("set macan socket owner");
        }
        server.listener.set_nonblocking(true)?;
        Ok(server)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = fs::remove_file(ipc::SOCKET);
    }
}

#[derive(Eq, PartialEq)]
enum Phase {
    Request,
    Capture,
    Reply,
}

struct Client {
    stream: UnixStream,
    uid: u32,
    phase: Phase,
    input: Vec<u8>,
    output: Vec<u8>,
    sent: usize,
    deadline: Instant,
}

impl Client {
    fn new(stream: UnixStream, uid: u32) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            uid,
            phase: Phase::Request,
            input: Vec::new(),
            output: Vec::new(),
            sent: 0,
            deadline: Instant::now() + Duration::from_secs(3),
        })
    }

    fn request(&mut self) -> Result<Option<String>> {
        if self.phase == Phase::Reply {
            return Ok(None);
        }
        let mut bytes = [0; MAX_REQUEST];
        let count = match self.stream.read(&mut bytes) {
            Ok(0) => return Err(anyhow!("client disconnected")),
            Ok(count) => count,
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        ensure!(self.phase == Phase::Request && self.input.len() + count <= MAX_REQUEST, "invalid client request");
        self.input.extend_from_slice(&bytes[..count]);
        if self.input.last() != Some(&b'\n') {
            return Ok(None);
        }
        self.input.pop();
        Ok(Some(String::from_utf8(std::mem::take(&mut self.input))?))
    }

    fn reply(&mut self, response: Result<String>, capture: bool) {
        let response = match response {
            Ok(message) if message.is_empty() => "OK\n".to_owned(),
            Ok(message) => format!("OK {message}\n"),
            Err(error) => format!("ERR {}\n", format!("{error:#}").replace(['\n', '\r'], " ")),
        };
        self.phase = if capture { Phase::Capture } else { Phase::Reply };
        self.output.extend_from_slice(response.as_bytes());
    }

    fn write(&mut self) -> bool {
        if self.output.len() > MAX_OUTPUT || (self.phase != Phase::Capture && Instant::now() >= self.deadline) {
            return false;
        }
        if self.sent < self.output.len() {
            match self.stream.write(&self.output[self.sent..]) {
                Ok(0) => return false,
                Ok(count) => self.sent += count,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => return true,
                Err(_) => return false,
            }
        }
        if self.sent == self.output.len() {
            self.output.clear();
            self.sent = 0;
        }
        self.phase != Phase::Reply || !self.output.is_empty()
    }
}

struct ActiveBus {
    capture: Link,
    bridge: Bridge,
}

impl ActiveBus {
    fn open(options: &BusOptions) -> Result<Self> {
        let bridge = Bridge::open(options)?;
        let capture = Link::open(bridge.interface(), None)?;
        Ok(Self { capture, bridge })
    }

    fn matches(&self, name: &str) -> bool {
        name == "can0" || name == self.bridge.interface()
    }

    fn tick(&mut self, clients: &mut [Client]) -> Result<bool> {
        if !self.bridge.tick()? {
            return Ok(false);
        }
        for _ in 0..64 {
            let Some(event) = self.capture.next()? else { break };
            let bytes = ipc::encode_event(&event);
            for client in clients.iter_mut().filter(|client| client.phase == Phase::Capture && client.output.len() <= MAX_OUTPUT) {
                client.output.extend_from_slice(&bytes);
            }
        }
        Ok(true)
    }
}

fn handle(request: &str, bus: Option<&ActiveBus>, state: &str) -> Result<String> {
    let mut words = request.split_ascii_whitespace();
    match (words.next(), words.next(), words.next(), words.next()) {
        (Some("STATUS"), None, None, None) => Ok(state.to_owned()),
        (Some("WATCH"), Some(name), None, None) => {
            ensure!(matches!(name, "any" | "can0") || bus.is_some_and(|bus| bus.matches(name)), "unknown CAN interface {name}");
            Ok(String::new())
        }
        (Some("SEND"), Some(name), Some(value), None) => {
            let bus = bus.context("CAN bus is offline")?;
            ensure!(bus.matches(name), "unknown CAN interface {name}");
            let frame: Frame = value.parse()?;
            bus.capture.inject(frame, Direction::Tx)?;
            Ok(String::new())
        }
        _ => Err(anyhow!("invalid macan command")),
    }
}

pub fn run(options: BusOptions, owner: u32) -> Result<()> {
    ensure!(ipc::uid() == 0, "the macan daemon requires root");
    shutdown::install()?;
    let server = Server::bind(owner)?;
    let mut clients = Vec::new();
    let mut bus = None;
    let mut state = "can0 waiting (looking for a gs_usb adapter)".to_owned();
    let mut next_attempt = Instant::now();
    let mut paused = false;

    while !shutdown::requested() {
        for _ in 0..8 {
            let (stream, _) = match server.listener.accept() {
                Ok(client) => client,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("accept macan client"),
            };
            if clients.len() < MAX_CLIENTS
                && let Ok(uid) = ipc::peer_uid(&stream)
                && (uid == 0 || uid == owner)
                && let Ok(client) = Client::new(stream, uid)
            {
                clients.push(client);
            }
        }

        clients.retain_mut(|client| match client.request() {
            Ok(Some(request)) => {
                if request == "PAUSE" && client.uid == 0 {
                    paused = true;
                    bus = None;
                    state = "can0 paused".into();
                    client.reply(Ok(String::new()), false);
                } else {
                    let response = handle(&request, bus.as_ref(), &state);
                    let capture = response.is_ok() && request.starts_with("WATCH ");
                    client.reply(response, capture);
                }
                true
            }
            Ok(None) => true,
            Err(_) => false,
        });

        if !paused && bus.is_none() && Instant::now() >= next_attempt {
            let status = match ActiveBus::open(&options) {
                Ok(active) => {
                    let description = format!("can0 up {}", active.bridge.description());
                    bus = Some(active);
                    description
                }
                Err(error) => format!("can0 waiting ({error:#})"),
            };
            if status != state {
                eprintln!("{status}");
                state = status;
            }
            next_attempt = Instant::now() + RETRY;
        }

        if let Some(active) = &mut bus {
            let reason = match active.tick(&mut clients) {
                Ok(true) => None,
                Ok(false) => Some("interface went down".to_owned()),
                Err(error) => Some(format!("{error:#}")),
            };
            if let Some(reason) = reason {
                bus = None;
                state = format!("can0 waiting ({reason})");
                eprintln!("{state}");
                next_attempt = Instant::now() + RETRY;
            }
        } else {
            thread::sleep(Duration::from_millis(20));
        }
        clients.retain_mut(Client::write);
    }
    Ok(())
}
