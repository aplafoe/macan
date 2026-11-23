use std::{
    io::{self, BufRead, BufReader, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};

use crate::{
    frame::Frame,
    interface::{Direction, Event},
};

pub const DIRECTORY: &str = "/var/run/macan";
pub const SOCKET: &str = "/var/run/macan/can.sock";
pub const EVENT_SIZE: usize = 33;

pub fn peer_uid(socket: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

pub fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn encode_event(event: &Event) -> [u8; EVENT_SIZE] {
    let mut record = [0; EVENT_SIZE];
    record[..8].copy_from_slice(&event.time[0].to_le_bytes());
    record[8..16].copy_from_slice(&event.time[1].to_le_bytes());
    record[16] = event.direction as u8;
    record[17..].copy_from_slice(&event.frame.socketcan());
    record
}

fn decode_event(record: &[u8; EVENT_SIZE]) -> Result<Event> {
    let time = [i64::from_le_bytes(record[..8].try_into().unwrap()), i64::from_le_bytes(record[8..16].try_into().unwrap())];
    let direction = match record[16] {
        0 => Direction::Rx,
        1 => Direction::Tx,
        _ => bail!("invalid macan event direction"),
    };
    let frame = Frame::from_socketcan(&record[17..]).context("invalid macan event frame")?;
    Ok(Event { time, direction, frame })
}

fn request(command: &str) -> Result<(BufReader<UnixStream>, String)> {
    let mut stream = UnixStream::connect(SOCKET).context("connect to the macan system daemon")?;
    ensure!(peer_uid(&stream)? == 0, "macan socket did not identify as a root-owned daemon");
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    writeln!(stream, "{command}")?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).context("read daemon response")?;
    let response = response.trim_end();
    if response == "OK" {
        return Ok((reader, String::new()));
    }
    if let Some(message) = response.strip_prefix("OK ") {
        return Ok((reader, message.to_owned()));
    }
    if let Some(error) = response.strip_prefix("ERR ") {
        bail!("{error}");
    }
    bail!("daemon closed the connection or rejected access");
}

pub fn run(command: &str) -> Result<String> {
    request(command).map(|(_, response)| response)
}

pub struct Watch {
    stream: BufReader<UnixStream>,
    record: [u8; EVENT_SIZE],
    received: usize,
}

impl Watch {
    pub fn open(name: &str) -> Result<Self> {
        let (stream, _) = request(&format!("WATCH {name}"))?;
        stream.get_ref().set_read_timeout(Some(Duration::from_millis(50)))?;
        Ok(Self {
            stream,
            record: [0; EVENT_SIZE],
            received: 0,
        })
    }

    pub fn next(&mut self) -> Result<Option<Event>> {
        match self.stream.read(&mut self.record[self.received..]) {
            Ok(0) => bail!("macan daemon closed the capture"),
            Ok(count) => self.received += count,
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        if self.received < self.record.len() {
            return Ok(None);
        }
        self.received = 0;
        Ok(Some(decode_event(&self.record)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_protocol_preserves_extended_rtr() {
        let event = Event {
            time: [1_795_444_408, 680_865],
            direction: Direction::Rx,
            frame: "00000123#R4".parse().unwrap(),
        };
        let decoded = decode_event(&encode_event(&event)).unwrap();
        assert_eq!(decoded.time, event.time);
        assert_eq!(decoded.direction, event.direction);
        assert_eq!(decoded.frame, event.frame);
    }
}
