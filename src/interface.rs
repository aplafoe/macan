use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    io,
    process::Command,
    ptr::NonNull,
};

use anyhow::{Context, Result, bail, ensure};

use crate::frame::Frame;

pub const ETHERTYPE: u16 = 0x88b5;
const MAGIC: [u8; 4] = *b"MCAN";
const VERSION: u8 = 1;
const FRAME_OFFSET: usize = 22;

unsafe extern "C" {
    fn if_nametoindex(name: *const c_char) -> c_uint;
    fn macan_interface_up(name: *const c_char) -> c_int;
    fn macan_mac_address(name: *const c_char, address: *mut u8) -> c_int;
    fn macan_capture_open(name: *const c_char, filter: *const c_char, error: *mut c_char, size: usize) -> *mut c_void;
    fn macan_capture_next(capture: *mut c_void, packet: *mut u8, size: usize, time: *mut i64) -> c_int;
    fn pcap_geterr(capture: *mut c_void) -> *const c_char;
    fn pcap_inject(capture: *mut c_void, packet: *const c_void, size: usize) -> c_int;
    fn pcap_close(capture: *mut c_void);
}

pub fn interface_name(name: &str) -> Result<String> {
    let valid = name
        .strip_prefix("feth")
        .is_some_and(|unit| !unit.is_empty() && (unit.len() == 1 || !unit.starts_with('0')) && unit.bytes().all(|b| b.is_ascii_digit()) && unit.parse::<u16>().is_ok());
    ensure!(valid, "expected a macan interface name such as feth0");
    Ok(name.into())
}

fn ifconfig(args: &[&str]) -> Result<String> {
    let result = Command::new("/sbin/ifconfig").args(args).output().context("run /sbin/ifconfig")?;
    ensure!(result.status.success(), "ifconfig {}: {}", args.join(" "), String::from_utf8_lossy(&result.stderr).trim());
    Ok(String::from_utf8_lossy(&result.stdout).trim().to_owned())
}

struct Port {
    name: CString,
    index: c_uint,
}

impl Port {
    fn create(name: Option<&str>) -> Result<Self> {
        let name = match name {
            Some(name) => {
                ifconfig(&[name, "create"])?;
                name.to_owned()
            }
            None => interface_name(&ifconfig(&["feth", "create"])?)?,
        };
        let name = CString::new(name)?;
        let index = unsafe { if_nametoindex(name.as_ptr()) };
        ensure!(index != 0, "created interface disappeared");
        Ok(Self { name, index })
    }

    fn name(&self) -> &str {
        self.name.to_str().expect("interface names are ASCII")
    }

    fn exists(&self) -> bool {
        unsafe { if_nametoindex(self.name.as_ptr()) == self.index }
    }

    fn is_up(&self) -> Result<bool> {
        if !self.exists() {
            return Ok(false);
        }
        match unsafe { macan_interface_up(self.name.as_ptr()) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(io::Error::last_os_error()).with_context(|| format!("read flags on {}", self.name())),
        }
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if self.exists()
            && let Err(error) = ifconfig(&[self.name(), "destroy"])
        {
            eprintln!("{error:#}");
        }
    }
}

pub struct Ports {
    public: Port,
    peer: Port,
}

impl Ports {
    pub fn create(name: Option<&str>) -> Result<Self> {
        let public = Port::create(name)?;
        let peer = Port::create(None)?;
        ifconfig(&[public.name(), "peer", peer.name()])?;
        for port in [public.name(), peer.name()] {
            ifconfig(&[port, "inet6", "ifdisabled"])?;
            ifconfig(&[port, "-arp", "up"])?;
        }
        Ok(Self { public, peer })
    }

    pub fn public(&self) -> &str {
        self.public.name()
    }

    pub fn peer(&self) -> &str {
        self.peer.name()
    }

    pub fn is_up(&self) -> Result<bool> {
        Ok(self.public.is_up()? && self.peer.is_up()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Rx = 0,
    Tx = 1,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Rx => "RX",
            Self::Tx => "TX",
        }
    }
}

pub struct Event {
    pub time: [i64; 2],
    pub direction: Direction,
    pub frame: Frame,
}

fn encode(frame: Frame, direction: Direction, source: [u8; 6]) -> [u8; 60] {
    let mut packet = [0; 60];
    packet[..6].fill(0xff);
    packet[6..12].copy_from_slice(&source);
    packet[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
    packet[14..18].copy_from_slice(&MAGIC);
    packet[18] = VERSION;
    packet[19] = direction as u8;
    packet[FRAME_OFFSET..FRAME_OFFSET + 16].copy_from_slice(&frame.socketcan());
    packet
}

fn decode(packet: &[u8], time: [i64; 2]) -> Option<Event> {
    let header = packet.first_chunk::<FRAME_OFFSET>()?;
    if header[12..14] != ETHERTYPE.to_be_bytes() || header[14..18] != MAGIC || header[18] != VERSION || header[20..22] != [0, 0] {
        return None;
    }
    let direction = match header[19] {
        0 => Direction::Rx,
        1 => Direction::Tx,
        _ => return None,
    };
    let frame = Frame::from_socketcan(&packet[FRAME_OFFSET..])?;
    Some(Event { time, direction, frame })
}

pub struct Link {
    capture: NonNull<c_void>,
    address: [u8; 6],
    name: String,
}

impl Link {
    pub fn open(name: &str, direction: Option<Direction>) -> Result<Self> {
        let device = CString::new(name)?;
        let mut address = [0; 6];
        ensure!(unsafe { macan_mac_address(device.as_ptr(), address.as_mut_ptr()) } == 0, "interface {name} has no Ethernet address");

        let magic = u32::from_be_bytes(MAGIC);
        let mut filter = format!("ether proto {ETHERTYPE:#x} and ether[14:4] = {magic:#x} and ether[18] = {VERSION}");
        if let Some(direction) = direction {
            filter.push_str(&format!(" and ether[19] = {}", direction as u8));
        }
        let filter = CString::new(filter)?;
        let mut error = [0; 256];
        let capture = unsafe { macan_capture_open(device.as_ptr(), filter.as_ptr(), error.as_mut_ptr(), error.len()) };
        let capture = NonNull::new(capture).with_context(|| {
            let error = unsafe { CStr::from_ptr(error.as_ptr()) };
            format!("open BPF on {name}: {}", error.to_string_lossy())
        })?;
        Ok(Self { capture, address, name: name.into() })
    }

    pub fn next(&self) -> Result<Option<Event>> {
        let mut packet = [0; 96];
        let mut time = [0; 2];
        let count = unsafe { macan_capture_next(self.capture.as_ptr(), packet.as_mut_ptr(), packet.len(), time.as_mut_ptr()) };
        match count {
            0 => Ok(None),
            -2 => bail!("capture on {} ended", self.name),
            n if n < 0 => bail!("capture on {}: {}", self.name, self.error()),
            n => Ok(decode(&packet[..n as usize], time)),
        }
    }

    pub fn inject(&self, frame: Frame, direction: Direction) -> Result<()> {
        let packet = encode(frame, direction, self.address);
        let count = unsafe { pcap_inject(self.capture.as_ptr(), packet.as_ptr().cast(), packet.len()) };
        ensure!(count >= 0, "inject on {}: {}", self.name, self.error());
        ensure!(count as usize == packet.len(), "short Ethernet write on {} ({count}/{} bytes)", self.name, packet.len());
        Ok(())
    }

    fn error(&self) -> std::borrow::Cow<'_, str> {
        unsafe { CStr::from_ptr(pcap_geterr(self.capture.as_ptr())) }.to_string_lossy()
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        unsafe { pcap_close(self.capture.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_preserves_direction_and_frame() {
        let frame = "00123456#352001".parse().unwrap();
        let mut packet = encode(frame, Direction::Tx, [1; 6]);
        let parsed = decode(&packet, [1, 2]).unwrap();
        assert_eq!(parsed.frame, frame);
        assert_eq!(parsed.direction, Direction::Tx);
        assert_eq!(parsed.time, [1, 2]);
        assert!(decode(&packet[..37], [0; 2]).is_none());
        packet[18] = 2;
        assert!(decode(&packet, [0; 2]).is_none());
    }
}
