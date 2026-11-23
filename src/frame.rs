use std::{fmt, str::FromStr};

use anyhow::{Context, Result, ensure};

const EXTENDED: u32 = 1 << 31;
const REMOTE: u32 = 1 << 30;
const ERROR: u32 = 1 << 29;
const EXTENDED_MASK: u32 = 0x1fff_ffff;
const STANDARD_MASK: u32 = 0x7ff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub id: u32,
    pub len: u8,
    pub data: [u8; 8],
}

impl Frame {
    pub fn from_bus(id: u32, len: u8, data: &[u8]) -> Option<Self> {
        let remote = id & REMOTE != 0;
        let error = id & ERROR != 0;
        let invalid_id = id & EXTENDED == 0 && id & EXTENDED_MASK > STANDARD_MASK;
        if len > 8 || (error && id & (EXTENDED | REMOTE) != 0) || (!error && invalid_id) {
            return None;
        }

        let mut payload = [0; 8];
        if !remote {
            let len = usize::from(len);
            payload[..len].copy_from_slice(data.get(..len)?);
        }
        Some(Self { id, len, data: payload })
    }

    pub fn is_error(self) -> bool {
        self.id & ERROR != 0
    }

    pub fn socketcan(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&self.id.to_be_bytes());
        bytes[4] = self.len;
        bytes[8..].copy_from_slice(&self.data);
        bytes
    }

    pub fn from_socketcan(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.first_chunk::<16>()?;
        Self::from_bus(u32::from_be_bytes(bytes[..4].try_into().ok()?), bytes[4], &bytes[8..])
    }
}

impl FromStr for Frame {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (id_hex, payload) = value.split_once('#').context("expected ID#DATA")?;
        ensure!(matches!(id_hex.len(), 3 | 8), "use 3 hex digits for standard IDs and 8 for extended IDs");
        ensure!(id_hex.bytes().all(|byte| byte.is_ascii_hexdigit()), "invalid CAN ID");

        let mut id = u32::from_str_radix(id_hex, 16)?;
        if id_hex.len() == 8 {
            ensure!(id <= EXTENDED_MASK, "extended CAN ID exceeds 29 bits");
            id |= EXTENDED;
        } else {
            ensure!(id <= STANDARD_MASK, "standard CAN ID exceeds 11 bits");
        }

        if let Some(dlc) = payload.strip_prefix(['R', 'r']) {
            let len = match dlc.as_bytes() {
                [] => 0,
                [digit @ b'0'..=b'8'] => digit - b'0',
                _ => anyhow::bail!("RTR length must be between 0 and 8"),
            };
            return Ok(Self { id: id | REMOTE, len, data: [0; 8] });
        }

        ensure!(payload.len() <= 16 && payload.len() % 2 == 0, "expected up to 8 complete hex bytes");
        ensure!(payload.bytes().all(|byte| byte.is_ascii_hexdigit()), "invalid CAN data");

        let mut data = [0; 8];
        for (index, byte) in data.iter_mut().take(payload.len() / 2).enumerate() {
            *byte = u8::from_str_radix(&payload[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self {
            id,
            len: (payload.len() / 2) as u8,
            data,
        })
    }
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id = self.id & EXTENDED_MASK;
        if self.is_error() {
            write!(f, "ERROR {id:08X}#")?;
        } else if self.id & EXTENDED != 0 {
            write!(f, "{id:08X}#")?;
        } else {
            write!(f, "{id:03X}#")?;
        }

        if self.id & REMOTE != 0 {
            return write!(f, "R{}", self.len);
        }
        for byte in &self.data[..usize::from(self.len)] {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socketcan_frames_preserve_id_dlc_and_flags() {
        for value in ["000#", "123#AABB", "1ABCDEFF#0011223344556677", "321#R8", "00000123#R0"] {
            let frame: Frame = value.parse().unwrap();
            assert_eq!(Frame::from_socketcan(&frame.socketcan()), Some(frame));
            assert_eq!(frame.to_string(), value);
        }
        let frame: Frame = "00000123#R7".parse().unwrap();
        assert_eq!(&frame.socketcan()[..5], &[0xc0, 0, 1, 0x23, 7]);
    }

    #[test]
    fn invalid_frames_cannot_be_sent() {
        for value in ["800#", "+01#", "20000000#", "123#f", "123#é", "123#R9", "123##0"] {
            assert!(value.parse::<Frame>().is_err(), "{value}");
        }
    }
}
