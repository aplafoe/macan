use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, ValueEnum};

use crate::{
    frame::Frame,
    interface::{Event, Link, interface_name},
    ipc, shutdown,
};

const EFF: u32 = 1 << 31;
const RTR: u32 = 1 << 30;
const ID_MASK: u32 = 0x1fff_ffff;

#[derive(Clone, Copy, ValueEnum)]
enum Timestamp {
    #[value(name = "a")]
    Absolute,
    #[value(name = "d")]
    Delta,
    #[value(name = "z")]
    Zero,
}

#[derive(Args)]
pub struct Options {
    /// CAN interface (can0, any, or the active feth name), followed by optional ID:MASK filters.
    interface: String,
    /// Stop after printing this many frames.
    #[arg(short = 'n', short_alias = 'c', long, value_parser = clap::value_parser!(u64).range(1..))]
    count: Option<u64>,
    /// Print compact candump log format.
    #[arg(short = 'L', long)]
    log_format: bool,
    /// Timestamp mode: absolute (a), delta (d), or relative to the first frame (z).
    #[arg(short = 't', value_enum)]
    timestamp: Option<Timestamp>,
    /// Show additional RX/TX direction in the expanded output.
    #[arg(short = 'x', long)]
    extra: bool,
    /// Stop after this many milliseconds without a matching frame.
    #[arg(short = 'T', value_parser = clap::value_parser!(u32).range(1..))]
    idle_timeout: Option<u32>,
    /// Stop after this many total seconds.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    timeout: Option<u32>,
    /// Create a new CAN_SOCKETCAN capture readable in Wireshark.
    #[arg(long)]
    pcap: Option<PathBuf>,
}

#[derive(Default)]
struct Filters {
    ids: Vec<(u32, u32, bool)>,
    errors: Option<u32>,
    join: bool,
}

impl Filters {
    fn parse<'a>(parts: impl Iterator<Item = &'a str>) -> Result<Self> {
        let mut filters = Self::default();
        for part in parts {
            if matches!(part, "j" | "J") {
                filters.join = true;
            } else if let Some(mask) = part.strip_prefix('#') {
                filters.errors = Some(u32::from_str_radix(mask, 16)? & ID_MASK);
            } else {
                let (id, invert, mask) = if let Some((id, mask)) = part.split_once(':') {
                    (id, false, mask)
                } else if let Some((id, mask)) = part.split_once('~') {
                    (id, true, mask)
                } else {
                    bail!("invalid CAN filter {part}: expected ID:MASK, ID~MASK or #ERROR_MASK");
                };
                let mut value = u32::from_str_radix(id, 16)?;
                if id.len() == 8 {
                    value |= EFF;
                }
                filters.ids.push((value, u32::from_str_radix(mask, 16)?, invert));
            }
        }
        Ok(filters)
    }

    fn matches(&self, frame: Frame, legacy: bool) -> bool {
        if frame.is_error() {
            return self.errors.map_or(legacy, |mask| mask & frame.id != 0);
        }
        let mut matches = self.ids.iter().map(|&(id, mask, invert)| ((frame.id & mask) == (id & mask)) != invert);
        self.ids.is_empty() || if self.join { matches.all(|matches| matches) } else { matches.any(|matches| matches) }
    }
}

fn open_pcap(path: Option<PathBuf>) -> Result<Option<io::BufWriter<File>>> {
    path.map(|path| {
        let mut file = File::create_new(&path).with_context(|| format!("create {}", path.display()))?;
        // Microsecond-resolution pcap, little-endian file headers, LINKTYPE_CAN_SOCKETCAN.
        file.write_all(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 227, 0, 0, 0])?;
        Ok(io::BufWriter::new(file))
    })
    .transpose()
}

fn write_pcap_record(file: &mut impl Write, event: &Event) -> Result<()> {
    let mut record = [0; 32];
    for (slot, value) in record[..16].chunks_exact_mut(4).zip([
        u32::try_from(event.time[0]).context("pcap seconds outside u32 range")?,
        u32::try_from(event.time[1]).context("invalid pcap microsecond timestamp")?,
        16,
        16,
    ]) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    record[16..].copy_from_slice(&event.frame.socketcan());
    file.write_all(&record)?;
    Ok(())
}

fn expanded(output: &mut impl Write, name: &str, event: &Event, extra: bool) -> io::Result<()> {
    let frame = event.frame;
    let id = frame.id & ID_MASK;
    write!(output, "  {name:>4}  ")?;
    if extra {
        write!(output, "{}  ", event.direction.label())?;
    }
    if frame.is_error() {
        return writeln!(output, "{frame}");
    }
    if frame.id & EFF != 0 {
        write!(output, "{id:08X}  [{}]", frame.len)?;
    } else {
        write!(output, "{id:03X}   [{}]", frame.len)?;
    }
    if frame.id & RTR != 0 {
        return writeln!(output, "  remote request");
    }
    for byte in &frame.data[..usize::from(frame.len)] {
        write!(output, " {byte:02X}")?;
    }
    writeln!(output)
}

pub fn run(options: Options, legacy: bool) -> Result<()> {
    shutdown::install()?;
    let mut parts = options.interface.split(',');
    let name = parts.next().unwrap();
    if !matches!(name, "can0" | "any") {
        interface_name(name)?;
    }
    let filters = Filters::parse(parts)?;
    let show_name = if name == "any" { "can0" } else { name };
    let mut next: Box<dyn FnMut() -> Result<Option<Event>>> = if legacy && name.starts_with("feth") {
        let link = Link::open(name, None)?;
        Box::new(move || link.next())
    } else {
        let mut watch = ipc::Watch::open(name)?;
        Box::new(move || watch.next())
    };
    let mut capture = open_pcap(options.pcap)?;
    let mut output = io::stdout().lock();
    let mut captured = 0;
    let start = Instant::now();
    let mut last_event = start;
    let idle = options.idle_timeout.map(|ms| Duration::from_millis(ms.into()));
    let timeout = options.timeout.map(|seconds| Duration::from_secs(seconds.into()));
    let mut base = None;

    while !shutdown::requested() && options.count != Some(captured) {
        if timeout.is_some_and(|limit| start.elapsed() >= limit) || idle.is_some_and(|limit| last_event.elapsed() >= limit) {
            break;
        }
        let Some(event) = next()? else {
            thread::sleep(Duration::from_millis(5));
            continue;
        };
        if !filters.matches(event.frame, legacy) {
            continue;
        }
        last_event = Instant::now();
        if let Some(file) = &mut capture {
            write_pcap_record(file, &event)?;
        }

        let log_format = options.log_format || legacy;
        if log_format || options.timestamp.is_some() {
            let now = i128::from(event.time[0]) * 1_000_000 + i128::from(event.time[1]);
            let timestamp = match options.timestamp.unwrap_or(Timestamp::Absolute) {
                Timestamp::Absolute => now,
                Timestamp::Delta => now.saturating_sub(base.replace(now).unwrap_or(now)).max(0),
                Timestamp::Zero => now.saturating_sub(*base.get_or_insert(now)).max(0),
            };
            write!(output, "({}.{:06}) ", timestamp / 1_000_000, timestamp % 1_000_000)?;
        }
        if log_format {
            if legacy {
                writeln!(output, "{show_name} {} {}", event.direction.label(), event.frame)?;
            } else {
                writeln!(output, "{show_name} {}", event.frame)?;
            }
        } else {
            expanded(&mut output, show_name, &event, options.extra)?;
        }
        output.flush()?;
        captured += 1;
    }
    if let Some(mut file) = capture {
        file.flush()?;
    }
    if legacy
        && !shutdown::requested()
        && let Some(count) = options.count
    {
        ensure!(captured >= count, "timed out after capturing {captured} of {count} frames");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_can_distinguish_standard_extended_and_remote_frames() {
        let short = Filters::parse(["123:C00007FF"].into_iter()).unwrap();
        assert!(short.matches("123#11".parse().unwrap(), false));
        assert!(!short.matches("123#R1".parse().unwrap(), false));
        assert!(!short.matches("00000123#11".parse().unwrap(), false));
        let extended = Filters::parse(["00000123:DFFFFFFF"].into_iter()).unwrap();
        assert!(extended.matches("00000123#11".parse().unwrap(), false));
        assert!(!extended.matches("123#11".parse().unwrap(), false));
    }
}
