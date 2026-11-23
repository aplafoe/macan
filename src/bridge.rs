use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Args;

use crate::{
    interface::{Direction, Link, Ports, interface_name},
    usb::{DeviceAddress, GsUsb},
};

#[derive(Clone, Args)]
pub struct BusOptions {
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub bitrate: u32,
    /// Decimal BUS:ADDRESS from `macan devices`.
    #[arg(long)]
    pub device: Option<DeviceAddress>,
    #[arg(long, default_value_t = 0)]
    pub channel: u8,
    /// Choose a free feth interface name. By default macOS assigns one.
    #[arg(short, long, value_parser = interface_name)]
    pub interface: Option<String>,
}

pub struct Bridge {
    link: Link,
    ports: Ports,
    usb: GsUsb,
    echo_id: u32,
    next_status: Instant,
}

impl Bridge {
    pub fn open(options: &BusOptions) -> Result<Self> {
        let mut usb = GsUsb::open(options.device, options.channel, options.bitrate)?;
        let ports = Ports::create(options.interface.as_deref()).context("create macan network interfaces (requires root)")?;
        let link = Link::open(ports.peer(), Some(Direction::Tx))?;
        usb.start()?;

        Ok(Self {
            link,
            ports,
            usb,
            echo_id: 0,
            next_status: Instant::now(),
        })
    }

    pub fn interface(&self) -> &str {
        self.ports.public()
    }

    pub fn description(&self) -> String {
        format!(
            "{}  USB {} channel {}  {} bit/s  sample point {:.1}%",
            self.interface(),
            self.usb.device,
            self.usb.channel,
            self.usb.timing.bitrate,
            f64::from(self.usb.timing.sample_point) / 10.0
        )
    }

    pub fn tick(&mut self) -> Result<bool> {
        let now = Instant::now();
        if now >= self.next_status {
            if !self.ports.is_up()? {
                return Ok(false);
            }
            self.next_status = now + Duration::from_millis(250);
        }
        // Keep servicing the USB input if macOS is sending a burst.
        for _ in 0..16 {
            let Some(event) = self.link.next()? else { break };
            if !event.frame.is_error() {
                self.usb.send(event.frame, self.echo_id)?;
                self.echo_id = (self.echo_id + 1) % 32;
            }
        }
        if let Some(frame) = self.usb.receive()? {
            self.link.inject(frame, Direction::Rx)?;
        }
        Ok(true)
    }
}
