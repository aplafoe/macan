mod bridge;
mod capture;
mod daemon;
mod frame;
mod interface;
mod ipc;
mod service;
mod shutdown;
mod timing;
mod usb;

use std::{
    env,
    io::{self, Write},
    path::Path,
};

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::{
    bridge::{Bridge, BusOptions},
    frame::Frame,
    interface::{Direction, Link, interface_name},
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List connected gs_usb adapters.
    Devices,
    /// Create a CAN interface in the foreground.
    Up(BusOptions),
    /// Show the system daemon and its active CAN interface.
    Status,
    /// Manage the macan system daemon.
    Service {
        #[command(subcommand)]
        action: service::Action,
    },
    #[command(hide = true)]
    Daemon {
        #[command(flatten)]
        options: BusOptions,
        #[arg(long)]
        user_uid: u32,
    },
    /// Print and filter CAN frames using candump syntax.
    Candump(capture::Options),
    /// Queue a frame through the daemon using cansend syntax.
    Cansend(SendOptions),
    /// Capture frames from a macan interface in the original output format.
    Dump(capture::Options),
    /// Queue one CAN frame.
    Send(SendOptions),
}

#[derive(Args)]
struct SendOptions {
    /// CAN interface name, such as can0 or feth0.
    interface: String,
    /// Classical CAN frame, such as 123#1122 or 123#R4.
    frame: Frame,
}

#[derive(Parser)]
#[command(name = "candump", version, about = "Print and filter CAN frames on macOS")]
struct Candump {
    #[command(flatten)]
    options: capture::Options,
}

#[derive(Parser)]
#[command(name = "cansend", version, about = "Queue one CAN frame on macOS")]
struct Cansend {
    #[command(flatten)]
    options: SendOptions,
}

fn up(options: BusOptions) -> Result<()> {
    shutdown::install()?;
    let mut bridge = Bridge::open(&options)?;
    println!("{}", bridge.description());
    io::stdout().flush()?;
    while !shutdown::requested() && bridge.tick()? {}
    Ok(())
}

fn send(options: SendOptions, legacy: bool) -> Result<()> {
    if options.interface != "can0" {
        interface_name(&options.interface)?;
    }
    if legacy && options.interface.starts_with("feth") {
        Link::open(&options.interface, None)?.inject(options.frame, Direction::Tx)
    } else {
        ipc::run(&format!("SEND {} {}", options.interface, options.frame))?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let executable = env::args_os().next().unwrap_or_default();
    match Path::new(&executable).file_name().and_then(|name| name.to_str()) {
        Some("candump") => return capture::run(Candump::parse().options, false),
        Some("cansend") => return send(Cansend::parse().options, false),
        _ => (),
    }

    match Cli::parse().command {
        Command::Devices => {
            for device in usb::list()? {
                println!("{device}");
            }
            Ok(())
        }
        Command::Up(options) => up(options),
        Command::Daemon { options, user_uid } => daemon::run(options, user_uid),
        Command::Status => service::run(service::Action::Status),
        Command::Service { action } => service::run(action),
        Command::Candump(options) => capture::run(options, false),
        Command::Cansend(options) => send(options, false),
        Command::Dump(options) => capture::run(options, true),
        Command::Send(options) => send(options, true),
    }
}
