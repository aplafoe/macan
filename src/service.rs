use std::{
    env, fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::Path,
    process::Command,
};

use anyhow::{Context, Result, ensure};
use clap::Subcommand;

use crate::{bridge::BusOptions, ipc};

const LABEL: &str = "io.macan.macan";
const TARGET: &str = "system/io.macan.macan";
const HELPER: &str = "/Library/PrivilegedHelperTools/io.macan.macan";
const PLIST: &str = "/Library/LaunchDaemons/io.macan.macan.plist";

#[derive(Subcommand)]
pub enum Action {
    /// Install or update the system daemon and start it at boot.
    Install {
        #[command(flatten)]
        options: BusOptions,
        /// User allowed to access the CAN socket. Defaults to the invoking sudo user's UID.
        #[arg(long)]
        user_uid: Option<u32>,
    },
    /// Start the installed daemon and enable it at boot.
    Start,
    /// Stop the daemon and disable automatic startup.
    Stop,
    /// Show the daemon's CAN channel state.
    Status,
    /// Stop the daemon and remove its installed helper and LaunchDaemon.
    Uninstall,
}

fn launchctl(args: &[&str]) -> Result<()> {
    let output = Command::new("/bin/launchctl").args(args).output().context("run launchctl")?;
    ensure!(output.status.success(), "launchctl {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr).trim());
    Ok(())
}

fn loaded() -> bool {
    launchctl(&["print", TARGET]).is_ok()
}

fn bootout() -> Result<()> {
    if loaded() {
        // Release the CAN channel and its interfaces before asking launchd to exit.
        let _ = ipc::run("PAUSE");
        launchctl(&["bootout", TARGET])?;
    }
    Ok(())
}

fn start() -> Result<()> {
    ensure!(Path::new(PLIST).is_file() && Path::new(HELPER).is_file(), "run macan service install first");
    launchctl(&["enable", TARGET])?;
    if !loaded() {
        launchctl(&["bootstrap", "system", PLIST])?;
    }
    Ok(())
}

fn plist(options: &BusOptions, user_uid: u32) -> String {
    let mut args = vec![
        HELPER.to_owned(),
        "daemon".to_owned(),
        "--bitrate".to_owned(),
        options.bitrate.to_string(),
        "--channel".to_owned(),
        options.channel.to_string(),
        "--user-uid".to_owned(),
        user_uid.to_string(),
    ];
    if let Some(device) = options.device {
        args.extend(["--device".to_owned(), device.to_string()]);
    }
    if let Some(interface) = &options.interface {
        args.extend(["--interface".to_owned(), interface.to_owned()]);
    }
    let args = args.iter().map(|arg| format!("    <string>{arg}</string>\n")).collect::<String>();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>
{args}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>3</integer>
  <key>ExitTimeOut</key><integer>5</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/var/log/macan.log</string>
</dict>
</plist>
"#
    )
}

fn stage(path: &str, bytes: &[u8], mode: u32) -> Result<tempfile::NamedTempFile> {
    let directory = Path::new(path).parent().unwrap();
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o755);
    match builder.create(directory) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).with_context(|| format!("create {}", directory.display())),
    }
    let directory_metadata = fs::symlink_metadata(directory)?;
    ensure!(
        directory_metadata.is_dir() && directory_metadata.uid() == 0 && directory_metadata.mode() & 0o022 == 0,
        "unsafe system directory {}",
        directory.display()
    );

    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().set_permissions(fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn existing(path: &str, mode: u32) -> Result<Option<tempfile::NamedTempFile>> {
    match fs::read(path) {
        Ok(contents) => stage(path, &contents, mode).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {path}")),
    }
}

fn remove(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {path}")),
    }
}

fn restore(file: Option<tempfile::NamedTempFile>, path: &str) -> Result<()> {
    if let Some(file) = file {
        file.persist(path).with_context(|| format!("restore {path}"))?;
    } else {
        remove(path)?;
    }
    Ok(())
}

fn install(options: &BusOptions, user_uid: Option<u32>) -> Result<()> {
    let user_uid = user_uid.or_else(|| env::var("SUDO_UID").ok().and_then(|uid| uid.parse().ok())).unwrap_or(0);
    let binary = fs::read(env::current_exe()?).context("read macan executable")?;
    let helper = stage(HELPER, &binary, 0o755)?;
    let config = stage(PLIST, plist(options, user_uid).as_bytes(), 0o644)?;
    let old_helper = existing(HELPER, 0o755)?;
    let old_config = existing(PLIST, 0o644)?;
    let was_running = loaded();
    bootout()?;

    let replaced = (|| -> Result<()> {
        helper.persist(HELPER).context("install macan system helper")?;
        config.persist(PLIST).context("install macan LaunchDaemon")?;
        start()
    })();
    if let Err(error) = replaced {
        let rollback = (|| -> Result<()> {
            bootout()?;
            restore(old_helper, HELPER)?;
            restore(old_config, PLIST)?;
            if was_running {
                start()?;
            }
            Ok(())
        })();
        if let Err(rollback) = rollback {
            return Err(error).context(format!("restore previous service: {rollback:#}"));
        }
        return Err(error);
    }
    println!("{TARGET} installed (CAN client UID {user_uid})");
    Ok(())
}

pub fn run(action: Action) -> Result<()> {
    if matches!(action, Action::Status) {
        println!("{}", ipc::run("STATUS")?);
        return Ok(());
    }
    ensure!(ipc::uid() == 0, "this operation requires sudo");

    match action {
        Action::Install { options, user_uid } => install(&options, user_uid),
        Action::Start => start(),
        Action::Stop => {
            bootout()?;
            launchctl(&["disable", TARGET])
        }
        Action::Uninstall => {
            bootout()?;
            remove(PLIST)?;
            remove(HELPER)
        }
        Action::Status => unreachable!(),
    }
}
