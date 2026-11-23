use std::{ffi::c_int, io};

use anyhow::{Context, Result};

unsafe extern "C" {
    fn macan_install_shutdown() -> c_int;
    fn macan_stop_requested() -> c_int;
}

pub fn install() -> Result<()> {
    if unsafe { macan_install_shutdown() } != 0 {
        return Err(io::Error::last_os_error()).context("install shutdown handlers");
    }
    Ok(())
}

pub fn requested() -> bool {
    unsafe { macan_stop_requested() != 0 }
}
