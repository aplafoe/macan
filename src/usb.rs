use std::{
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    fmt,
    ptr::{self, NonNull},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};

use crate::{
    frame::Frame,
    timing::{Timing, TimingLimits},
};

type UsbDevice = c_void;
type UsbHandle = c_void;

const USB_TIMEOUT: c_int = -7;
const USB_NO_DEVICE: c_int = -4;
const VENDOR_INTERFACE: u8 = 0x41;
const HOST_FORMAT: u8 = 0;
const BITTIMING: u8 = 1;
const MODE: u8 = 2;
const BT_CONST: u8 = 4;
const DEVICE_CONFIG: u8 = 5;
const QUIRK_LPC546XX: u32 = 1 << 9;
const BERR_REPORTING: u32 = 1 << 12;
const FLAG_FD: u8 = 1 << 1;
const FLAG_OVERFLOW: u8 = 1;
const RX_ECHO_ID: u32 = u32::MAX;

const DEVICES: &[(u16, u16)] = &[
    (0x1d50, 0x606f), // Geschwister Schneider, CANable, CANtact and compatibles
    (0x1209, 0x2323), // candleLight
    (0x1cd2, 0x606f), // CES CANext FD / CANtact Pro
    (0x16d0, 0x10b8), // ABE CANdebugger FD
    (0x16d0, 0x0f30), // Xylanta SAINT3
    (0x1209, 0xca01), // CANnectivity
];

unsafe extern "C" {
    fn libusb_init(context: *mut *mut c_void) -> c_int;
    fn libusb_exit(context: *mut c_void);
    fn libusb_get_device_list(context: *mut c_void, list: *mut *mut *mut UsbDevice) -> isize;
    fn libusb_free_device_list(list: *mut *mut UsbDevice, unref_devices: c_int);
    fn libusb_get_bus_number(device: *mut UsbDevice) -> u8;
    fn libusb_get_device_address(device: *mut UsbDevice) -> u8;
    fn libusb_open(device: *mut UsbDevice, handle: *mut *mut UsbHandle) -> c_int;
    fn libusb_close(handle: *mut UsbHandle);
    fn libusb_claim_interface(handle: *mut UsbHandle, interface: c_int) -> c_int;
    fn libusb_release_interface(handle: *mut UsbHandle, interface: c_int) -> c_int;
    fn libusb_control_transfer(handle: *mut UsbHandle, request_type: u8, request: u8, value: u16, index: u16, data: *mut u8, length: u16, timeout: c_uint) -> c_int;
    fn libusb_bulk_transfer(handle: *mut UsbHandle, endpoint: u8, data: *mut u8, length: c_int, transferred: *mut c_int, timeout: c_uint) -> c_int;
    fn libusb_error_name(code: c_int) -> *const c_char;
    fn macan_usb_id(device: *mut UsbDevice, id: *mut u16) -> c_int;
    fn macan_usb_endpoints(device: *mut UsbDevice, endpoints: *mut u8) -> c_int;
}

fn check(code: c_int) -> Result<c_int> {
    if code >= 0 {
        return Ok(code);
    }
    // libusb_error_name returns a static string, including for unknown codes.
    let name = unsafe { CStr::from_ptr(libusb_error_name(code)) };
    bail!("{}", name.to_string_lossy());
}

struct UsbContext(NonNull<c_void>);

impl UsbContext {
    fn new() -> Result<Self> {
        let mut context = ptr::null_mut();
        check(unsafe { libusb_init(&mut context) }).context("initialize libusb")?;
        Ok(Self(NonNull::new(context).context("libusb returned no context")?))
    }

    fn devices(&self) -> Result<DeviceList<'_>> {
        let mut list = ptr::null_mut();
        let count = unsafe { libusb_get_device_list(self.0.as_ptr(), &mut list) };
        if count < 0 {
            check(count as c_int).context("enumerate USB devices")?;
        }
        Ok(DeviceList {
            list,
            count: count as usize,
            _context: self,
        })
    }
}

impl Drop for UsbContext {
    fn drop(&mut self) {
        unsafe { libusb_exit(self.0.as_ptr()) };
    }
}

struct DeviceList<'a> {
    list: *mut *mut UsbDevice,
    count: usize,
    _context: &'a UsbContext,
}

impl DeviceList<'_> {
    fn gs_usb(&self) -> impl Iterator<Item = (DeviceInfo, *mut UsbDevice)> + '_ {
        (0..self.count).filter_map(|index| {
            let device = unsafe { *self.list.add(index) };
            let mut id = [0; 2];
            if unsafe { macan_usb_id(device, id.as_mut_ptr()) } != 0 || !DEVICES.contains(&(id[0], id[1])) {
                return None;
            }

            let address = DeviceAddress {
                bus: unsafe { libusb_get_bus_number(device) },
                device: unsafe { libusb_get_device_address(device) },
            };
            Some((DeviceInfo { id, address }, device))
        })
    }
}

impl Drop for DeviceList<'_> {
    fn drop(&mut self) {
        unsafe { libusb_free_device_list(self.list, 1) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAddress {
    bus: u8,
    device: u8,
}

impl FromStr for DeviceAddress {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (bus, device) = value.split_once(':').context("expected decimal BUS:ADDRESS")?;
        Ok(Self {
            bus: bus.parse()?,
            device: device.parse()?,
        })
    }
}

impl fmt::Display for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.bus, self.device)
    }
}

pub struct DeviceInfo {
    id: [u16; 2],
    address: DeviceAddress,
}

impl fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:04x}:{:04x}", self.address, self.id[0], self.id[1])
    }
}

pub fn list() -> Result<Vec<DeviceInfo>> {
    let context = UsbContext::new()?;
    Ok(context.devices()?.gs_usb().map(|(info, _)| info).collect())
}

struct Handle {
    pointer: NonNull<UsbHandle>,
    claimed: bool,
}

impl Handle {
    fn control(&self, read: bool, request: u8, value: u16, data: &mut [u8]) -> Result<()> {
        let request_type = VENDOR_INTERFACE | (u8::from(read) << 7);
        let count = check(unsafe { libusb_control_transfer(self.pointer.as_ptr(), request_type, request, value, 0, data.as_mut_ptr(), data.len() as u16, 1000) })?;
        ensure!(count as usize == data.len(), "short gs_usb control transfer ({count}/{} bytes)", data.len());
        Ok(())
    }

    fn bulk(&self, endpoint: u8, data: &mut [u8], timeout: c_uint) -> (c_int, usize) {
        let mut count = 0;
        let status = unsafe { libusb_bulk_transfer(self.pointer.as_ptr(), endpoint, data.as_mut_ptr(), data.len() as c_int, &mut count, timeout) };
        (status, count as usize)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            if self.claimed {
                libusb_release_interface(self.pointer.as_ptr(), 0);
            }
            libusb_close(self.pointer.as_ptr());
        }
    }
}

pub struct GsUsb {
    handle: Handle,
    _context: UsbContext,
    pub device: DeviceInfo,
    pub timing: Timing,
    pub channel: u8,
    endpoints: [u8; 2],
    features: u32,
    running: bool,
}

impl GsUsb {
    pub fn open(address: Option<DeviceAddress>, channel: u8, bitrate: u32) -> Result<Self> {
        let context = UsbContext::new()?;
        let list = context.devices()?;
        let mut matches = list.gs_usb().filter(|(info, _)| address.is_none_or(|address| address == info.address));
        let (info, device) = matches.next().context("no matching gs_usb device (see macan devices)")?;
        ensure!(matches.next().is_none(), "multiple gs_usb devices found, select one with --device BUS:ADDRESS");
        drop(matches);

        let mut endpoints = [0; 2];
        check(unsafe { macan_usb_endpoints(device, endpoints.as_mut_ptr()) }).context("read gs_usb bulk endpoints")?;
        let mut pointer = ptr::null_mut();
        check(unsafe { libusb_open(device, &mut pointer) }).with_context(|| format!("open USB device {info} (release it from any VM or other application first)"))?;
        let mut handle = Handle {
            pointer: NonNull::new(pointer).context("libusb returned no device handle")?,
            claimed: false,
        };
        check(unsafe { libusb_claim_interface(handle.pointer.as_ptr(), 0) }).with_context(|| format!("claim USB interface of {info} (release it from any VM or other application first)"))?;
        handle.claimed = true;
        drop(list);

        handle.control(false, HOST_FORMAT, 1, &mut 0x0000_beef_u32.to_le_bytes()).context("set gs_usb host format")?;
        let mut config = [0; 12];
        handle.control(true, DEVICE_CONFIG, 1, &mut config).context("read gs_usb device config")?;
        ensure!(channel <= config[3], "USB channel {channel} is unavailable (last channel is {})", config[3]);

        let mut constants = [0; 40];
        handle.control(true, BT_CONST, channel.into(), &mut constants).context("read gs_usb bit timing limits")?;
        let field = |index: usize| u32::from_le_bytes(constants[index * 4..][..4].try_into().unwrap());
        let timing = TimingLimits {
            clock: field(1),
            tseg1_min: field(2),
            tseg1_max: field(3),
            tseg2_min: field(4),
            tseg2_max: field(5),
            sjw_max: field(6),
            brp_min: field(7),
            brp_max: field(8),
            brp_inc: field(9),
        }
        .calculate(bitrate)?;

        Ok(Self {
            handle,
            _context: context,
            device: info,
            timing,
            channel,
            endpoints,
            features: field(0),
            running: false,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        self.handle.control(false, MODE, self.channel.into(), &mut [0; 8]).context("reset CAN channel")?;
        let mut bytes = [0; 20];
        for (slot, field) in bytes.chunks_exact_mut(4).zip(self.timing.fields) {
            slot.copy_from_slice(&field.to_le_bytes());
        }
        self.handle.control(false, BITTIMING, self.channel.into(), &mut bytes).context("set CAN bit timing")?;

        let mut mode = [0; 8];
        mode[0] = 1;
        mode[4..].copy_from_slice(&(self.features & BERR_REPORTING).to_le_bytes());
        self.running = true;
        self.handle.control(false, MODE, self.channel.into(), &mut mode).context("start CAN channel")
    }

    pub fn send(&self, frame: Frame, echo_id: u32) -> Result<()> {
        let mut bytes = [0; 21];
        bytes[..4].copy_from_slice(&echo_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&frame.id.to_le_bytes());
        bytes[8] = frame.len;
        bytes[9] = self.channel;
        bytes[12..20].copy_from_slice(&frame.data);

        let len = 20 + usize::from(self.features & QUIRK_LPC546XX != 0);
        let (status, written) = self.handle.bulk(self.endpoints[0], &mut bytes[..len], 250);
        check(status).context("write CAN frame to USB adapter")?;
        ensure!(written == len, "short USB write ({written}/{len} bytes)");
        Ok(())
    }

    pub fn receive(&self) -> Result<Option<Frame>> {
        let mut bytes = [0; 128];
        let (status, count) = self.handle.bulk(self.endpoints[1], &mut bytes, 5);
        if status == USB_NO_DEVICE {
            bail!("USB adapter disconnected");
        }
        if status != USB_TIMEOUT {
            check(status).context("read from USB adapter")?;
        }

        let Some(header) = bytes[..count].first_chunk::<12>() else {
            return Ok(None);
        };
        if header[9] != self.channel {
            return Ok(None);
        }
        if header[10] & FLAG_OVERFLOW != 0 {
            eprintln!("gs_usb channel {} reported a receive overflow", self.channel);
        }
        let echo = u32::from_le_bytes(header[..4].try_into().unwrap());
        if echo != RX_ECHO_ID || header[10] & FLAG_FD != 0 {
            return Ok(None);
        }
        let id = u32::from_le_bytes(header[4..8].try_into().unwrap());
        Ok(Frame::from_bus(id, header[8].min(8), &bytes[12..count]))
    }
}

impl Drop for GsUsb {
    fn drop(&mut self) {
        if self.running {
            let _ = self.handle.control(false, MODE, self.channel.into(), &mut [0; 8]);
        }
    }
}
