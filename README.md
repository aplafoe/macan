# macan

Classical CAN on macOS for USB adapters that speak `gs_usb`. A system LaunchDaemon owns the USB adapter and creates a pair of macOS `feth` interfaces. The clients use a local Unix socket and refer to the daemon's CAN channel as `can0`. Use `macan status` to see the corresponding interface for `ifconfig` or `tcpdump`.

The CAN driver runs in user space. macOS registers the link as virtual Ethernet. Programs that open a Linux `AF_CAN` socket require a macOS integration. [Apple NetworkingDriverKit](https://developer.apple.com/documentation/networkingdriverkit), [Apple XNU `if_fake`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_fake.c)

## Install with Homebrew

From a checkout on the target Mac, generate a local tap. This needs Rust 1.90+, the Xcode Command Line Tools, and the Homebrew build dependencies.

```sh
brew install libusb pkgconf
sh packaging/make-tap.sh
brew tap --custom-remote local/macan "$PWD/dist/homebrew-macan"
brew install local/macan/macan
```

The tap points to the checksummed archive in `dist` for the architecture of the build Mac. Keep the archive at that path for reinstalls. Once the tap and archive exist, installing the formula does not need Rust or libusb. The tool is statically linked to libusb. The daemon's executable is installed to a root-owned system directory.

## Run the system daemon

If the adapter is passed through to a VM, first disconnect it from the VM's USB menu. Use the bitrate of the existing CAN bus.

```sh
macan devices
sudo "$(command -v macan)" service install --bitrate 250000
macan status
```

The system service is registered as `system/io.macan.macan` and starts at boot. It waits for an adapter and retries after a USB disconnect. By default the user who runs `sudo` gets socket access for capturing and sending frames. Use `--user-uid` to grant access to a different account. `--channel` selects the adapter channel and defaults to `0`. With multiple adapters present, use `--device BUS:ADDRESS` from `macan devices`. USB addresses can change after reconnection, so omit this option when using a single adapter. `--interface feth10` requests a specific free macOS interface.

```sh
sudo "$(command -v macan)" service stop
sudo "$(command -v macan)" service start
sudo "$(command -v macan)" service uninstall
brew uninstall macan
```

`stop` disables startup at boot. `start` re-enables it. To change the bitrate or update the system helper after reinstalling the formula, run `service install` again. Daemon messages are in `/var/log/macan.log`.

## Capture and send

```sh
candump can0
candump -L -n 10 can0,123:7FF
candump -ta -x -T 5000 can0
candump --pcap can.pcap can0
cansend can0 '123#11223344'
cansend can0 '01ABCDEF#0102'
cansend can0 '321#R4'
```

`macan candump` and `macan cansend` also work. `candump` accepts `any` for the active channel. `ID:MASK` matches an ID, `ID~MASK` inverts the match, `#ERROR_MASK` enables error frames, and `j` combines ID filters with AND. Append filters to the interface argument, separated by commas. `-L` prints the compact log format, `-n` stops after a frame count, `-T` stops on idle milliseconds, and `-t a|d|z` selects absolute, delta, or zero-based timestamps. [can-utils](https://github.com/linux-can/can-utils)

Use three hexadecimal digits for an 11-bit ID and eight for a 29-bit ID. `123#` sends an empty data frame. `321#R4` requests four bytes using RTR. `cansend` queues a transmit request. The adapter starts in normal mode and participates in CAN acknowledgements.

The optional `--pcap` file contains `LINKTYPE_CAN_SOCKETCAN` records for Wireshark. To capture on the macOS interface itself, replace `feth0` with the interface from `macan status`:

```sh
ifconfig feth0
sudo tcpdump -ni feth0 -xx 'ether proto 0x88b5'
```

The local EtherType `0x88b5` carries `MCAN`, version byte `1`, direction byte (`0` for RX or `1` for TX), two zero bytes, and a 16-byte classical SocketCAN frame with the ID in network byte order. Remaining bytes are Ethernet padding. Captures use macOS BPF timestamps.

The foreground path remains available when the daemon is stopped. It requires root for BPF and interface setup.

```sh
sudo macan up --bitrate 250000
sudo macan dump feth0
sudo macan send feth0 '123#11223344'
sudo ifconfig feth0 down
```

## Adapter support

This build covers classical CAN data and RTR frames. Adapter error frames are captured when the firmware reports them. USB discovery recognizes `1d50:606f` (CANable, CANtact, and compatibles), `1209:2323` (candleLight), `1cd2:606f` (CANext / CANtact Pro), `16d0:10b8` (CANdebugger), `16d0:0f30` (SAINT3), and `1209:ca01` (CANnectivity). Compatibility depends on the installed firmware. Serial SLCAN and CAN FD require separate support. [CANable firmware](https://canable.io/getting-started.html), [Linux `gs_usb` protocol and USB IDs](https://github.com/torvalds/linux/blob/master/drivers/net/can/usb/gs_usb.c)
