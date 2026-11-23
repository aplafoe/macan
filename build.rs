fn main() {
    assert_eq!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("macos"), "macan requires macOS");

    println!("cargo:rerun-if-changed=src/native.c");
    let usb = pkg_config::Config::new()
        .cargo_metadata(false)
        .statik(true)
        .probe("libusb-1.0")
        .expect("Install libusb and pkgconf (brew install libusb pkgconf)");

    cc::Build::new().file("src/native.c").includes(usb.include_paths).compile("macan_native");
    // The system daemon must only load libraries from system-owned locations.
    let archive = usb
        .link_paths
        .iter()
        .map(|path| path.join("libusb-1.0.a"))
        .find(|path| path.is_file())
        .expect("libusb must provide a static archive");
    println!("cargo:rustc-link-arg={}", archive.display());
    for library in usb.libs.into_iter().filter(|name| name != "usb-1.0") {
        println!("cargo:rustc-link-lib={library}");
    }
    for framework in usb.frameworks {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-lib=pcap");
}
