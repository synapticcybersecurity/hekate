fn main() {
    // Compile + link the Swift Touch ID helper (swift-lib/biometric.swift)
    // on macOS. We invoke `swiftc` directly (no SwiftPM/swift-rs) — the Swift
    // 6.3 toolchain + a single-file helper makes a direct compile the
    // simplest, most robust path. See docs/desktop-touch-id.md.
    #[cfg(target_os = "macos")]
    build_swift_helper();

    tauri_build::build();
}

#[cfg(target_os = "macos")]
fn build_swift_helper() {
    use std::process::Command;

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let src = "swift-lib/biometric.swift";
    let lib = format!("{out_dir}/libHekateBiometric.a");

    let sdk = {
        let out = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .expect("run xcrun to find the macOS SDK");
        String::from_utf8(out.stdout)
            .expect("sdk path is utf8")
            .trim()
            .to_string()
    };

    // Static Swift archive; the Swift stdlib is linked dynamically against the
    // OS runtime in /usr/lib/swift (present on macOS 12+), so nothing extra
    // needs bundling.
    let status = Command::new("swiftc")
        .args([
            "-emit-library",
            "-static",
            "-parse-as-library",
            "-O",
            "-module-name",
            "HekateBiometric",
            "-target",
            "arm64-apple-macosx11.0",
            "-sdk",
            &sdk,
            src,
            "-o",
            &lib,
        ])
        .status()
        .expect("run swiftc");
    assert!(
        status.success(),
        "swiftc failed to build the Touch ID helper"
    );

    // Toolchain lib dir (…/usr/lib/swift/macosx), derived from swiftc's
    // location so it works under either Command Line Tools or Xcode. Holds
    // the back-deployment compatibility archives (libswiftCompatibility*.a)
    // that swiftc autolinks when targeting an older macOS.
    let toolchain_lib = {
        let out = Command::new("xcrun")
            .args(["--find", "swiftc"])
            .output()
            .expect("run xcrun to find swiftc");
        let swiftc_path = String::from_utf8(out.stdout).expect("path utf8");
        std::path::Path::new(swiftc_path.trim())
            .parent()
            .and_then(|p| p.parent())
            .expect("…/usr/bin/swiftc")
            .join("lib/swift/macosx")
    };

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=HekateBiometric");
    // Swift runtime link-time stubs live in the SDK; the @_cdecl objects carry
    // autolink directives (-lswiftCore, …) that the linker resolves here.
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    println!("cargo:rustc-link-search=native={}", toolchain_lib.display());
    // Frameworks the helper imports.
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rerun-if-changed={src}");
}
