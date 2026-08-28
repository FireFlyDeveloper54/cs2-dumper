//! Compile the shade payload with rustc (not nested cargo) and embed it.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("cs2_dumper_shade.dll");

    // Cargo recurses into a directory, so a payload split across more than one
    // source file still triggers a rebuild. Naming `src/lib.rs` alone would
    // embed a stale DLL the moment a second module appears.
    println!("cargo:rerun-if-changed=shade-payload/src");
    println!("cargo:rerun-if-changed=shade-payload/Cargo.toml");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        fs::write(&dest, []).expect("write empty shade stub");
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join("shade-payload/src/lib.rs");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());

    let mut cmd = Command::new(&rustc);
    cmd.arg("--crate-name")
        .arg("cs2_dumper_shade")
        .arg("--crate-type")
        .arg("cdylib")
        .arg("--edition")
        .arg("2021")
        .arg("-o")
        .arg(&dest)
        .arg(&src);
    if let Ok(target) = env::var("TARGET") {
        cmd.arg("--target").arg(target);
    }
    if profile == "release" {
        cmd.arg("-C").arg("opt-level=3");
        cmd.arg("-C").arg("debuginfo=0");
        cmd.arg("-C").arg("strip=symbols");
        // Deliberately *not* `-C panic=abort`. This DLL runs inside the game
        // process, and `on_attach` wraps its work in `catch_unwind` so a panic
        // becomes a status file the host can report. Aborting instead would
        // take cs2.exe down with it and leave no status behind, so the host
        // would report a timeout rather than the real cause.
    }

    let output = cmd
        .output()
        .unwrap_or_else(|err| panic!("failed to spawn rustc for shade payload: {err}"));
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "shade payload rustc failed: {}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            output.status
        );
    }
    if !dest.is_file() {
        panic!("shade payload missing: {}", dest.display());
    }
}
