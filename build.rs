//! Compile the shade payload with rustc (not nested cargo) and embed it.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("cs2_dumper_shade.dll");

    println!("cargo:rerun-if-changed=shade-payload/src/lib.rs");
    println!("cargo:rerun-if-changed=shade-payload/Cargo.toml");

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        fs::write(&dest, []).expect("write empty shade stub");
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join("shade-payload/src/lib.rs");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());

    let mut cmd = Command::new(rustc);
    cmd.arg("--crate-name")
        .arg("cs2_dumper_shade")
        .arg("--crate-type")
        .arg("cdylib")
        .arg("--edition")
        .arg("2021")
        .arg("-o")
        .arg(&dest)
        .arg(&src);
    if profile == "release" {
        cmd.arg("-C").arg("opt-level=3");
        cmd.arg("-C").arg("lto");
        cmd.arg("-C").arg("strip=symbols");
    }

    let status = cmd
        .status()
        .unwrap_or_else(|err| panic!("failed to spawn rustc for shade payload: {err}"));
    if !status.success() {
        panic!("shade payload rustc failed: {status}");
    }
    if !dest.is_file() {
        panic!("shade payload missing: {}", dest.display());
    }
}
