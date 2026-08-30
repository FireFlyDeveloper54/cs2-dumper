//! Compile the shade payload with rustc (not nested cargo) and embed it.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let dest = out_dir.join("cs2_dumper_shade.dll");

    // Cargo recurses into a directory, so a payload split across more than one
    // source file still triggers a rebuild. Naming `src/lib.rs` alone would
    // embed a stale DLL the moment a second module appears.
    println!("cargo:rerun-if-changed=shade-payload/src");
    println!("cargo:rerun-if-changed=src/shade_payload.rs");
    println!("cargo:rerun-if-changed=shade-payload/Cargo.toml");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=PROFILE");

    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows"
        || env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() != "x86_64"
    {
        return Err("cs2-dumper supports Windows x86-64 only; shade payload cannot be built for this target".into());
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let src = manifest_dir.join("src/shade_payload.rs");
    if !src.is_file() {
        // Published packages include the payload through the explicit include list.
        return Err(format!("shade payload source missing: {}", src.display()).into());
    }
    // Keep the standalone payload crate and the published embedded source in lockstep.
    // The standalone crate is excluded from the root package, so this check is skipped
    // when building a package tarball where that directory is intentionally absent.
    let standalone_src = manifest_dir.join("shade-payload/src/lib.rs");
    if standalone_src.is_file() && fs::read(&src)? != fs::read(&standalone_src)? {
        return Err(format!(
            "shade payload sources differ: {} and {}",
            src.display(),
            standalone_src.display()
        )
        .into());
    }
    println!("cargo:rustc-env=CS2_DUMPER_SHADE_PAYLOAD_AVAILABLE=1");
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

    let output = cmd.output()?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "shade payload rustc failed: {}
--- stdout ---
{stdout}
--- stderr ---
{stderr}",
            output.status
        )
        .into());
    }
    if !dest.is_file() {
        return Err(format!("shade payload missing: {}", dest.display()).into());
    }
    Ok(())
}
