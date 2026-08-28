//! Optional `-c shade` backend: inject a payload DLL into live `cs2.exe`.
//!
//! The payload (shade-dumper's in-process trick) enumerates modules that
//! export `InstallSchemaBindings` and calls them against `SchemaSystem_001`.
//! The host then attaches with memflow native and dumps as usual — extra
//! type scopes registered by the payload show up in the schema walk.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const CONFIG_NAME: &str = "cs2_dumper_shade.out";
const DLL_NAME: &str = "cs2_dumper_shade.dll";

#[cfg(windows)]
const EMBEDDED_SHADE_DLL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cs2_dumper_shade.dll"));

/// True when `--connector` names the shade inject backend.
pub fn is_shade_connector(name: Option<&str>) -> bool {
    name.is_some_and(|value| value.eq_ignore_ascii_case("shade"))
}

/// `LoadLibraryW` rejects `\\?\` extended paths. Keep the payload path as a
/// normal Win32 path even if a caller canonicalized it.
pub(crate) fn injectable_dll_path(path: &Path) -> PathBuf {
    const PREFIX: &str = r"\\?\";
    match path.to_str() {
        Some(s) if s.starts_with(PREFIX) => PathBuf::from(&s[PREFIX.len()..]),
        _ => path.to_path_buf(),
    }
}

pub(crate) fn parse_status_json(raw: &str) -> Result<ShadeReport, serde_json::Error> {
    serde_json::from_str(raw)
}

#[derive(Debug, Default, Deserialize)]
pub struct ShadeReport {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub schema_system: u64,
    #[serde(default)]
    pub bindings: Vec<String>,
    #[serde(default)]
    pub failed: Vec<(String, String)>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Write the embedded payload to a temp file so LoadLibrary can inject it.
/// The sidecar `.out` file is the status-path handshake used by the DLL.
#[cfg(windows)]
pub fn materialize_payload_dll() -> Result<PathBuf> {
    if EMBEDDED_SHADE_DLL.is_empty() {
        bail!("shade payload was not embedded in this build");
    }
    let dir = create_payload_dir()?;
    let path = dir.join(DLL_NAME);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, EMBEDDED_SHADE_DLL))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

/// Create a fresh directory for every injection so the payload and status
/// handshake do not use predictable shared paths in the temporary directory.
#[cfg(windows)]
fn create_payload_dir() -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir();
    for _ in 0..32 {
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = root.join(format!(
            "cs2-dumper-{}-{seed:X}-{serial:X}",
            std::process::id()
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to create {}", dir.display()))
            }
        }
    }
    bail!("failed to allocate a unique shade payload directory")
}

#[cfg(windows)]
pub fn inject_schema_bindings() -> Result<ShadeReport> {
    win::inject_schema_bindings()
}

#[cfg(not(windows))]
pub fn inject_schema_bindings() -> Result<ShadeReport> {
    bail!("-c shade is Windows-only")
}

#[cfg(windows)]
mod win {
    use super::*;
    use crate::memory::syscall;
    use crate::memory::win::{
        last_error, to_wide_path, CloseHandle, GetModuleHandleA, GetProcAddress, HandleGuard,
        OpenProcess,
    };
    use std::fs;
    use std::thread;
    use std::time::{Duration, Instant};

    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const LOAD_WAIT_MS: u32 = 30_000;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x102;

    unsafe extern "system" {
        fn VirtualAllocEx(
            process: *mut core::ffi::c_void,
            addr: *mut core::ffi::c_void,
            size: usize,
            alloc_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualFreeEx(
            process: *mut core::ffi::c_void,
            addr: *mut core::ffi::c_void,
            size: usize,
            free_type: u32,
        ) -> i32;
        fn WriteProcessMemory(
            process: *mut core::ffi::c_void,
            addr: *mut core::ffi::c_void,
            buf: *const core::ffi::c_void,
            size: usize,
            written: *mut usize,
        ) -> i32;
        fn CreateRemoteThread(
            process: *mut core::ffi::c_void,
            attr: *mut core::ffi::c_void,
            stack: usize,
            start: *const core::ffi::c_void,
            param: *mut core::ffi::c_void,
            flags: u32,
            tid: *mut u32,
        ) -> *mut core::ffi::c_void;
        fn WaitForSingleObject(handle: *mut core::ffi::c_void, ms: u32) -> u32;
        fn GetExitCodeThread(handle: *mut core::ffi::c_void, code: *mut u32) -> i32;
    }

    pub fn inject_schema_bindings() -> Result<ShadeReport> {
        let pid = syscall::find_process("cs2.exe").context("-c shade needs a live cs2.exe")?;
        let dll = super::injectable_dll_path(&super::materialize_payload_dll()?);
        let payload_dir = dll
            .parent()
            .context("shade payload has no parent directory")?;
        let status_path = payload_dir.join("status.json");

        let outcome = (|| {
            let _ = fs::remove_file(&status_path);
            let config = payload_dir.join(CONFIG_NAME);
            fs::write(&config, status_path.to_string_lossy().as_bytes())
                .with_context(|| format!("failed to write {}", config.display()))?;
            log::info!("shade: injecting {} into cs2.exe pid {pid}", dll.display());
            inject_load_library(pid, &dll)?;
            let report = wait_status(&status_path, Duration::from_secs(90))?;
            if !report.ok {
                bail!(
                    "shade payload failed: {}",
                    report.error.as_deref().unwrap_or("unknown error")
                );
            }
            if report.bindings.is_empty() {
                bail!("shade payload registered no schema modules");
            }
            Ok(report)
        })();
        // A timeout can leave LoadLibraryW or the payload thread still using
        // files from this directory.  Keep failed runs intact so cleanup
        // cannot race a remote thread; successful runs are safe to remove.
        if outcome.is_ok() {
            if let Err(err) = fs::remove_dir_all(payload_dir) {
                log::warn!(
                    "shade: completed, but failed to remove payload directory {}: {err}",
                    payload_dir.display()
                );
            }
        } else {
            log::warn!(
                "shade: preserving payload directory after failure: {}",
                payload_dir.display()
            );
        }
        outcome
    }

    fn inject_load_library(pid: u32, dll: &Path) -> Result<()> {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;
        let process_guard =
            HandleGuard::new(unsafe { OpenProcess(access, 0, pid) }).map_err(|_| {
                anyhow::anyhow!(
                    "OpenProcess(cs2.exe pid {pid}) for inject failed ({})",
                    last_error()
                )
            })?;
        let process = process_guard.get();
        let path = to_wide_path(dll);
        let bytes = path.len() * 2;
        let remote = unsafe {
            VirtualAllocEx(
                process,
                core::ptr::null_mut(),
                bytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote.is_null() {
            bail!("VirtualAllocEx(dll path) failed ({})", last_error());
        }
        let mut written = 0usize;
        let wrote = unsafe {
            WriteProcessMemory(process, remote, path.as_ptr().cast(), bytes, &mut written)
        };
        if wrote == 0 || written != bytes {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("WriteProcessMemory(dll path) failed ({})", last_error());
        }
        let kernel32 = unsafe { GetModuleHandleA(c"kernel32.dll".as_ptr()) };
        if kernel32.is_null() {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("GetModuleHandleA(kernel32.dll) failed");
        }
        let load_library = unsafe { GetProcAddress(kernel32, c"LoadLibraryW".as_ptr()) };
        if load_library.is_null() {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("GetProcAddress(LoadLibraryW) failed");
        }
        let thread = unsafe {
            CreateRemoteThread(
                process,
                core::ptr::null_mut(),
                0,
                load_library,
                remote,
                0,
                core::ptr::null_mut(),
            )
        };
        if thread.is_null() {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("CreateRemoteThread(LoadLibraryW) failed ({})", last_error());
        }
        let wait = unsafe { WaitForSingleObject(thread, LOAD_WAIT_MS) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                CloseHandle(thread);
            }
            if wait == WAIT_TIMEOUT {
                // The remote thread may still dereference `remote`; leaving
                // this allocation avoids freeing memory that is still in use.
                bail!("LoadLibraryW remote thread timed out after {LOAD_WAIT_MS} ms");
            }
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!(
                "WaitForSingleObject(LoadLibraryW) failed ({})",
                last_error()
            );
        }
        let mut exit_code = 0u32;
        let got_exit_code = unsafe { GetExitCodeThread(thread, &mut exit_code) };
        unsafe {
            CloseHandle(thread);
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        if got_exit_code == 0 {
            bail!("GetExitCodeThread(LoadLibraryW) failed ({})", last_error());
        }
        if exit_code == 0 {
            bail!("remote LoadLibraryW({}) returned NULL", dll.display());
        }
        Ok(())
    }

    fn wait_status(path: &Path, timeout: Duration) -> Result<ShadeReport> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(raw) = fs::read_to_string(path)
                && let Ok(report) = super::parse_status_json(&raw)
            {
                return Ok(report);
            }
            thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "timed out waiting for shade payload status at {}",
            path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_shade_connector_name() {
        assert!(is_shade_connector(Some("shade")));
        assert!(is_shade_connector(Some("SHADE")));
        assert!(!is_shade_connector(Some("syscall")));
        assert!(!is_shade_connector(None));
    }

    #[test]
    fn parses_payload_status_json() {
        let raw = r#"{
  "ok": true,
  "schema_system": 140737488355328,
  "bindings": ["client.dll", "vconcomm.dll"],
  "failed": [["foo.dll", "status 0x2"]],
  "error": null
}"#;
        let report = parse_status_json(raw).unwrap();
        assert!(report.ok);
        assert_eq!(report.schema_system, 140737488355328);
        assert_eq!(report.bindings, ["client.dll", "vconcomm.dll"]);
        assert_eq!(report.failed[0].0, "foo.dll");
        assert!(report.error.is_none());
    }

    #[test]
    fn truncated_status_json_is_retried_instead_of_a_hard_error() {
        let truncated = r#"{
  "ok": true,
  "schema_system": 140737488355328
"#;
        assert!(
            parse_status_json(truncated).is_err(),
            "incomplete status is not a report"
        );
        let hex = r#"{"ok":true,"schema_system":0x7ffd17ed5730,"bindings":[]}"#;
        assert!(
            parse_status_json(hex).is_err(),
            "0x-prefixed schema_system is not valid JSON"
        );
    }

    #[test]
    fn inject_path_strips_extended_prefix() {
        let extended =
            PathBuf::from(r"\\?\C:\Users\Admin\AppData\Local\Temp\cs2-dumper\cs2_dumper_shade.dll");
        let injected = injectable_dll_path(&extended);
        let text = injected.to_string_lossy();
        assert!(
            !text.starts_with(r"\\?\"),
            "LoadLibraryW path must not be extended: {text}"
        );
        assert!(text.ends_with(r"cs2_dumper_shade.dll"));
        assert_eq!(
            injectable_dll_path(Path::new(r"C:\temp\cs2_dumper_shade.dll")),
            PathBuf::from(r"C:\temp\cs2_dumper_shade.dll")
        );
    }

    #[cfg(windows)]
    #[test]
    fn embeds_a_nonempty_shade_payload() {
        assert!(
            EMBEDDED_SHADE_DLL.len() > 64,
            "embedded shade DLL should be a real PE, got {} bytes",
            EMBEDDED_SHADE_DLL.len()
        );
        assert_eq!(&EMBEDDED_SHADE_DLL[..2], b"MZ");
    }
}
