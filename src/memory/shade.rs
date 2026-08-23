//! Optional `-c shade` backend: inject a payload DLL into live `cs2.exe`.
//!
//! The payload (shade-dumper's in-process trick) enumerates modules that
//! export `InstallSchemaBindings` and calls them against `SchemaSystem_001`.
//! The host then attaches with memflow native and dumps as usual — extra
//! type scopes registered by the payload show up in the schema walk.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const CONFIG_NAME: &str = "cs2_dumper_shade.out";
const DLL_NAME: &str = "cs2_dumper_shade.dll";

#[cfg(windows)]
const EMBEDDED_SHADE_DLL: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/cs2_dumper_shade.dll"));

/// True when `--connector` names the shade inject backend.
pub fn is_shade_connector(name: Option<&str>) -> bool {
    name.is_some_and(|value| value.eq_ignore_ascii_case("shade"))
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
    let dir = std::env::temp_dir().join("cs2-dumper");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(DLL_NAME);
    std::fs::write(&path, EMBEDDED_SHADE_DLL)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
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
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
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
    const INFINITE_WAIT: u32 = 0xFFFF_FFFF;

    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
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
        fn GetModuleHandleA(name: *const i8) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            module: *mut core::ffi::c_void,
            name: *const i8,
        ) -> *const core::ffi::c_void;
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
        fn GetLastError() -> u32;
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn inject_schema_bindings() -> Result<ShadeReport> {
        let pid = syscall::find_process("cs2.exe")
            .context("-c shade needs a live cs2.exe")?;
        let dll = super::materialize_payload_dll()?.canonicalize()?;
        let status_path = std::env::temp_dir().join(format!("cs2-dumper-shade-{pid}.json"));
        let _ = fs::remove_file(&status_path);
        let config = dll
            .parent()
            .map(|dir| dir.join(CONFIG_NAME))
            .context("shade payload has no parent directory")?;
        fs::write(&config, status_path.to_string_lossy().as_bytes())
            .with_context(|| format!("failed to write {}", config.display()))?;

        log::info!("shade: injecting {} into cs2.exe pid {pid}", dll.display());
        inject_load_library(pid, &dll)?;
        let report = wait_status(&status_path, Duration::from_secs(90))?;
        let _ = fs::remove_file(&config);
        let _ = fs::remove_file(&dll);
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
    }

    fn inject_load_library(pid: u32, dll: &Path) -> Result<()> {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;
        let process = unsafe { OpenProcess(access, 0, pid) };
        if process.is_null() {
            bail!(
                "OpenProcess(cs2.exe pid {pid}) for inject failed ({})",
                unsafe { GetLastError() }
            );
        }
        struct Close(*mut core::ffi::c_void);
        impl Drop for Close {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _proc = Close(process);
        let path = wide(dll);
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
            bail!("VirtualAllocEx(dll path) failed ({})", unsafe { GetLastError() });
        }
        let mut written = 0usize;
        let wrote = unsafe {
            WriteProcessMemory(
                process,
                remote,
                path.as_ptr().cast(),
                bytes,
                &mut written,
            )
        };
        if wrote == 0 || written != bytes {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("WriteProcessMemory(dll path) failed ({})", unsafe { GetLastError() });
        }
        let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr().cast()) };
        if kernel32.is_null() {
            unsafe {
                VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            }
            bail!("GetModuleHandleA(kernel32.dll) failed");
        }
        let load_library = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr().cast()) };
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
            bail!(
                "CreateRemoteThread(LoadLibraryW) failed ({})",
                unsafe { GetLastError() }
            );
        }
        unsafe {
            WaitForSingleObject(thread, INFINITE_WAIT);
            CloseHandle(thread);
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        Ok(())
    }

    fn wait_status(path: &Path, timeout: Duration) -> Result<ShadeReport> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(raw) = fs::read_to_string(path) {
                if raw.contains("\"ok\"") {
                    return serde_json::from_str(&raw)
                        .with_context(|| format!("invalid shade status {}", path.display()));
                }
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
        let report: ShadeReport = serde_json::from_str(raw).unwrap();
        assert!(report.ok);
        assert_eq!(report.bindings, ["client.dll", "vconcomm.dll"]);
        assert_eq!(report.failed[0].0, "foo.dll");
        assert!(report.error.is_none());
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
