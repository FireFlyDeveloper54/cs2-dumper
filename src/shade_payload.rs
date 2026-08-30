//! Injected into `cs2.exe` by `-c shade`.
//!
//! Enumerates loaded modules that export `InstallSchemaBindings`, resolves
//! `SchemaSystem_001`, and calls the export so scopes that the game has not
//! registered yet show up in the host dump. Writes a status JSON and unloads.

#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(linker_messages)]
#[cfg(not(windows))]
compile_error!("cs2-dumper-shade supports Windows only");
#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("cs2-dumper-shade requires the x86_64 Windows target");

use std::fs;
use std::path::{Path, PathBuf};

const DLL_PROCESS_ATTACH: u32 = 1;
const SCHEMA_BINDINGS_OK: usize = 0xC000_0001;
const MAX_PATH: usize = 260;
const MAX_MODULE_NAME32: usize = 255;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
const CONFIG_NAME: &str = "cs2_dumper_shade.out";

type Handle = *mut core::ffi::c_void;
type CreateInterfaceFn = unsafe extern "C" fn(*const i8, *mut i32) -> Handle;
type InstallSchemaBindingsFn = unsafe extern "C" fn(*const i8, Handle) -> usize;
type ThreadStart = unsafe extern "system" fn(Handle) -> u32;

#[repr(C)]
struct ModuleEntry32W {
    dw_size: u32,
    th32_module_id: u32,
    th32_process_id: u32,
    glbl_cnt_usage: u32,
    proc_cnt_usage: u32,
    mod_base_addr: *mut u8,
    mod_base_size: u32,
    h_module: Handle,
    sz_module: [u16; MAX_MODULE_NAME32 + 1],
    sz_exe_path: [u16; MAX_PATH],
}

unsafe extern "system" {
    fn DisableThreadLibraryCalls(module: Handle) -> i32;
    fn CreateThread(
        attr: Handle,
        stack: usize,
        start: ThreadStart,
        param: Handle,
        flags: u32,
        tid: *mut u32,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetModuleHandleA(name: *const i8) -> Handle;
    fn GetProcAddress(module: Handle, name: *const i8) -> *const core::ffi::c_void;
    fn GetModuleFileNameW(module: Handle, buf: *mut u16, size: u32) -> u32;
    fn GetCurrentProcessId() -> u32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    fn FreeLibraryAndExitThread(module: Handle, code: u32) -> !;
}

/// Windows loader entry. Spawns the schema-registration worker on attach
/// and always returns success so `LoadLibraryW` does not fail the host.
///
/// # Safety
/// `module` must be this DLL's `HMODULE`. `reason` is a `DLL_*` code from
/// the loader. Only the Windows loader may call this.
#[no_mangle]
pub unsafe extern "system" fn DllMain(module: Handle, reason: u32, _reserved: Handle) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(module);
        }
        let thread = unsafe {
            CreateThread(
                core::ptr::null_mut(),
                0,
                on_attach,
                module,
                0,
                core::ptr::null_mut(),
            )
        };
        if !thread.is_null() {
            unsafe {
                CloseHandle(thread);
            }
        }
    }
    1
}

unsafe extern "system" fn on_attach(module: Handle) -> u32 {
    let status_path = status_path_from_module(module);
    let result = std::panic::catch_unwind(register_schema);
    match result {
        Ok(Ok(report)) => write_status(&status_path, true, &report, None),
        Ok(Err(err)) => write_status(&status_path, false, &Report::default(), Some(&err)),
        Err(_) => write_status(
            &status_path,
            false,
            &Report::default(),
            Some("payload panicked"),
        ),
    }
    unsafe {
        FreeLibraryAndExitThread(module, 0);
    }
}

#[derive(Default)]
struct Report {
    schema_system: u64,
    bindings: Vec<String>,
    failed: Vec<(String, String)>,
}

fn register_schema() -> Result<Report, String> {
    let schema_dll = load_mod(c"schemasystem.dll")?;
    let create: CreateInterfaceFn = export(schema_dll, c"CreateInterface")
        .ok_or_else(|| "schemasystem.dll has no CreateInterface".to_string())?;
    let schema_system = unsafe { create(c"SchemaSystem_001".as_ptr(), core::ptr::null_mut()) };
    if schema_system.is_null() {
        return Err("CreateInterface(SchemaSystem_001) returned null".into());
    }
    let mut report = Report {
        schema_system: schema_system as u64,
        ..Report::default()
    };
    for (name, handle) in process_modules() {
        if name.eq_ignore_ascii_case("cs2_dumper_shade.dll") {
            continue;
        }
        let Some(install): Option<InstallSchemaBindingsFn> =
            export(handle, c"InstallSchemaBindings")
        else {
            continue;
        };
        let status = unsafe { install(c"SchemaSystem_001".as_ptr(), schema_system) };
        if status == SCHEMA_BINDINGS_OK || status == 0 {
            report.bindings.push(name);
        } else {
            report
                .failed
                .push((name, format!("InstallSchemaBindings status {status:#X}")));
        }
    }
    if report.bindings.is_empty() {
        return Err("no InstallSchemaBindings calls succeeded".into());
    }
    Ok(report)
}

fn load_mod(name: &std::ffi::CStr) -> Result<Handle, String> {
    let handle = unsafe { GetModuleHandleA(name.as_ptr()) };
    if handle.is_null() {
        Err(format!(
            "GetModuleHandleA({}) failed",
            name.to_string_lossy()
        ))
    } else {
        Ok(handle)
    }
}

fn export<T>(module: Handle, name: &std::ffi::CStr) -> Option<T> {
    let ptr = unsafe { GetProcAddress(module, name.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute_copy(&ptr) })
    }
}

fn process_modules() -> Vec<(String, Handle)> {
    let pid = unsafe { GetCurrentProcessId() };
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snap.is_null() || snap == (-1isize as Handle) {
        return Vec::new();
    }
    let mut entry = unsafe { std::mem::zeroed::<ModuleEntry32W>() };
    entry.dw_size = u32::try_from(std::mem::size_of::<ModuleEntry32W>()).unwrap_or(u32::MAX);
    let mut modules = Vec::new();
    unsafe {
        if Module32FirstW(snap, &raw mut entry) != 0 {
            loop {
                modules.push((wchar_to_string(&entry.sz_module), entry.h_module));
                if Module32NextW(snap, &raw mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    modules
}

fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn status_path_from_module(module: Handle) -> PathBuf {
    let mut buf = [0u16; MAX_PATH];
    let n = unsafe {
        GetModuleFileNameW(
            module,
            buf.as_mut_ptr(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
    } as usize;
    let dll = PathBuf::from(wchar_to_string(&buf[..n.min(MAX_PATH)]));
    let dir = dll.parent().unwrap_or_else(|| Path::new("."));
    let config = dir.join(CONFIG_NAME);
    if let Ok(text) = fs::read_to_string(&config) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dir.join("cs2_dumper_shade.status.json")
}

fn json_escape(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn write_status(path: &Path, ok: bool, report: &Report, error: Option<&str>) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = format_status_json(ok, report, error);
    let _ = fs::write(path, json);
}

fn format_status_json(ok: bool, report: &Report, error: Option<&str>) -> String {
    let mut json = String::from("{\n");
    json.push_str(&format!(
        "  \"ok\": {},\n",
        if ok { "true" } else { "false" }
    ));
    json.push_str(&format!("  \"schema_system\": {},\n", report.schema_system));
    json.push_str("  \"bindings\": [");
    for (i, name) in report.bindings.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!("\"{}\"", json_escape(name)));
    }
    json.push_str("],\n  \"failed\": [");
    for (i, (name, err)) in report.failed.iter().enumerate() {
        if i > 0 {
            json.push_str(", ");
        }
        json.push_str(&format!(
            "[\"{}\", \"{}\"]",
            json_escape(name),
            json_escape(err)
        ));
    }
    json.push_str("],\n  \"error\": ");
    match error {
        Some(err) => json.push_str(&format!("\"{}\"", json_escape(err))),
        None => json.push_str("null"),
    }
    json.push_str("\n}\n");
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_json_uses_a_decimal_schema_system_number() {
        let report = Report {
            schema_system: 0x7FFD_17ED_5730,
            bindings: vec!["client.dll".into()],
            failed: Vec::new(),
        };
        let json = format_status_json(true, &report, None);
        assert!(
            json.contains("\"schema_system\": 140725004883760"),
            "payload must emit a JSON number, not 0x...: {json}"
        );
        assert!(!json.contains("0x"));
        assert!(json.contains("\"ok\": true"));
    }

    #[test]
    fn status_json_escapes_all_control_characters() {
        let report = Report {
            bindings: vec!["module\r\n\t\u{0001}".into()],
            failed: vec![("bad\u{000B}module".into(), "err\u{000C}".into())],
            ..Report::default()
        };
        let json = format_status_json(false, &report, Some("fatal\u{0000}"));
        assert!(!json.chars().any(|ch| matches!(
            ch,
            '\r' | '\t' | '\u{0001}' | '\u{000B}' | '\u{000C}' | '\0'
        )));
        assert!(json.contains("\\r\\n\\t\\u0001"));
        assert!(json.contains("\\u000B"));
        assert!(json.contains("\\f"));
        assert!(json.contains("\\u0000"));
        assert!(json.contains("\"ok\": false"));
    }
}
