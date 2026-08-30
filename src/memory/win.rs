//! Shared Windows Toolhelp / handle helpers for the local, syscall, and shade backends.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Result, bail};
use memflow::prelude::v1::*;

pub const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
pub const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
pub const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
pub const MAX_PATH: usize = 260;
pub const MAX_MODULE_NAME32: usize = 255;
pub const PAGE: usize = 0x1000;

pub type Handle = *mut core::ffi::c_void;

#[repr(C)]
pub struct ProcessEntry32W {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: [u16; MAX_PATH],
}

#[repr(C)]
pub struct ModuleEntry32W {
    pub dw_size: u32,
    pub th32_module_id: u32,
    pub th32_process_id: u32,
    pub glbl_cnt_usage: u32,
    pub proc_cnt_usage: u32,
    pub mod_base_addr: *mut u8,
    pub mod_base_size: u32,
    pub h_module: Handle,
    pub sz_module: [u16; MAX_MODULE_NAME32 + 1],
    pub sz_exe_path: [u16; MAX_PATH],
}

unsafe extern "system" {
    pub fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    pub fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    pub fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
    pub fn Module32FirstW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    pub fn Module32NextW(snapshot: Handle, entry: *mut ModuleEntry32W) -> i32;
    pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    pub fn CloseHandle(handle: Handle) -> i32;
    pub fn GetCurrentProcess() -> Handle;
    pub fn GetCurrentProcessId() -> u32;
    pub fn ReadProcessMemory(
        process: Handle,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
    pub fn GetModuleHandleA(name: *const i8) -> Handle;
    pub fn GetProcAddress(module: Handle, name: *const i8) -> *const core::ffi::c_void;
    pub fn GetLastError() -> u32;
}

pub fn wchar_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

pub fn invalid_handle(handle: Handle) -> bool {
    handle.is_null() || handle == (-1isize as Handle)
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

pub fn to_wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub struct HandleGuard(Handle);

impl HandleGuard {
    pub fn new(handle: Handle) -> Result<Self> {
        if invalid_handle(handle) {
            bail!("invalid handle ({})", last_error());
        }
        Ok(Self(handle))
    }

    pub fn get(&self) -> Handle {
        self.0
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !invalid_handle(self.0) {
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

pub fn toolhelp_snapshot(flags: u32, pid: u32) -> Result<HandleGuard> {
    HandleGuard::new(unsafe { CreateToolhelp32Snapshot(flags, pid) }).map_err(|err| {
        anyhow::anyhow!("CreateToolhelp32Snapshot({flags:#x}, pid {pid}) failed: {err}")
    })
}

pub fn find_pid(process_name: &str) -> Result<u32> {
    let snap = toolhelp_snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut entry = ProcessEntry32W {
        dw_size: u32::try_from(std::mem::size_of::<ProcessEntry32W>()).unwrap_or(u32::MAX),
        cnt_usage: 0,
        th32_process_id: 0,
        th32_default_heap_id: 0,
        th32_module_id: 0,
        cnt_threads: 0,
        th32_parent_process_id: 0,
        pc_pri_class_base: 0,
        dw_flags: 0,
        sz_exe_file: [0; MAX_PATH],
    };
    if unsafe { Process32FirstW(snap.get(), &mut entry) } == 0 {
        bail!("Process32FirstW failed ({})", last_error());
    }
    loop {
        if wchar_to_string(&entry.sz_exe_file).eq_ignore_ascii_case(process_name) {
            return Ok(entry.th32_process_id);
        }
        if unsafe { Process32NextW(snap.get(), &mut entry) } == 0 {
            break;
        }
    }
    bail!("{process_name} is not running")
}

pub fn enumerate_modules(
    pid: u32,
    parent: Address,
    arch: ArchitectureIdent,
) -> Result<Vec<ModuleInfo>> {
    let snap = toolhelp_snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
    let mut entry = unsafe { std::mem::zeroed::<ModuleEntry32W>() };
    entry.dw_size = u32::try_from(std::mem::size_of::<ModuleEntry32W>()).unwrap_or(u32::MAX);
    if unsafe { Module32FirstW(snap.get(), &mut entry) } == 0 {
        bail!("Module32FirstW(pid {pid}) failed ({})", last_error());
    }
    let mut modules = Vec::new();
    loop {
        let name = wchar_to_string(&entry.sz_module);
        let path = wchar_to_string(&entry.sz_exe_path);
        let base = entry.mod_base_addr as umem;
        if base == 0 || entry.mod_base_size == 0 || name.is_empty() {
            if unsafe { Module32NextW(snap.get(), &mut entry) } == 0 {
                break;
            }
            continue;
        }
        modules.push(ModuleInfo {
            address: Address::from(base),
            parent_process: parent,
            base: Address::from(base),
            size: entry.mod_base_size as umem,
            name: name.into(),
            path: path.into(),
            arch,
        });
        if unsafe { Module32NextW(snap.get(), &mut entry) } == 0 {
            break;
        }
    }
    if modules.is_empty() {
        bail!("no modules enumerated for pid {pid}");
    }
    Ok(modules)
}
