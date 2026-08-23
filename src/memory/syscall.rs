//! Optional Windows backend: open `cs2.exe` and read it with a local
//! `NtReadVirtualMemory` syscall stub (from cs2-best-dumper).
//!
//! Default attach is still memflow native. This path is selected with
//! `-c syscall` and requires a live game process — it does not LoadLibrary.

use anyhow::Result;

/// True when `--connector` names this backend rather than a memflow plugin.
pub fn is_syscall_connector(name: Option<&str>) -> bool {
    name.is_some_and(|value| value.eq_ignore_ascii_case("syscall"))
}

/// Hell's Gate: `mov r10, rcx; mov eax, SSN` at the start of an ntdll stub.
pub fn extract_ssn(stub: &[u8]) -> Option<u32> {
    if stub.len() >= 8
        && stub[0] == 0x4C
        && stub[1] == 0x8B
        && stub[2] == 0xD1
        && stub[3] == 0xB8
    {
        return Some(u32::from_le_bytes(stub[4..8].try_into().ok()?));
    }
    for i in 0..stub.len().saturating_sub(5) {
        if stub[i] == 0xB8 {
            return Some(u32::from_le_bytes(stub[i + 1..i + 5].try_into().ok()?));
        }
        if stub[i] == 0x0F && stub.get(i + 1) == Some(&0x05) {
            break;
        }
    }
    None
}

/// Recover an SSN from a window of neighboring ntdll stubs (`stride` bytes
/// each). `center_index` is the hooked export; a clean neighbour at ±i has
/// SSN = ours ± i.
pub fn ssn_from_ntdll_window(window: &[u8], center_index: usize, stride: usize) -> Option<u32> {
    if stride < 8 {
        return None;
    }
    let center = center_index.checked_mul(stride)?;
    if center < window.len() {
        let end = (center + stride).min(window.len());
        if let Some(ssn) = extract_ssn(&window[center..end]) {
            return Some(ssn);
        }
    }
    for i in 1..=16isize {
        for sign in [1isize, -1] {
            let idx = center_index as isize + sign * i;
            if idx < 0 {
                continue;
            }
            let off = idx as usize * stride;
            if off + 8 > window.len() {
                continue;
            }
            let end = (off + stride).min(window.len());
            if let Some(neigh) = extract_ssn(&window[off..end]) {
                return Some(neigh.wrapping_add_signed((-sign * i) as i32));
            }
        }
    }
    None
}

#[cfg(windows)]
mod win {
    use super::ssn_from_ntdll_window;
    use anyhow::{Context, Result, bail};
    use memflow::cglue::{CTup2, CTup3};
    use memflow::mem::mem_data::{MemOps, ReadRawMemOps, WriteRawMemOps, opt_call};
    use memflow::prelude::v1::*;
    use std::slice;

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
    const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const MAX_PATH: usize = 260;
    const MAX_MODULE_NAME32: usize = 255;
    const PAGE: usize = 0x1000;
    const STUB_STRIDE: usize = 32;
    const NEIGHBOR_RADIUS: usize = 16;

    type Handle = isize;

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    struct ModuleEntry32W {
        dw_size: u32,
        th32_module_id: u32,
        th32_process_id: u32,
        glbl_cnt_usage: u32,
        proc_cnt_usage: u32,
        mod_base_addr: *mut u8,
        mod_base_size: u32,
        h_module: *mut core::ffi::c_void,
        sz_module: [u16; MAX_MODULE_NAME32 + 1],
        sz_exe_path: [u16; MAX_PATH],
    }

    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut core::ffi::c_void;
        fn Process32FirstW(snapshot: *mut core::ffi::c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut core::ffi::c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Module32FirstW(snapshot: *mut core::ffi::c_void, entry: *mut ModuleEntry32W) -> i32;
        fn Module32NextW(snapshot: *mut core::ffi::c_void, entry: *mut ModuleEntry32W) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
        fn VirtualAlloc(
            addr: *mut core::ffi::c_void,
            size: usize,
            alloc_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualFree(addr: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
        fn GetModuleHandleA(name: *const i8) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            module: *mut core::ffi::c_void,
            name: *const i8,
        ) -> *const core::ffi::c_void;
        fn GetLastError() -> u32;
    }

    type NtReadVirtualMemory = unsafe extern "system" fn(
        process: *mut core::ffi::c_void,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;

    fn wchar_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn invalid_handle(handle: *mut core::ffi::c_void) -> bool {
        handle.is_null() || handle == (-1isize as *mut core::ffi::c_void)
    }

    fn ntdll_ssn(export: &str) -> Result<u32> {
        let mut name = export.as_bytes().to_vec();
        name.push(0);
        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr().cast());
            if ntdll.is_null() {
                bail!("GetModuleHandleA(ntdll.dll) failed");
            }
            let proc = GetProcAddress(ntdll, name.as_ptr().cast());
            if proc.is_null() {
                bail!("ntdll export {export} not found");
            }
            let proc = proc.cast::<u8>();
            let start = proc.sub(NEIGHBOR_RADIUS * STUB_STRIDE);
            let window = slice::from_raw_parts(start, (NEIGHBOR_RADIUS * 2 + 1) * STUB_STRIDE);
            ssn_from_ntdll_window(window, NEIGHBOR_RADIUS, STUB_STRIDE)
                .with_context(|| format!("failed to extract SSN for {export}"))
        }
    }

    fn emit_syscall_stub(ssn: u32) -> Result<(usize, usize)> {
        unsafe {
            let page = VirtualAlloc(
                core::ptr::null_mut(),
                PAGE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if page.is_null() {
                bail!("VirtualAlloc(syscall stub) failed ({})", GetLastError());
            }
            let bytes = page as *mut u8;
            *bytes.add(0) = 0x4C;
            *bytes.add(1) = 0x8B;
            *bytes.add(2) = 0xD1;
            *bytes.add(3) = 0xB8;
            bytes.add(4).cast::<u32>().write_unaligned(ssn);
            *bytes.add(8) = 0x0F;
            *bytes.add(9) = 0x05;
            *bytes.add(10) = 0xC3;
            Ok((page as usize, bytes as usize))
        }
    }

    pub(super) fn find_pid(process_name: &str) -> Result<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if invalid_handle(snap) {
                bail!("CreateToolhelp32Snapshot(process) failed ({})", GetLastError());
            }
            struct Close(*mut core::ffi::c_void);
            impl Drop for Close {
                fn drop(&mut self) {
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
            let _guard = Close(snap);
            let mut entry = ProcessEntry32W {
                dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
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
            if Process32FirstW(snap, &mut entry) == 0 {
                bail!("Process32FirstW failed ({})", GetLastError());
            }
            loop {
                let name = wchar_to_string(&entry.sz_exe_file);
                if name.eq_ignore_ascii_case(process_name) {
                    return Ok(entry.th32_process_id);
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        bail!("{process_name} is not running")
    }

    fn enumerate_modules(pid: u32, parent: Address, arch: ArchitectureIdent) -> Result<Vec<ModuleInfo>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if invalid_handle(snap) {
                bail!(
                    "CreateToolhelp32Snapshot(module) failed ({}) — try running elevated",
                    GetLastError()
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
            let _guard = Close(snap);
            let mut entry = std::mem::zeroed::<ModuleEntry32W>();
            entry.dw_size = std::mem::size_of::<ModuleEntry32W>() as u32;
            if Module32FirstW(snap, &mut entry) == 0 {
                bail!("Module32FirstW failed ({})", GetLastError());
            }
            let mut modules = Vec::new();
            loop {
                let name = wchar_to_string(&entry.sz_module);
                let path = wchar_to_string(&entry.sz_exe_path);
                let base = entry.mod_base_addr as umem;
                modules.push(ModuleInfo {
                    address: Address::from(base),
                    parent_process: parent,
                    base: Address::from(base),
                    size: entry.mod_base_size as umem,
                    name: name.into(),
                    path: path.into(),
                    arch,
                });
                if Module32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
            if modules.is_empty() {
                bail!("no modules enumerated for pid {pid}");
            }
            Ok(modules)
        }
    }

    pub struct SyscallProcess {
        handle: Handle,
        stub_page: usize,
        stub: usize,
        info: ProcessInfo,
        modules: Vec<ModuleInfo>,
    }

    impl SyscallProcess {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> bool {
            if buf.is_empty() {
                return true;
            }
            let read_vm: NtReadVirtualMemory = unsafe { std::mem::transmute(self.stub) };
            let handle = self.handle as *mut core::ffi::c_void;
            let mut off = 0usize;
            let mut any = false;
            while off < buf.len() {
                let next_page = PAGE - ((addr as usize + off) % PAGE);
                let chunk = next_page.min(buf.len() - off);
                let mut n = 0usize;
                let status = unsafe {
                    read_vm(
                        handle,
                        (addr as usize + off) as *const core::ffi::c_void,
                        buf[off..off + chunk].as_mut_ptr() as *mut core::ffi::c_void,
                        chunk,
                        &mut n,
                    )
                };
                if n > 0 {
                    off += n;
                    any = true;
                    continue;
                }
                if status >= 0 && n == 0 {
                    break;
                }
                buf[off..off + chunk].fill(0);
                off += chunk;
            }
            any
        }
    }

    impl Drop for SyscallProcess {
        fn drop(&mut self) {
            unsafe {
                if self.stub_page != 0 {
                    VirtualFree(self.stub_page as *mut core::ffi::c_void, 0, MEM_RELEASE);
                    self.stub_page = 0;
                    self.stub = 0;
                }
                if self.handle != 0 {
                    CloseHandle(self.handle as *mut core::ffi::c_void);
                    self.handle = 0;
                }
            }
        }
    }

    impl MemoryView for SyscallProcess {
        fn read_raw_iter(
            &mut self,
            MemOps {
                inp,
                mut out,
                mut out_fail,
            }: ReadRawMemOps,
        ) -> memflow::error::Result<()> {
            for CTup3(addr, meta, mut data) in inp {
                if self.read_bytes(addr.to_umem(), &mut data) {
                    opt_call(out.as_deref_mut(), CTup2(meta, data));
                } else {
                    opt_call(out_fail.as_deref_mut(), CTup2(meta, data));
                }
            }
            Ok(())
        }

        fn write_raw_iter(
            &mut self,
            MemOps {
                inp,
                out: _out,
                mut out_fail,
            }: WriteRawMemOps,
        ) -> memflow::error::Result<()> {
            for CTup3(_addr, meta, data) in inp {
                opt_call(out_fail.as_deref_mut(), CTup2(meta, data));
            }
            Ok(())
        }

        fn metadata(&self) -> MemoryViewMetadata {
            MemoryViewMetadata {
                max_address: Address::from(u64::MAX),
                real_size: 0,
                readonly: true,
                little_endian: true,
                arch_bits: 64,
            }
        }
    }

    impl Process for SyscallProcess {
        fn state(&mut self) -> ProcessState {
            ProcessState::Alive
        }

        fn set_dtb(&mut self, _dtb1: Address, _dtb2: Address) -> memflow::error::Result<()> {
            Ok(())
        }

        fn module_address_list_callback(
            &mut self,
            target_arch: Option<&ArchitectureIdent>,
            callback: ModuleAddressCallback,
        ) -> memflow::error::Result<()> {
            self.modules
                .iter()
                .filter(|m| target_arch.is_none() || Some(&m.arch) == target_arch)
                .map(|m| ModuleAddressInfo {
                    address: m.address,
                    arch: m.arch,
                })
                .feed_into(callback);
            Ok(())
        }

        fn module_by_address(
            &mut self,
            address: Address,
            architecture: ArchitectureIdent,
        ) -> memflow::error::Result<ModuleInfo> {
            self.modules
                .iter()
                .find(|m| m.address == address && m.arch == architecture)
                .cloned()
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
        }

        fn module_by_name(&mut self, name: &str) -> memflow::error::Result<ModuleInfo> {
            self.modules
                .iter()
                .find(|m| m.name.as_ref().eq_ignore_ascii_case(name))
                .cloned()
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
        }

        fn primary_module_address(&mut self) -> memflow::error::Result<Address> {
            self.modules
                .iter()
                .find(|m| m.name.as_ref().eq_ignore_ascii_case(&self.info.name))
                .or_else(|| self.modules.first())
                .map(|m| m.address)
                .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
        }

        fn module_import_list_callback(
            &mut self,
            info: &ModuleInfo,
            callback: ImportCallback,
        ) -> memflow::error::Result<()> {
            memflow::os::util::module_import_list_callback(self, info, callback)
        }

        fn module_export_list_callback(
            &mut self,
            info: &ModuleInfo,
            callback: ExportCallback,
        ) -> memflow::error::Result<()> {
            memflow::os::util::module_export_list_callback(self, info, callback)
        }

        fn module_section_list_callback(
            &mut self,
            info: &ModuleInfo,
            callback: SectionCallback,
        ) -> memflow::error::Result<()> {
            memflow::os::util::module_section_list_callback(self, info, callback)
        }

        fn info(&self) -> &ProcessInfo {
            &self.info
        }

        fn mapped_mem_range(
            &mut self,
            _gap_size: imem,
            start: Address,
            end: Address,
            out: MemoryRangeCallback,
        ) {
            self.modules
                .iter()
                .filter(|m| {
                    m.base >= start && (end.is_null() || end == Address::INVALID || m.base < end)
                })
                .map(|m| CTup3(m.base, m.size, PageType::UNKNOWN))
                .feed_into(out);
        }
    }

    pub fn attach(process_name: &str) -> Result<SyscallProcess> {
        let ssn = ntdll_ssn("NtReadVirtualMemory")?;
        log::info!("syscall backend: NtReadVirtualMemory SSN {ssn:#x}");
        let pid = find_pid(process_name)?;
        let handle = unsafe {
            OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid)
        };
        if handle.is_null() {
            bail!(
                "OpenProcess({process_name} pid {pid}) failed ({}) — PROCESS_VM_READ denied",
                unsafe { GetLastError() }
            );
        }
        let arch = ArchitectureIdent::X86(64, false);
        let parent = Address::from(pid as umem);
        let modules = match enumerate_modules(pid, parent, arch) {
            Ok(modules) => modules,
            Err(err) => {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(err);
            }
        };
        let exe_path = modules
            .iter()
            .find(|m| m.name.as_ref().eq_ignore_ascii_case(process_name))
            .map(|m| m.path.to_string())
            .unwrap_or_default();
        let (stub_page, stub) = match emit_syscall_stub(ssn) {
            Ok(pair) => pair,
            Err(err) => {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(err);
            }
        };
        log::info!(
            "syscall backend attached to {process_name} pid {pid} ({} modules)",
            modules.len()
        );
        Ok(SyscallProcess {
            handle: handle as Handle,
            stub_page,
            stub,
            info: ProcessInfo {
                address: parent,
                pid,
                state: ProcessState::Alive,
                name: process_name.into(),
                path: exe_path.into(),
                command_line: "".into(),
                sys_arch: arch,
                proc_arch: arch,
                dtb1: Address::INVALID,
                dtb2: Address::INVALID,
            },
            modules,
        })
    }
}

#[cfg(windows)]
pub fn find_process(name: &str) -> Result<u32> {
    win::find_pid(name)
}

#[cfg(windows)]
pub use win::attach;

#[cfg(not(windows))]
pub fn attach(_process_name: &str) -> Result<std::convert::Infallible> {
    bail!("-c syscall is Windows-only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_syscall_connector_name() {
        assert!(is_syscall_connector(Some("syscall")));
        assert!(is_syscall_connector(Some("SYSCALL")));
        assert!(!is_syscall_connector(Some("pcileech")));
        assert!(!is_syscall_connector(None));
    }

    #[test]
    fn extracts_classic_ntdll_stub_ssn() {
        let stub = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x3F, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ];
        assert_eq!(extract_ssn(&stub), Some(0x3F));
    }

    #[test]
    fn hooked_export_recovers_ssn_from_next_stub() {
        let stride = 32usize;
        let mut window = vec![0xE9u8; stride * 3];
        let neighbor = [
            0x4C, 0x8B, 0xD1, 0xB8, 0x40, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3,
        ];
        window[stride * 2..stride * 2 + neighbor.len()].copy_from_slice(&neighbor);
        assert_eq!(ssn_from_ntdll_window(&window, 1, stride), Some(0x3F));
    }
}
