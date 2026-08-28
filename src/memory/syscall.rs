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
    if stub.len() >= 8 && stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
        return Some(u32::from_le_bytes(stub[4..8].try_into().ok()?));
    }
    // A fallback `mov eax, imm32` is exactly five bytes long. `0..=len - 5`
    // written with a saturating subtraction would be `0..=0` — one iteration,
    // not none — for every buffer shorter than that, so the length is checked
    // up front instead.
    if stub.len() < 5 {
        return None;
    }
    for i in 0..=stub.len() - 5 {
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
    // The neighbour search uses signed offsets; reject an index that cannot
    // be represented without wrapping before doing any arithmetic.
    if center_index > isize::MAX as usize {
        return None;
    }
    let center = center_index.checked_mul(stride)?;
    if center < window.len() {
        let end = center.checked_add(stride)?.min(window.len());
        if let Some(ssn) = extract_ssn(&window[center..end]) {
            return Some(ssn);
        }
    }
    for i in 1..=16isize {
        for sign in [1isize, -1] {
            let delta = sign.checked_mul(i)?;
            let idx = (center_index as isize).checked_add(delta)?;
            if idx < 0 {
                continue;
            }
            let off = (idx as usize).checked_mul(stride)?;
            let Some(min_end) = off.checked_add(8) else {
                continue;
            };
            if min_end > window.len() {
                continue;
            }
            let end = off.checked_add(stride)?.min(window.len());
            if let Some(neigh) = extract_ssn(&window[off..end])
                && let Some(ssn) = neigh.checked_add_signed((-sign * i) as i32)
            {
                return Some(ssn);
            }
        }
    }
    None
}

#[cfg(windows)]
mod win {
    use super::ssn_from_ntdll_window;
    use anyhow::{bail, Context, Result};
    use memflow::cglue::{CTup2, CTup3};
    use memflow::mem::mem_data::{opt_call, MemOps, ReadRawMemOps, WriteRawMemOps};
    use memflow::prelude::v1::*;
    use std::slice;

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_GUARD: u32 = 0x100;
    const STUB_STRIDE: usize = 32;
    const NEIGHBOR_RADIUS: usize = 16;

    use crate::memory::snapshot::{self, ProcessSnapshot};
    use crate::memory::win::{
        enumerate_modules, find_pid, last_error, CloseHandle, GetModuleHandleA, GetProcAddress,
        OpenProcess, PAGE,
    };

    type Handle = isize;

    fn is_readable_protection(protect: u32) -> bool {
        if protect & PAGE_GUARD != 0 {
            return false;
        }
        matches!(protect & 0xff, 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80)
    }

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut core::ffi::c_void,
        allocation_base: *mut core::ffi::c_void,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    unsafe extern "system" {
        fn VirtualAlloc(
            addr: *mut core::ffi::c_void,
            size: usize,
            alloc_type: u32,
            protect: u32,
        ) -> *mut core::ffi::c_void;
        fn VirtualFree(addr: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
        fn VirtualQuery(
            address: *const core::ffi::c_void,
            buffer: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
    }

    type NtReadVirtualMemory = unsafe extern "system" fn(
        process: *mut core::ffi::c_void,
        base: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;

    fn ntdll_ssn(export: &str) -> Result<u32> {
        let mut name = export.as_bytes().to_vec();
        name.push(0);
        unsafe {
            let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr());
            if ntdll.is_null() {
                bail!("GetModuleHandleA(ntdll.dll) failed");
            }
            let proc = GetProcAddress(ntdll, name.as_ptr().cast());
            if proc.is_null() {
                bail!("ntdll export {export} not found");
            }
            let proc = proc.cast::<u8>();
            let window_len = (NEIGHBOR_RADIUS * 2 + 1) * STUB_STRIDE;
            let start = (proc as usize)
                .checked_sub(NEIGHBOR_RADIUS * STUB_STRIDE)
                .context("ntdll export is too close to the address-space start")?;
            let end = start
                .checked_add(window_len)
                .context("ntdll SSN scan window overflowed")?;
            let mut memory = std::mem::zeroed::<MemoryBasicInformation>();
            if VirtualQuery(
                start as *const core::ffi::c_void,
                &mut memory,
                std::mem::size_of::<MemoryBasicInformation>(),
            ) == 0
            {
                bail!(
                    "VirtualQuery(ntdll SSN scan window) failed ({})",
                    last_error()
                );
            }
            let memory_end = (memory.base_address as usize)
                .checked_add(memory.region_size)
                .context("ntdll memory region overflowed")?;
            let readable = is_readable_protection(memory.protect);
            if memory.state != MEM_COMMIT
                || memory.allocation_base != ntdll
                || !readable
                || start < memory.base_address as usize
                || end > memory_end
            {
                bail!("ntdll SSN scan window is outside a readable ntdll region");
            }
            let window = slice::from_raw_parts(start as *const u8, window_len);
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
                bail!("VirtualAlloc(syscall stub) failed ({})", last_error());
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

    pub struct SyscallProcess {
        handle: Handle,
        stub_page: usize,
        stub: usize,
        snapshot: ProcessSnapshot,
    }

    impl SyscallProcess {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> bool {
            if buf.is_empty() {
                return true;
            }
            let read_vm: NtReadVirtualMemory = unsafe { std::mem::transmute(self.stub) };
            let handle = self.handle as *mut core::ffi::c_void;
            let mut off = 0usize;
            let mut complete = true;
            while off < buf.len() {
                let current = match (addr as usize).checked_add(off) {
                    Some(value) => value,
                    None => {
                        complete = false;
                        buf[off..].fill(0);
                        break;
                    }
                };
                let next_page = PAGE - (current % PAGE);
                let chunk = next_page.min(buf.len() - off);
                let mut n = 0usize;
                let status = unsafe {
                    read_vm(
                        handle,
                        current as *const core::ffi::c_void,
                        buf[off..off + chunk].as_mut_ptr() as *mut core::ffi::c_void,
                        chunk,
                        &mut n,
                    )
                };
                let n = n.min(chunk);
                if status >= 0 && n == chunk {
                    off += n;
                    continue;
                }
                complete = false;
                let fill_start = (off + n).min(buf.len());
                let fill_end = (off + chunk).min(buf.len());
                if fill_start < fill_end {
                    buf[fill_start..fill_end].fill(0);
                }
                off += chunk;
            }
            complete
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

        fn write_raw_iter(&mut self, ops: WriteRawMemOps) -> memflow::error::Result<()> {
            snapshot::reject_writes(ops)
        }

        fn metadata(&self) -> MemoryViewMetadata {
            snapshot::readonly_metadata()
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
            self.snapshot
                .module_address_list_callback(target_arch, callback)
        }

        fn module_by_address(
            &mut self,
            address: Address,
            architecture: ArchitectureIdent,
        ) -> memflow::error::Result<ModuleInfo> {
            self.snapshot.module_by_address(address, architecture)
        }

        fn module_by_name(&mut self, name: &str) -> memflow::error::Result<ModuleInfo> {
            self.snapshot.module_by_name(name)
        }

        fn primary_module_address(&mut self) -> memflow::error::Result<Address> {
            self.snapshot.primary_module_address()
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
            self.snapshot.info()
        }

        fn mapped_mem_range(
            &mut self,
            _gap_size: imem,
            start: Address,
            end: Address,
            out: MemoryRangeCallback,
        ) {
            self.snapshot.mapped_mem_range(start, end, out);
        }
    }

    pub fn attach(process_name: &str) -> Result<SyscallProcess> {
        let ssn = ntdll_ssn("NtReadVirtualMemory")?;
        log::info!("syscall backend: NtReadVirtualMemory SSN {ssn:#x}");
        let pid = find_pid(process_name)?;
        let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
        if handle.is_null() {
            bail!(
                "OpenProcess({process_name} pid {pid}) failed ({}) — PROCESS_VM_READ denied",
                last_error()
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
            snapshot: ProcessSnapshot::new(
                ProcessInfo {
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
            ),
        })
    }
}

#[cfg(windows)]
pub fn find_process(name: &str) -> Result<u32> {
    crate::memory::win::find_pid(name)
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
    fn extracts_five_byte_fallback_stub() {
        assert_eq!(extract_ssn(&[0xB8, 0x3F, 0x00, 0x00, 0x00]), Some(0x3F));
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

    #[test]
    fn malformed_window_indices_are_rejected_without_panicking() {
        assert_eq!(ssn_from_ntdll_window(&[], usize::MAX, usize::MAX), None);
        assert_eq!(ssn_from_ntdll_window(&[0; 8], isize::MAX as usize, 8), None);
    }

    /// `extract_ssn` is public, and a buffer too short to hold `mov eax, imm32`
    /// has to decline rather than index past its end.
    #[test]
    fn buffers_too_short_for_a_stub_decline_instead_of_panicking() {
        assert_eq!(extract_ssn(&[]), None);
        assert_eq!(extract_ssn(&[0xB8]), None);
        assert_eq!(extract_ssn(&[0xB8, 0x3F, 0x00, 0x00]), None);
        // Five bytes is the shortest buffer that can carry one.
        assert_eq!(extract_ssn(&[0xB8, 0x3F, 0x00, 0x00, 0x00]), Some(0x3F));
    }
}
