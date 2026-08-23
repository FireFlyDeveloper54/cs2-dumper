//! In-process dump target used after LoadLibrary.
//!
//! Game DLLs pulled into this process can hook enumeration APIs, so memflow's
//! `process_by_name("cs2-dumper.exe")` often fails right after a successful
//! schema bind. We already live in the address space — read it with
//! `ReadProcessMemory(GetCurrentProcess())` and snapshot our own modules.

use anyhow::Result;

#[cfg(windows)]
mod win {
    use anyhow::{Result, bail};
    use memflow::cglue::{CTup2, CTup3};
    use memflow::mem::mem_data::{MemOps, ReadRawMemOps, WriteRawMemOps, opt_call};
    use memflow::prelude::v1::*;

    const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
    const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
    const MAX_PATH: usize = 260;
    const MAX_MODULE_NAME32: usize = 255;
    const PAGE: usize = 0x1000;

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
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetCurrentProcessId() -> u32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut core::ffi::c_void;
        #[link_name = "Module32FirstW"]
        fn module32_first_w(snapshot: *mut core::ffi::c_void, entry: *mut ModuleEntry32W) -> i32;
        #[link_name = "Module32NextW"]
        fn module32_next_w(snapshot: *mut core::ffi::c_void, entry: *mut ModuleEntry32W) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
        fn ReadProcessMemory(
            process: *mut core::ffi::c_void,
            base: *const core::ffi::c_void,
            buffer: *mut core::ffi::c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    fn wchar_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn invalid_handle(handle: *mut core::ffi::c_void) -> bool {
        handle.is_null() || handle == (-1isize as *mut core::ffi::c_void)
    }

    fn enumerate_modules(pid: u32, parent: Address, arch: ArchitectureIdent) -> Result<Vec<ModuleInfo>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if invalid_handle(snap) {
                bail!(
                    "CreateToolhelp32Snapshot(self modules) failed ({})",
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
            if module32_first_w(snap, &mut entry) == 0 {
                bail!("Module32FirstW(self) failed ({})", GetLastError());
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
                if module32_next_w(snap, &mut entry) == 0 {
                    break;
                }
            }
            if modules.is_empty() {
                bail!("no modules enumerated for self pid {pid}");
            }
            Ok(modules)
        }
    }

    pub struct LocalProcess {
        handle: isize,
        info: ProcessInfo,
        modules: Vec<ModuleInfo>,
    }

    impl LocalProcess {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> bool {
            if buf.is_empty() {
                return true;
            }
            let mut off = 0usize;
            let mut any = false;
            while off < buf.len() {
                let next_page = PAGE - ((addr as usize + off) % PAGE);
                let chunk = next_page.min(buf.len() - off);
                let mut n = 0usize;
                let ok = unsafe {
                    ReadProcessMemory(
                        self.handle as *mut core::ffi::c_void,
                        (addr as usize + off) as *const core::ffi::c_void,
                        buf[off..off + chunk].as_mut_ptr() as *mut core::ffi::c_void,
                        chunk,
                        &mut n,
                    )
                };
                if ok != 0 && n > 0 {
                    off += n;
                    any = true;
                    continue;
                }
                buf[off..off + chunk].fill(0);
                off += chunk;
            }
            any
        }
    }

    impl MemoryView for LocalProcess {
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

    impl Process for LocalProcess {
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

    pub fn attach_self() -> Result<LocalProcess> {
        let pid = unsafe { GetCurrentProcessId() };
        let handle = unsafe { GetCurrentProcess() };
        let arch = ArchitectureIdent::X86(64, false);
        let parent = Address::from(pid as umem);
        let modules = enumerate_modules(pid, parent, arch)?;
        let exe_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "cs2-dumper.exe".into());
        let exe_path = modules
            .iter()
            .find(|m| m.name.as_ref().eq_ignore_ascii_case(&exe_name))
            .map(|m| m.path.to_string())
            .unwrap_or_default();
        log::info!(
            "loadlib backend: reading self pid {pid} ({} modules)",
            modules.len()
        );
        Ok(LocalProcess {
            handle: handle as isize,
            info: ProcessInfo {
                address: parent,
                pid,
                state: ProcessState::Alive,
                name: exe_name.into(),
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
pub fn attach_self() -> Result<win::LocalProcess> {
    win::attach_self()
}

#[cfg(not(windows))]
pub fn attach_self() -> Result<()> {
    anyhow::bail!("LoadLibrary dump is Windows-only")
}
