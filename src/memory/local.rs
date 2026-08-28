//! In-process dump target used after LoadLibrary.
//!
//! Game DLLs pulled into this process can hook enumeration APIs, so memflow's
//! `process_by_name("cs2-dumper.exe")` often fails right after a successful
//! schema bind. We already live in the address space — read it with
//! `ReadProcessMemory(GetCurrentProcess())` and snapshot our own modules.

use anyhow::Result;

#[cfg(windows)]
mod win {
    use anyhow::Result;
    use memflow::cglue::{CTup2, CTup3};
    use memflow::mem::mem_data::{opt_call, MemOps, ReadRawMemOps, WriteRawMemOps};
    use memflow::prelude::v1::*;

    use crate::memory::snapshot::{self, ProcessSnapshot};
    use crate::memory::win::{
        enumerate_modules, GetCurrentProcess, GetCurrentProcessId, ReadProcessMemory, PAGE,
    };

    pub struct LocalProcess {
        handle: isize,
        snapshot: ProcessSnapshot,
    }

    impl LocalProcess {
        fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> bool {
            if buf.is_empty() {
                return true;
            }
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
                let ok = unsafe {
                    ReadProcessMemory(
                        self.handle as *mut core::ffi::c_void,
                        current as *const core::ffi::c_void,
                        buf[off..off + chunk].as_mut_ptr() as *mut core::ffi::c_void,
                        chunk,
                        &mut n,
                    )
                };
                let n = n.min(chunk);
                if ok != 0 && n == chunk {
                    off += n;
                    continue;
                }
                complete = false;
                let old_off = off;
                let fill_start = (old_off + n).min(buf.len());
                let fill_end = (old_off + chunk).min(buf.len());
                if fill_start < fill_end {
                    buf[fill_start..fill_end].fill(0);
                }
                off = old_off + chunk;
            }
            complete
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

        fn write_raw_iter(&mut self, ops: WriteRawMemOps) -> memflow::error::Result<()> {
            snapshot::reject_writes(ops)
        }

        fn metadata(&self) -> MemoryViewMetadata {
            snapshot::readonly_metadata()
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
            snapshot: ProcessSnapshot::new(
                ProcessInfo {
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
            ),
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
