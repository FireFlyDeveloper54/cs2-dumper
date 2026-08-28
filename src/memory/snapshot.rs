//! Cached module list shared by the local and syscall backends.

use memflow::cglue::{CTup2, CTup3};
use memflow::mem::mem_data::{opt_call, MemOps, WriteRawMemOps};
use memflow::prelude::v1::*;

pub struct ProcessSnapshot {
    pub info: ProcessInfo,
    pub modules: Vec<ModuleInfo>,
}

impl ProcessSnapshot {
    pub fn new(info: ProcessInfo, modules: Vec<ModuleInfo>) -> Self {
        Self { info, modules }
    }

    pub fn info(&self) -> &ProcessInfo {
        &self.info
    }

    pub fn module_address_list_callback(
        &self,
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

    pub fn module_by_address(
        &self,
        address: Address,
        architecture: ArchitectureIdent,
    ) -> memflow::error::Result<ModuleInfo> {
        self.modules
            .iter()
            .find(|m| m.address == address && m.arch == architecture)
            .cloned()
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
    }

    pub fn module_by_name(&self, name: &str) -> memflow::error::Result<ModuleInfo> {
        self.modules
            .iter()
            .find(|m| m.name.as_ref().eq_ignore_ascii_case(name))
            .cloned()
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
    }

    pub fn primary_module_address(&self) -> memflow::error::Result<Address> {
        self.modules
            .iter()
            .find(|m| m.name.as_ref().eq_ignore_ascii_case(&self.info.name))
            .or_else(|| self.modules.first())
            .map(|m| m.address)
            .ok_or(Error(ErrorOrigin::OsLayer, ErrorKind::ModuleNotFound))
    }

    pub fn mapped_mem_range(&self, start: Address, end: Address, out: MemoryRangeCallback) {
        let start = start.to_umem();
        let limit = if end.is_null() || end == Address::INVALID {
            u64::MAX
        } else {
            end.to_umem()
        };
        self.modules
            .iter()
            .filter_map(|m| {
                let module_start = m.base.to_umem();
                let module_end = module_start.checked_add(m.size)?;
                let overlap_start = module_start.max(start);
                let overlap_end = module_end.min(limit);
                (overlap_start < overlap_end).then_some(CTup3(
                    Address::from(overlap_start),
                    overlap_end - overlap_start,
                    PageType::UNKNOWN,
                ))
            })
            .feed_into(out);
    }
}

pub fn readonly_metadata() -> MemoryViewMetadata {
    MemoryViewMetadata {
        max_address: Address::from(u64::MAX),
        real_size: 0,
        readonly: true,
        little_endian: true,
        arch_bits: 64,
    }
}

pub fn reject_writes(
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
