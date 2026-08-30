use std::collections::{BTreeMap, HashSet};

use anyhow::Result;

use log::debug;

use memflow::prelude::v1::*;

use pelite::pe64::exports::Export;
use pelite::pe64::{Pe, PeView};

use crate::analysis::module_data;
use crate::memory::address;
use crate::source2::InterfaceReg;

pub type InterfaceMap = BTreeMap<String, BTreeMap<String, umem>>;

const MAX_INTERFACE_REGISTRATIONS: usize = 16_384;

pub fn interfaces<P: Process + MemoryView>(process: &mut P) -> Result<InterfaceMap> {
    process
        .module_list()?
        .iter()
        .filter_map(|module| {
            let (_, buf) = module_data::read_image(process, module.name.as_ref()).ok()?;

            let view = PeView::from_bytes(&buf).ok()?;

            let ci_export = view
                .exports()
                .ok()?
                .by()
                .ok()?
                .name("CreateInterface")
                .ok()?;

            match ci_export {
                Export::Symbol(symbol) => {
                    let symbol_address = module
                        .base
                        .to_umem()
                        .checked_add(*symbol as u64)
                        .map(Address::from)?;
                    let list_ptr = address::resolve_rip(process, symbol_address).ok()?;
                    let list_head = process.read_addr64(list_ptr).data_part().ok()?;

                    read_interfaces(process, module, list_head)
                        .ok()
                        .filter(|ifaces| !ifaces.is_empty())
                        .map(|ifaces| Ok((module.name.to_string().to_ascii_lowercase(), ifaces)))
                }
                _ => None,
            }
        })
        .collect()
}

fn read_interfaces(
    mem: &mut impl MemoryView,
    module: &ModuleInfo,
    list_head: Address,
) -> Result<BTreeMap<String, umem>> {
    let mut result = BTreeMap::new();

    let mut reg_ptr = Pointer64::<InterfaceReg>::from(list_head);
    let mut seen = HashSet::new();

    while !reg_ptr.is_null() {
        let reg_va = reg_ptr.address().to_umem();
        if !seen.insert(reg_va) {
            anyhow::bail!("interface registry contains a cycle at {reg_va:#X}");
        }
        if seen.len() > MAX_INTERFACE_REGISTRATIONS {
            anyhow::bail!("interface registry exceeded {MAX_INTERFACE_REGISTRATIONS} entries");
        }
        let reg = mem.read_ptr(reg_ptr).data_part()?;
        let name = mem.read_utf8_lossy(reg.name.address(), 128).data_part()?;

        let instance_addr = address::resolve_rip(mem, reg.create_fn.address())?;

        if let Some(instance_rva) = instance_addr.to_umem().checked_sub(module.base.to_umem()) {
            debug!(
                "found \"{}\" at {:#X} ({} + {:#X})",
                name,
                instance_addr.to_umem(),
                module.name,
                instance_rva
            );

            result.insert(name, instance_rva);
        }

        reg_ptr = reg.next;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{MAX_INTERFACE_REGISTRATIONS, read_interfaces};
    use crate::memory::fake::FakeMemory;
    use memflow::prelude::v1::*;

    const MODULE_BASE: u64 = 0x0000_7FF6_1000_0000;
    const MODULE_SIZE: u64 = 0x0100_0000;

    fn module() -> ModuleInfo {
        ModuleInfo {
            address: Address::from(MODULE_BASE),
            parent_process: Address::from(0u64),
            base: Address::from(MODULE_BASE),
            size: MODULE_SIZE as umem,
            name: ReprCString::from("client.dll"),
            path: ReprCString::from("client.dll"),
            arch: ArchitectureIdent::X86(64, false),
        }
    }

    /// Lay down one `InterfaceReg` whose `create_fn` is a `lea rax, [rip+x]`
    /// style stub returning the singleton at `MODULE_BASE + instance_rva`.
    fn push_reg(mem: &mut FakeMemory, name: &str, instance_rva: u64, next: u64) -> u64 {
        let name_ptr = mem.alloc_cstr(name);
        let create_fn = mem.alloc(0x10);
        mem.put_rip(create_fn, &[0x48, 0x8D, 0x05], MODULE_BASE + instance_rva);
        let reg = mem.alloc(0x18);
        mem.put_ptr(reg, create_fn);
        mem.put_ptr(reg + 0x8, name_ptr);
        mem.put_ptr(reg + 0x10, next);
        reg
    }

    #[test]
    fn walks_the_registry_and_reports_module_relative_rvas() {
        let mut mem = FakeMemory::new();
        let third = push_reg(&mut mem, "Source2Client002", 0x12_3450, 0);
        let second = push_reg(&mut mem, "GameResourceServiceClientV001", 0x22_2220, third);
        let head = push_reg(&mut mem, "Source2ClientPrediction001", 0x33_3330, second);

        let found = read_interfaces(&mut mem, &module(), Address::from(head)).expect("walk");

        assert_eq!(found.len(), 3);
        assert_eq!(found.get("Source2Client002"), Some(&(0x12_3450 as umem)));
        assert_eq!(
            found.get("GameResourceServiceClientV001"),
            Some(&(0x22_2220 as umem))
        );
        assert_eq!(
            found.get("Source2ClientPrediction001"),
            Some(&(0x33_3330 as umem))
        );
    }

    #[test]
    fn a_cyclic_next_chain_is_rejected_instead_of_looping_forever() {
        let mut mem = FakeMemory::new();
        let first = push_reg(&mut mem, "Source2Client002", 0x1000, 0);
        let second = push_reg(&mut mem, "Source2Server001", 0x2000, first);
        // Close the loop: first -> second -> first.
        mem.put_ptr(first + 0x10, second);

        let error = read_interfaces(&mut mem, &module(), Address::from(first))
            .expect_err("a cycle must not be walked forever");
        assert!(error.to_string().contains("cycle"), "{error}");
    }

    #[test]
    fn an_instance_outside_the_module_is_skipped_not_wrapped() {
        let mut mem = FakeMemory::new();
        // A stub resolving below the module base would underflow the RVA.
        let name_ptr = mem.alloc_cstr("StrayInterface001");
        let create_fn = mem.alloc(0x10);
        mem.put_rip(create_fn, &[0x48, 0x8D, 0x05], MODULE_BASE - 0x1000);
        let good = push_reg(&mut mem, "Source2Client002", 0x4000, 0);
        let head = mem.alloc(0x18);
        mem.put_ptr(head, create_fn);
        mem.put_ptr(head + 0x8, name_ptr);
        mem.put_ptr(head + 0x10, good);

        let found = read_interfaces(&mut mem, &module(), Address::from(head)).expect("walk");
        assert_eq!(found.len(), 1);
        assert!(found.contains_key("Source2Client002"));
    }

    #[test]
    fn an_overlong_acyclic_chain_is_capped() {
        let mut mem = FakeMemory::new();
        let name_ptr = mem.alloc_cstr("Padding001");
        let create_fn = mem.alloc(0x10);
        mem.put_rip(create_fn, &[0x48, 0x8D, 0x05], MODULE_BASE + 0x1000);

        // Distinct nodes, so the cycle guard never fires; only the hard cap
        // stops the walk.
        let mut head = 0u64;
        for _ in 0..=MAX_INTERFACE_REGISTRATIONS {
            let reg = mem.alloc(0x18);
            mem.put_ptr(reg, create_fn);
            mem.put_ptr(reg + 0x8, name_ptr);
            mem.put_ptr(reg + 0x10, head);
            head = reg;
        }

        let error = read_interfaces(&mut mem, &module(), Address::from(head))
            .expect_err("the walk must be bounded");
        assert!(error.to_string().contains("exceeded"), "{error}");
    }
}
