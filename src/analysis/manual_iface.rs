//! Auto-discovery of vtable-only classes reached via `p*` patterns.
//!
//! For every pattern hit named `p*` that resolves to a data RVA, treat the
//! resolved address as a class singleton, read its vtable pointer, RTTI-walk
//! to recover the class name, and walk the vtable to count methods. Emit as
//! an `IfaceClass` alongside the registered-interface classes so the renderer
//! treats them uniformly.
//!
//! This is what makes things like `ifc::EnginePVSManager()` work without any
//! hardcoded entry — same mechanism `CreateInterface`-registered interfaces
//! use, just driven by pattern resolution instead of factory enumeration.

use std::borrow::Cow;

use memflow::prelude::v1::*;

use crate::analysis::rtti;
use crate::output::interface_classes::{IfaceClass, Method};
use crate::patterns::PatternReport;

/// Maximum vtable slots we attempt to walk before bailing.
const MAX_METHODS: usize = 256;

pub fn discover<'a, P: Process + MemoryView>(
    process: &mut P,
    report: &'a PatternReport,
) -> Vec<IfaceClass<'a>> {
    let modules = crate::analysis::module_data::cached_module_list(process).unwrap_or_default();

    let mut out = Vec::new();
    for hit in &report.hits {
        if !hit.found {
            continue;
        }
        if !hit.name.starts_with('p') {
            continue;
        }
        let Some(rva) = hit.rva else { continue };

        let Some((_, base, _)) = modules
            .iter()
            .find(|(n, _, _)| n.as_ref() == hit.module.as_ref())
        else {
            continue;
        };
        let Some(singleton_va) = base.checked_add(rva) else {
            continue;
        };

        // Read qword at the singleton — should be the vtable VA for class singletons.
        let Ok(vt_va) = process.read::<u64>(Address::from(singleton_va)).data_part() else {
            continue;
        };
        if vt_va < 0x10000 {
            continue;
        }

        // Locate which module hosts the vtable.
        let Some((_, vt_mod_base, vt_mod_size)) = modules.iter().find(|(_, b, s)| {
            b.checked_add(*s)
                .is_some_and(|end| vt_va >= *b && vt_va < end)
        }) else {
            continue;
        };

        // RTTI walk recovers the class name when the vtable carries a valid COL.
        // Non-class data (e.g. plain globals) silently fails this check.
        let Some(class_name) = rtti::resolve_class_name(process, vt_va, *vt_mod_base, *vt_mod_size)
        else {
            continue;
        };

        // Walk the vtable counting code-pointer slots until we hit non-code.
        let methods = walk_vtable_methods(process, vt_va, &modules);
        if methods == 0 {
            continue;
        }

        out.push(IfaceClass {
            module: hit.module.as_ref(),
            iface_name: hit.name.as_ref(),
            instance_rva: Some(rva),
            rtti_class: Some(Cow::Owned(class_name)),
            methods: (0..methods)
                .map(|i| Method {
                    index: i,
                    name: None,
                })
                .collect(),
            manual: true,
        });
    }
    out
}

fn walk_vtable_methods<P: MemoryView>(
    process: &mut P,
    vt_va: u64,
    modules: &[(std::sync::Arc<str>, u64, u64)],
) -> usize {
    let Ok(raw) = process
        .read_raw(Address::from(vt_va), MAX_METHODS * 8)
        .data_part()
    else {
        return 0;
    };
    let mut count = 0;
    for chunk in raw.as_chunks::<8>().0 {
        let p = u64::from_le_bytes(*chunk);
        if !modules
            .iter()
            .any(|(_, b, s)| b.checked_add(*s).is_some_and(|end| p >= *b && p < end))
        {
            break;
        }
        count += 1;
    }
    count
}
