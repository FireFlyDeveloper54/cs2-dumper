//! Per-interface vtable dumper.
//!
//! For every entry in [`InterfaceMap`] we follow the instance pointer
//! to the C++ vftable (the first qword of any polymorphic object) and
//! walk it as a contiguous array of function pointers, stopping at the
//! first entry that doesn't look like a code address.
//!
//! # What this lets internals do
//!
//! With `inline constexpr std::ptrdiff_t Connect = 0;` etc. emitted per
//! interface, hooking by index becomes one line:
//!
//! ```cpp
//! using Connect_t = bool(__thiscall*)(void* self, ...);
//! auto* iface = cs2::ifaces::client_dll::Source2Client002(client_base);
//! auto** vt = *reinterpret_cast<void***>(iface);
//! auto fn  = reinterpret_cast<Connect_t>(vt[cs2::vtables::client_dll::Source2Client002::Connect]);
//! ```
//!
//! # Method-name recovery
//!
//! We don't have PDBs, so most slots are emitted as `method_<N>`. As a
//! bonus pass, callers can cross-reference each method RVA against the
//! Pattern database — if a hit's resolved RVA matches a method RVA,
//! the Pattern name is used in place of `method_<N>` (handled in the
//! writer, not here, so this analyzer stays pure).

use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;
use memflow::prelude::v1::*;
use serde::Serialize;

use super::InterfaceMap;
use super::rtti;

/// Dump of one interface's virtual function table.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VTableInfo {
    /// RVA of the vftable itself within the *owning* module (may differ
    /// from the interface instance's module if the vftable was emitted
    /// into a different translation unit).
    pub vtable_rva: u64,
    /// Module name that hosts the vftable bytes.
    pub vtable_module: String,
    /// MSVC RTTI class name recovered from `vftable[-1]` -> COL ->
    /// TypeDescriptor.  `None` when the vtable doesn't carry RTTI
    /// (compiler thunks, `/GR-` builds) or when the COL fails our
    /// Pattern/self-RVA sanity checks.
    pub rtti_class: Option<String>,
    /// One entry per virtual method, in slot order. `module` is the DLL
    /// that hosts the method body; `rva` is its offset within that DLL.
    pub methods: Vec<VTableMethod>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VTableMethod {
    /// Module hosting the method body (may differ from the vtable's own
    /// module — thunks and cross-module overrides are common).
    pub module: String,
    /// Offset of the method body within `module`.
    pub rva: u64,
    /// Pattern-database name for this slot, when its resolved RVA matches
    /// a known Pattern hit exactly. Filled in by [`recover_names`] as a
    /// post-pass — this analyzer stays pure and doesn't know about
    /// Pattern.
    pub name: Option<String>,
}

/// `module → interface_name → vtable_info`
pub type VTableMap = BTreeMap<String, BTreeMap<String, VTableInfo>>;

/// Maximum vtable slots to read per interface. CS2's biggest interface
/// vtables sit comfortably under 200; 256 gives plenty of headroom and
/// caps memory in the worst case.
const MAX_METHODS: usize = 256;

/// Walk every interface's vtable. Failures on individual interfaces are
/// logged and skipped — one bad pointer doesn't take the whole pass
/// down.
pub fn vtables<P: Process + MemoryView>(
    process: &mut P,
    interfaces: &InterfaceMap,
) -> Result<VTableMap> {
    // Build a `[module_base, module_size, name]` table once so we can
    // classify any address into "(module, rva)" without re-walking the
    // module list per method.
    let modules: Vec<(String, u64, u64)> = process
        .module_list()?
        .into_iter()
        .map(|m| {
            (
                m.name.to_string().to_ascii_lowercase(),
                m.base.to_umem() as u64,
                m.size as u64,
            )
        })
        .collect();

    let mut out: VTableMap = BTreeMap::new();

    for (module_name, ifaces) in interfaces {
        let Some(host) = modules.iter().find(|(n, _, _)| n == module_name) else {
            continue;
        };

        let mut by_iface: BTreeMap<String, VTableInfo> = BTreeMap::new();

        for (iface_name, entry) in ifaces {
            // The original cs2-dumper interface pass resolves the factory
            // function's RIP-relative target to the singleton instance RVA.
            // Unlike universal-offsets, InterfaceMap has no needs_deref flag,
            // so the stored RVA is already the object address.
            let inst_va = host.1 + *entry as u64;
            match dump_one(process, inst_va, &modules) {
                Ok(Some(info)) => {
                    debug!(
                        "{}::{} vtable @ {}+{:#X} ({} methods, rtti={:?})",
                        module_name,
                        iface_name,
                        info.vtable_module,
                        info.vtable_rva,
                        info.methods.len(),
                        info.rtti_class,
                    );
                    by_iface.insert(iface_name.clone(), info);
                }
                Ok(None) => {} // not a polymorphic instance — skip silently
                Err(e) => {
                    debug!("{}::{} vtable walk failed: {}", module_name, iface_name, e);
                }
            }
        }

        if !by_iface.is_empty() {
            out.insert(module_name.clone(), by_iface);
        }
    }

    Ok(out)
}

/// Cross-reference every method slot's `(module, rva)` against resolved
/// Pattern hits, filling in `VTableMethod::name` on exact matches. A
/// separate pass (rather than doing this in [`vtables`]) keeps the walker
/// free of any dependency on the Pattern database.
pub fn recover_names(map: &mut VTableMap, hits: &[crate::patterns::PatternHit]) {
    use std::collections::HashMap;

    let mut by_loc: HashMap<(&str, u64), &str> = HashMap::new();
    for h in hits {
        if h.found
            && let Some(rva) = h.rva
        {
            by_loc.insert((h.module.as_str(), rva), h.name.as_str());
        }
    }

    for ifaces in map.values_mut() {
        for info in ifaces.values_mut() {
            for m in &mut info.methods {
                if let Some(name) = by_loc.get(&(m.module.as_str(), m.rva)) {
                    m.name = Some((*name).to_string());
                }
            }
        }
    }
}

fn dump_one<P: MemoryView>(
    process: &mut P,
    instance_va: u64,
    modules: &[(String, u64, u64)],
) -> Result<Option<VTableInfo>> {
    // [instance][0] = vftable VA
    let vt_va = process
        .read::<u64>(Address::from(instance_va))
        .data_part()?;
    let Some((vt_mod, vt_rva)) = classify(vt_va, modules) else {
        return Ok(None);
    };

    // RTTI lookup is best-effort: a vtable without a valid COL is
    // perfectly normal for thunks, and we'd rather emit unnamed slots
    // than skip the vtable entirely.
    let rtti_class = modules
        .iter()
        .find(|(name, _, _)| name == &vt_mod)
        .and_then(|(_, base, size)| rtti::resolve_class_name(process, vt_va, *base, *size));

    // Slurp up to MAX_METHODS slots in one shot for speed; truncate at
    // the first non-code pointer.
    let raw = process
        .read_raw(Address::from(vt_va), MAX_METHODS * 8)
        .data_part()?;

    let mut methods = Vec::with_capacity(MAX_METHODS / 4);
    for chunk in raw.chunks_exact(8) {
        let p = u64::from_le_bytes(chunk.try_into().unwrap());
        match classify(p, modules) {
            Some((module, rva)) => methods.push(VTableMethod {
                module,
                rva,
                name: None,
            }),
            None => break,
        }
    }

    if methods.is_empty() {
        return Ok(None);
    }

    Ok(Some(VTableInfo {
        vtable_rva: vt_rva,
        vtable_module: vt_mod,
        rtti_class,
        methods,
    }))
}

/// Map a VA back to `(module_name, rva)` if it falls inside any loaded
/// module's image range. We don't bother gating on per-section bounds —
/// a vftable entry could legally point at a thunk in `.text`,
/// `.text$mn`, or `__icall_thunks`, and we'd rather over-accept than
/// truncate a real vtable on a stylistic edge case.
fn classify(va: u64, modules: &[(String, u64, u64)]) -> Option<(String, u64)> {
    if va < 0x10000 {
        return None; // null + low-canonical garbage
    }
    for (name, base, size) in modules {
        if va >= *base && va < base.wrapping_add(*size) {
            return Some((name.clone(), va - *base));
        }
    }
    None
}
