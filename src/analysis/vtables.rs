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

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use log::debug;
use memflow::prelude::v1::*;
use serde::Serialize;

use super::InterfaceMap;
use super::module_data;
use super::rtti;

/// Dump of one interface's virtual function table.
#[derive(Debug, Clone, Serialize)]
pub struct VTableInfo {
    /// RVA of the vftable itself within the *owning* module (may differ
    /// from the interface instance's module if the vftable was emitted
    /// into a different translation unit).
    pub vtable_rva: u64,
    /// Module name that hosts the vftable bytes.
    #[serde(serialize_with = "serialize_arc_str")]
    pub vtable_module: Arc<str>,
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
    /// Interned from the session module list so each slot does not clone
    /// `"client.dll"`.
    #[serde(serialize_with = "serialize_arc_str")]
    pub module: Arc<str>,
    /// Offset of the method body within `module`.
    pub rva: u64,
    /// Pattern-database name for this slot, when its resolved RVA matches
    /// a known Pattern hit exactly. Filled in by [`recover_names`] as a
    /// post-pass — this analyzer stays pure and doesn't know about
    /// Pattern.
    #[serde(serialize_with = "serialize_opt_arc_str")]
    pub name: Option<Arc<str>>,
}

/// `module → interface_name → vtable_info`
pub type VTableMap = BTreeMap<String, BTreeMap<String, VTableInfo>>;

fn serialize_arc_str<S>(value: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(value)
}

fn serialize_opt_arc_str<S>(value: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(name) => serializer.serialize_some(name.as_ref()),
        None => serializer.serialize_none(),
    }
}

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
    // module list per method. Names are interned `Arc<str>`.
    let modules = module_data::cached_module_list(process)?;

    let mut out: VTableMap = BTreeMap::new();

    for (module_name, ifaces) in interfaces {
        let Some(host) = modules
            .iter()
            .find(|(n, _, _)| n.as_ref().eq_ignore_ascii_case(module_name))
        else {
            continue;
        };

        let mut by_iface: BTreeMap<String, VTableInfo> = BTreeMap::new();

        for (iface_name, entry) in ifaces {
            // The original cs2-dumper interface pass resolves the factory
            // function's RIP-relative target to the singleton instance RVA.
            // Unlike universal-offsets, InterfaceMap has no needs_deref flag,
            // so the stored RVA is already the object address.
            let Some(inst_va) = host.1.checked_add(*entry) else {
                continue;
            };
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

    let mut by_loc: HashMap<String, HashMap<u64, &str>> = HashMap::new();
    for h in hits {
        if h.found
            && let Some(rva) = h.rva
        {
            by_loc
                .entry(h.module.to_ascii_lowercase())
                .or_default()
                .insert(rva, h.name.as_ref());
        }
    }

    let mut intern: HashMap<&str, Arc<str>> = HashMap::new();
    for ifaces in map.values_mut() {
        for info in ifaces.values_mut() {
            for m in &mut info.methods {
                let module = if m.module.bytes().any(|b| b.is_ascii_uppercase()) {
                    Cow::Owned(m.module.to_ascii_lowercase())
                } else {
                    Cow::Borrowed(m.module.as_ref())
                };
                let Some(name) = by_loc
                    .get(module.as_ref())
                    .and_then(|slots| slots.get(&m.rva))
                    .copied()
                else {
                    continue;
                };
                let interned = intern.entry(name).or_insert_with(|| Arc::from(name));
                m.name = Some(Arc::clone(interned));
            }
        }
    }
}

fn dump_one<P: MemoryView>(
    process: &mut P,
    instance_va: u64,
    modules: &[(Arc<str>, u64, u64)],
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
        .find(|(name, _, _)| name.as_ref() == vt_mod.as_ref())
        .and_then(|(_, base, size)| rtti::resolve_class_name(process, vt_va, *base, *size));

    // Slurp up to MAX_METHODS slots in one shot for speed; truncate at
    // the first non-code pointer.
    let raw = process
        .read_raw(Address::from(vt_va), MAX_METHODS * 8)
        .data_part()?;

    let mut methods = Vec::with_capacity(MAX_METHODS / 4);
    for chunk in raw.as_chunks::<8>().0 {
        let p = u64::from_le_bytes(*chunk);
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
fn classify(va: u64, modules: &[(Arc<str>, u64, u64)]) -> Option<(Arc<str>, u64)> {
    if va < 0x10000 {
        return None; // null + low-canonical garbage
    }
    for (name, base, size) in modules {
        let Some(end) = base.checked_add(*size) else {
            continue;
        };
        if va >= *base && va < end {
            return Some((Arc::clone(name), va.checked_sub(*base)?));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::PatternHit;
    use std::borrow::Cow;
    use std::sync::Arc;

    fn hit(name: &'static str, module: &str, rva: u64) -> PatternHit {
        PatternHit {
            name: Cow::Borrowed(name),
            module: Arc::from(module),
            resolve: "raw",
            pattern: Cow::Borrowed("48 8B"),
            prototype: None,
            bytes: None,
            pattern_synth: None,
            repaired_from: None,
            found: true,
            match_rva: Some(rva),
            match_va: Some(rva),
            rva: Some(rva),
            va: Some(rva),
            matches: 1,
            confidence: 1.0,
            error: None,
        }
    }

    #[test]
    fn recover_names_matches_module_case_insensitively() {
        let mut map: VTableMap = BTreeMap::from([(
            "client.dll".into(),
            BTreeMap::from([(
                "Source2Client002".into(),
                VTableInfo {
                    vtable_rva: 0x1000,
                    vtable_module: "client.dll".into(),
                    rtti_class: None,
                    methods: vec![VTableMethod {
                        module: "client.dll".into(),
                        rva: 0x2000,
                        name: None,
                    }],
                },
            )]),
        )]);
        recover_names(&mut map, &[hit("Connect", "CLIENT.DLL", 0x2000)]);
        assert_eq!(
            map["client.dll"]["Source2Client002"].methods[0]
                .name
                .as_deref(),
            Some("Connect")
        );
    }

    #[test]
    fn recover_names_ignores_rva_mismatch() {
        let mut map: VTableMap = BTreeMap::from([(
            "client.dll".into(),
            BTreeMap::from([(
                "Source2Client002".into(),
                VTableInfo {
                    vtable_rva: 0x1000,
                    vtable_module: "client.dll".into(),
                    rtti_class: None,
                    methods: vec![VTableMethod {
                        module: "client.dll".into(),
                        rva: 0x2000,
                        name: None,
                    }],
                },
            )]),
        )]);
        recover_names(&mut map, &[hit("Connect", "client.dll", 0x9999)]);
        assert!(
            map["client.dll"]["Source2Client002"].methods[0]
                .name
                .is_none()
        );
    }
}
