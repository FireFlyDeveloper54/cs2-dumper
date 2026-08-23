//! Read-only walker for the tier0 **CCvar** convar / concommand registry.
//!
//! The registry is normally enumerated through virtual methods
//! (`GetFirstConVar` / `GetNextConVar` / `GetConVarData`), which a memory-only
//! reader cannot call. Instead we walk the underlying storage directly. The
//! registry layout is selected from a small set of candidates by validating
//! live list data; the historical layout remains the fallback when probing is
//! inconclusive. The `g_pCVar` global that anchors the walk is resolved via the
//! `pCvarRegistry` RIP-relative pattern, or — when that pattern no longer
//! matches — by [`find_registry`], which describes the registry object itself
//! and finds the global holding it in tier0's writable data.
//!
//! ```text
//! *g_pCVar  ->  CCvar instance:
//!   +0x50  convar linked-list array base   (stride 16)
//!   +0x58  convar list head index (u16)
//!          elem = { ConVarInfo* @+0, u16 prev @+8, u16 next @+10 }
//!   +0x108 concommand array base           (stride 56)
//!   +0x110 concommand head index (u16)
//!          elem = { name @+0, desc @+8, u32 flags @+0x10, u16 prev @+0x30, next @+0x32 }
//!
//! ConVarInfo (the convar data object):
//!   +0x00 name (char*)   +0x20 description (char*)
//!   +0x28 type (u16 EConVarType)   +0x30 flags (u32)   +0x58 value union
//! ```
//!
//! Enumeration follows the head→next index chain (the exact list the game's own
//! `cvarlist` walks), so every registered convar/command is captured regardless
//! of hidden/dev flags. All reads are best-effort — a bad pointer yields an
//! empty field, never a panic.

use anyhow::{Result, bail};
use memflow::prelude::v1::*;
use serde::Serialize;

use crate::analysis::global_anchor::{self, AnchorScan, Head};

/// Sentinel index terminating a CUtlLinkedList chain.
const LIST_END: u16 = 0xFFFF;
/// Hard cap on chain length — guards against a corrupt `next` pointer looping
/// forever. Comfortably above CS2's real convar count (~5k).
const MAX_WALK: usize = 200_000;

// --- CCvar instance offsets ------------------------------------------------
const OFF_CV_BASE: u64 = 0x50; // convar list array base ptr
const OFF_CV_HEAD: u64 = 0x58; // convar list head index (u16)
const CV_STRIDE: u64 = 16;
const CV_ELEM_NEXT: u64 = 10; // next index within a convar list element

const OFF_CC_BASE: u64 = 0x108; // concommand array base ptr
const OFF_CC_HEAD: u64 = 0x110; // concommand array head index (u16)
const CC_STRIDE: u64 = 56;
const CC_ELEM_NEXT: u64 = 0x32; // next index within a concommand element

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RegistryLayout {
    pub cv_base: u64,
    pub cv_head: u64,
    pub cv_stride: u64,
    pub cv_next: u64,
    pub cc_base: u64,
    pub cc_head: u64,
    pub cc_stride: u64,
    pub cc_next: u64,
}

impl Default for RegistryLayout {
    fn default() -> Self {
        Self {
            cv_base: OFF_CV_BASE,
            cv_head: OFF_CV_HEAD,
            cv_stride: CV_STRIDE,
            cv_next: CV_ELEM_NEXT,
            cc_base: OFF_CC_BASE,
            cc_head: OFF_CC_HEAD,
            cc_stride: CC_STRIDE,
            cc_next: CC_ELEM_NEXT,
        }
    }
}

const CV_LAYOUT_CANDIDATES: &[(u64, u64, u64, u64)] = &[
    (OFF_CV_BASE, OFF_CV_HEAD, CV_STRIDE, CV_ELEM_NEXT),
    (0x48, 0x50, 16, 0x0A),
    (0x58, 0x60, 16, 0x0A),
    (0x50, 0x58, 24, 0x12),
];

const CC_LAYOUT_CANDIDATES: &[(u64, u64, u64, u64)] = &[
    (OFF_CC_BASE, OFF_CC_HEAD, CC_STRIDE, CC_ELEM_NEXT),
    (0x100, 0x108, 56, 0x32),
    (0x110, 0x118, 56, 0x32),
    (0x108, 0x110, 64, 0x3A),
];
// --- ConVarInfo_t field offsets --------------------------------------------
const CVI_NAME: u64 = 0x00;
const CVI_DESC: u64 = 0x20;
const CVI_TYPE: u64 = 0x28;
const CVI_FLAGS: u64 = 0x30;
const CVI_VALUE: u64 = 0x58;

// --- ConCommand element field offsets --------------------------------------
const CC_NAME: u64 = 0x00;
const CC_DESC: u64 = 0x08;
const CC_FLAGS: u64 = 0x10;

/// FCVAR bit -> canonical `FCVAR_*` short name. Names are normalised to the
/// well-known Source SDK constants rather than the terse console tokens.
const FCVAR_FLAGS: &[(u32, &str)] = &[
    (0x00000001, "FCVAR_LINKED_CONCOMMAND"),
    (0x00000002, "FCVAR_DEVELOPMENTONLY"),
    (0x00000004, "FCVAR_GAMEDLL"),
    (0x00000008, "FCVAR_CLIENTDLL"),
    (0x00000020, "FCVAR_PROTECTED"),
    (0x00000040, "FCVAR_SPONLY"),
    (0x00000080, "FCVAR_ARCHIVE"),
    (0x00000100, "FCVAR_NOTIFY"),
    (0x00000200, "FCVAR_USERINFO"),
    (0x00000800, "FCVAR_UNLOGGED"),
    (0x00002000, "FCVAR_REPLICATED"),
    (0x00004000, "FCVAR_CHEAT"),
    (0x00008000, "FCVAR_PER_USER"),
    (0x00010000, "FCVAR_DEMO"),
    (0x00020000, "FCVAR_DONTRECORD"),
    (0x00080000, "FCVAR_RELEASE"),
    (0x00100000, "FCVAR_MENUBAR_ITEM"),
    (0x00800000, "FCVAR_VCONSOLE_FUZZY_MATCHING"),
    (0x01000000, "FCVAR_SERVER_CAN_EXECUTE"),
    (0x04000000, "FCVAR_SERVER_CANNOT_QUERY"),
    (0x08000000, "FCVAR_VCONSOLE_SET_FOCUS"),
    (0x10000000, "FCVAR_CLIENTCMD_CAN_EXECUTE"),
    (0x20000000, "FCVAR_EXECUTE_PER_TICK"),
];

/// One registered convar with its live value decoded to a string.
#[derive(Debug, Serialize)]
pub struct ConVar {
    pub name: String,
    pub value: String,
    pub type_id: u16,
    pub type_name: &'static str,
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub description: String,
    /// VA of the `ConVarInfo_t` object (handy for external tooling).
    pub address: u64,
}

/// One registered console command (no value; name/flags/help only).
#[derive(Debug, Serialize)]
pub struct ConCommand {
    pub name: String,
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub description: String,
    pub address: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct ConVarsDump {
    pub convars: Vec<ConVar>,
    pub commands: Vec<ConCommand>,
    pub registry_layout: RegistryLayout,
}

/// Walk the registry. `registry_global_va` is the resolved address of the
/// `g_pCVar` global (a `CCvar*`), i.e. the VA the `pCvarRegistry` pattern
/// resolves to.
pub fn walk<P: MemoryView>(process: &mut P, registry_global_va: u64) -> Result<ConVarsDump> {
    let inst = rd_u64(process, registry_global_va);
    if inst == 0 {
        bail!("g_pCVar is null (0x{:X})", registry_global_va);
    }

    let layout = detect_layout(process, inst);
    let mut dump = ConVarsDump {
        registry_layout: layout,
        ..Default::default()
    };

    let cv_base = rd_u64(process, inst + layout.cv_base);
    if cv_base != 0 {
        let mut idx = rd_u16(process, inst + layout.cv_head);
        let mut seen = 0usize;
        let mut indexes = std::collections::BTreeSet::new();
        while idx != LIST_END && seen < MAX_WALK && indexes.insert(idx) {
            seen += 1;
            let elem = cv_base + layout.cv_stride * idx as u64;
            let data = rd_u64(process, elem);
            let next = rd_u16(process, elem + layout.cv_next);
            if data != 0
                && let Ok(cv) = read_convar(process, data)
            {
                dump.convars.push(cv);
            }
            idx = next;
        }
    }

    let cc_base = rd_u64(process, inst + layout.cc_base);
    if cc_base != 0 {
        let mut idx = rd_u16(process, inst + layout.cc_head);
        let mut seen = 0usize;
        let mut indexes = std::collections::BTreeSet::new();
        while idx != LIST_END && seen < MAX_WALK && indexes.insert(idx) {
            seen += 1;
            let elem = cc_base + layout.cc_stride * idx as u64;
            let next = rd_u16(process, elem + layout.cc_next);
            if let Ok(cc) = read_concommand(process, elem) {
                dump.commands.push(cc);
            }
            idx = next;
        }
    }

    dump.convars.sort_by(|a, b| a.name.cmp(&b.name));
    dump.commands.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(dump)
}

fn detect_layout<P: MemoryView>(process: &mut P, inst: u64) -> RegistryLayout {
    let (best, best_score) = best_layout(process, inst);
    // A single plausible pointer is not enough evidence: unrelated fields in
    // CCvar can look pointer-like. Require several validated nodes before
    // replacing the known fallback layout.
    if best_score >= 8 {
        best
    } else {
        RegistryLayout::default()
    }
}

/// The best-fitting candidate pair for `inst` and how much evidence it found.
/// [`detect_layout`] answers "which layout is this registry"; the score answers
/// "is this a registry at all", which is what the anchor scan needs.
fn best_layout<P: MemoryView>(process: &mut P, inst: u64) -> (RegistryLayout, usize) {
    let mut best = RegistryLayout::default();
    let mut best_score = 0usize;
    for &(cv_base, cv_head, cv_stride, cv_next) in CV_LAYOUT_CANDIDATES {
        for &(cc_base, cc_head, cc_stride, cc_next) in CC_LAYOUT_CANDIDATES {
            let candidate = RegistryLayout {
                cv_base,
                cv_head,
                cv_stride,
                cv_next,
                cc_base,
                cc_head,
                cc_stride,
                cc_next,
            };
            let score = score_layout(process, inst, candidate);
            if score > best_score {
                best_score = score;
                best = candidate;
            }
        }
    }
    (best, best_score)
}

fn score_layout<P: MemoryView>(process: &mut P, inst: u64, layout: RegistryLayout) -> usize {
    let mut score = 0usize;
    let cv_base = rd_u64(process, inst + layout.cv_base);
    let cv_head = rd_u16(process, inst + layout.cv_head);
    if cv_base >= 0x10000 && cv_head != LIST_END && cv_head < 0x8000 {
        let mut idx = cv_head;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            if idx == LIST_END || !seen.insert(idx) {
                score += 1;
                break;
            }
            let elem = cv_base.saturating_add(layout.cv_stride.saturating_mul(idx as u64));
            let data = rd_u64(process, elem);
            if data < 0x10000 {
                break;
            }
            let name = rd_cstr_at(process, data + CVI_NAME);
            let type_id = rd_u16(process, data + CVI_TYPE);
            if !plausible_name(&name) || type_id > 14 {
                break;
            }
            score += 2;
            let next = rd_u16(process, elem + layout.cv_next);
            if next == LIST_END {
                score += 1;
                break;
            }
            if next >= 0x8000 {
                break;
            }
            idx = next;
        }
    }
    let cc_base = rd_u64(process, inst + layout.cc_base);
    let cc_head = rd_u16(process, inst + layout.cc_head);
    if cc_base >= 0x10000 && cc_head != LIST_END && cc_head < 0x8000 {
        let mut idx = cc_head;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            if idx == LIST_END || !seen.insert(idx) {
                score += 1;
                break;
            }
            let elem = cc_base.saturating_add(layout.cc_stride.saturating_mul(idx as u64));
            let name = rd_cstr_at(process, elem + CC_NAME);
            if !plausible_name(&name) {
                break;
            }
            score += 2;
            let flags = rd_u32(process, elem + CC_FLAGS);
            // FCVAR is a bit field; this rejects the common all-ones garbage
            // pattern while allowing future flags unknown to this dumper.
            if flags != u32::MAX {
                score += 1;
            }
            let next = rd_u16(process, elem + layout.cc_next);
            if next == LIST_END {
                score += 1;
                break;
            }
            if next >= 0x8000 {
                break;
            }
            idx = next;
        }
    }
    score
}

fn plausible_name(name: &str) -> bool {
    let len = name.len();
    (1..=128).contains(&len) && name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

// --- signature-free discovery of the `g_pCVar` global ----------------------

/// Bytes of a candidate `CCvar` read in one block, covering the furthest
/// candidate field (`cc_head` at 0x118, two bytes wide).
const REGISTRY_HEAD_SPAN: usize = 0x120;

/// Nodes' worth of evidence a candidate must present. [`score_layout`] awards
/// two per validated list node, so this asks for roughly six good nodes across
/// the two lists — more than a coincidence, far less than the real registry.
const REGISTRY_MIN_EVIDENCE: usize = 12;

/// The gate reads at most one list element, so a wider budget is affordable
/// here than for the entity list.
const REGISTRY_SCAN: AnchorScan = AnchorScan {
    head_span: REGISTRY_HEAD_SPAN,
    min_evidence: REGISTRY_MIN_EVIDENCE,
    max_probes: 128,
};

/// Locate the `g_pCVar` global in `module` by describing the registry it points
/// at, so the convar dump survives a recompile that invalidates the
/// `pCvarRegistry` signature.
pub fn find_registry<P: Process + MemoryView>(process: &mut P, module: &str) -> Option<u64> {
    global_anchor::find_in_module(
        process,
        module,
        REGISTRY_SCAN,
        gate_registry,
        score_registry,
    )
}

/// How much evidence `inst` presents as a convar registry, under whichever
/// candidate layout fits it best.
fn score_registry<P: MemoryView>(process: &mut P, inst: u64) -> usize {
    best_layout(process, inst).1
}

/// The same scan against a caller-supplied module image, so the policy can be
/// exercised without a live process.
#[cfg(test)]
fn find_registry_in<P: MemoryView>(
    mem: &mut P,
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
) -> Option<u64> {
    global_anchor::find_global(
        mem,
        image,
        base,
        ranges,
        REGISTRY_SCAN,
        gate_registry,
        score_registry,
    )
}

/// Cheap gate: under some candidate layout the convar list has a base and an
/// in-range head index, and that head element points at a `ConVarInfo` with a
/// printable name and a known type.
fn gate_registry<P: MemoryView>(process: &mut P, head: &Head) -> bool {
    CV_LAYOUT_CANDIDATES
        .iter()
        .any(|&(cv_base, cv_head, cv_stride, _)| {
            let base = head.u64(cv_base);
            let index = head.u16(cv_head);
            if base < 0x10000 || index >= 0x8000 {
                return false;
            }
            let elem = base.saturating_add(cv_stride.saturating_mul(index as u64));
            let data = rd_u64(process, elem);
            data >= 0x10000
                && plausible_name(&rd_cstr_at(process, data + CVI_NAME))
                && rd_u16(process, data + CVI_TYPE) <= 14
        })
}
fn read_convar<P: MemoryView>(process: &mut P, data_va: u64) -> Result<ConVar> {
    let name = rd_cstr_at(process, data_va + CVI_NAME);
    if name.is_empty() {
        bail!("empty convar name");
    }
    let description = rd_cstr_at(process, data_va + CVI_DESC);
    let type_id = rd_u16(process, data_va + CVI_TYPE);
    let flags = rd_u32(process, data_va + CVI_FLAGS);
    Ok(ConVar {
        name,
        value: decode_value(process, data_va + CVI_VALUE, type_id),
        type_id,
        type_name: type_name(type_id),
        flags,
        flag_names: decode_flags(flags),
        description,
        address: data_va,
    })
}

fn read_concommand<P: MemoryView>(process: &mut P, elem_va: u64) -> Result<ConCommand> {
    let name = rd_cstr_at(process, elem_va + CC_NAME);
    if name.is_empty() {
        bail!("empty concommand name");
    }
    let description = rd_cstr_at(process, elem_va + CC_DESC);
    let flags = rd_u32(process, elem_va + CC_FLAGS);
    Ok(ConCommand {
        name,
        flags,
        flag_names: decode_flags(flags),
        description,
        address: elem_va,
    })
}

/// EConVarType (CS2) -> readable type name.
fn type_name(t: u16) -> &'static str {
    match t {
        0 => "bool",
        1 => "int16",
        2 => "uint16",
        3 => "int32",
        4 => "uint32",
        5 => "int64",
        6 => "uint64",
        7 => "float32",
        8 => "float64",
        9 => "string",
        10 => "color",
        11 => "vector2",
        12 => "vector3",
        13 => "vector4",
        14 => "qangle",
        _ => "unknown",
    }
}

/// Decode the value union at `va` per EConVarType. Best-effort — unreadable
/// memory or an unknown type yields a raw hex fallback / empty string.
fn decode_value<P: MemoryView>(process: &mut P, va: u64, type_id: u16) -> String {
    let a = Address::from(va);
    match type_id {
        0 => {
            if process.read::<u8>(a).data_part().unwrap_or(0) != 0 {
                "true".into()
            } else {
                "false".into()
            }
        }
        1 => num(process.read::<i16>(a).data_part()),
        2 => num(process.read::<u16>(a).data_part()),
        3 => num(process.read::<i32>(a).data_part()),
        4 => num(process.read::<u32>(a).data_part()),
        5 => num(process.read::<i64>(a).data_part()),
        6 => num(process.read::<u64>(a).data_part()),
        7 => process
            .read::<f32>(a)
            .data_part()
            .map(fmt_f32)
            .unwrap_or_default(),
        8 => process
            .read::<f64>(a)
            .data_part()
            .map(fmt_f)
            .unwrap_or_default(),
        9 => rd_cstr_at(process, va), // string: char* at +0x58
        10 => {
            let c = rd_u32(process, va);
            format!(
                "{} {} {} {}",
                c & 0xFF,
                (c >> 8) & 0xFF,
                (c >> 16) & 0xFF,
                (c >> 24) & 0xFF
            )
        }
        11 => read_vec(process, va, 2),
        12 | 14 => read_vec(process, va, 3),
        13 => read_vec(process, va, 4),
        _ => format!("0x{:016X}", rd_u64(process, va)),
    }
}

fn read_vec<P: MemoryView>(process: &mut P, va: u64, n: u64) -> String {
    (0..n)
        .map(|i| {
            process
                .read::<f32>(Address::from(va + 4 * i))
                .data_part()
                .map(fmt_f32)
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_flags(flags: u32) -> Vec<&'static str> {
    FCVAR_FLAGS
        .iter()
        .filter(|(m, _)| flags & m != 0)
        .map(|(_, n)| *n)
        .collect()
}

// --- small read helpers (best-effort, never panic) -------------------------

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    process
        .read::<u64>(Address::from(va))
        .data_part()
        .unwrap_or(0)
}

fn rd_u32<P: MemoryView>(process: &mut P, va: u64) -> u32 {
    process
        .read::<u32>(Address::from(va))
        .data_part()
        .unwrap_or(0)
}

fn rd_u16<P: MemoryView>(process: &mut P, va: u64) -> u16 {
    process
        .read::<u16>(Address::from(va))
        .data_part()
        .unwrap_or(LIST_END)
}

fn rd_cstr<P: MemoryView>(process: &mut P, ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    process
        .read_utf8_lossy(Address::from(ptr), 256)
        .data_part()
        .unwrap_or_default()
}

/// Read a `char*` field at `ptr_field_va`, then the C-string it points to.
fn rd_cstr_at<P: MemoryView>(process: &mut P, ptr_field_va: u64) -> String {
    let ptr = rd_u64(process, ptr_field_va);
    rd_cstr(process, ptr)
}

fn num<T: std::fmt::Display, E>(r: Result<T, E>) -> String {
    r.map(|v| v.to_string()).unwrap_or_default()
}

/// `%g`-ish float formatting: Rust's default already drops trailing zeros
/// (`1.0` -> `"1"`, `0.5` -> `"0.5"`), which matches the engine's cvarlist.
fn fmt_f(v: f64) -> String {
    if v == 0.0 { "0".into() } else { format!("{v}") }
}

/// Format an `f32` directly (NOT widened to f64 first) so we get the shortest
/// round-trippable decimal — `1.92f32` prints `"1.92"`, not `"1.9199999570846558"`.
fn fmt_f32(v: f32) -> String {
    if v == 0.0 { "0".into() } else { format!("{v}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memory::fake::FakeMemory;

    /// Convars used by the layout probe tests, as (name, type id, value).
    const SAMPLE_CONVARS: &[(&str, u16)] =
        &[("sv_cheats", 0), ("mp_freezetime", 3), ("cl_name", 9)];
    const SAMPLE_COMMANDS: &[&str] = &["help", "status", "quit"];

    /// Build a `CCvar` instance whose storage uses the given candidate layout,
    /// so the probe has to recover that layout from live data alone.
    fn build_registry(
        mem: &mut FakeMemory,
        cv: (u64, u64, u64, u64),
        cc: (u64, u64, u64, u64),
    ) -> u64 {
        let (cv_base_off, cv_head_off, cv_stride, cv_next_off) = cv;
        let (cc_base_off, cc_head_off, cc_stride, cc_next_off) = cc;

        let inst = mem.alloc(0x200);

        let cv_base = mem.alloc(cv_stride as usize * SAMPLE_CONVARS.len());
        for (index, (name, type_id)) in SAMPLE_CONVARS.iter().enumerate() {
            let info = mem.alloc(0x80);
            let name_ptr = mem.alloc_cstr(name);
            let desc_ptr = mem.alloc_cstr("sample description");
            mem.put_ptr(info + CVI_NAME, name_ptr);
            mem.put_ptr(info + CVI_DESC, desc_ptr);
            mem.put_u16(info + CVI_TYPE, *type_id);
            mem.put_u32(info + CVI_FLAGS, 0x00080000);

            let elem = cv_base + cv_stride * index as u64;
            mem.put_ptr(elem, info);
            let next = if index + 1 == SAMPLE_CONVARS.len() {
                LIST_END
            } else {
                index as u16 + 1
            };
            mem.put_u16(elem + cv_next_off, next);
        }
        mem.put_ptr(inst + cv_base_off, cv_base);
        mem.put_u16(inst + cv_head_off, 0);

        let cc_base = mem.alloc(cc_stride as usize * SAMPLE_COMMANDS.len());
        for (index, name) in SAMPLE_COMMANDS.iter().enumerate() {
            let elem = cc_base + cc_stride * index as u64;
            let name_ptr = mem.alloc_cstr(name);
            let desc_ptr = mem.alloc_cstr("sample command");
            mem.put_ptr(elem + CC_NAME, name_ptr);
            mem.put_ptr(elem + CC_DESC, desc_ptr);
            mem.put_u32(elem + CC_FLAGS, 0x00080000);
            let next = if index + 1 == SAMPLE_COMMANDS.len() {
                LIST_END
            } else {
                index as u16 + 1
            };
            mem.put_u16(elem + cc_next_off, next);
        }
        mem.put_ptr(inst + cc_base_off, cc_base);
        mem.put_u16(inst + cc_head_off, 0);

        inst
    }

    #[test]
    fn default_registry_layout_preserves_known_fallback() {
        let layout = RegistryLayout::default();
        assert_eq!(layout.cv_base, OFF_CV_BASE);
        assert_eq!(layout.cv_head, OFF_CV_HEAD);
        assert_eq!(layout.cv_stride, CV_STRIDE);
        assert_eq!(layout.cv_next, CV_ELEM_NEXT);
        assert_eq!(layout.cc_base, OFF_CC_BASE);
        assert_eq!(layout.cc_head, OFF_CC_HEAD);
        assert_eq!(layout.cc_stride, CC_STRIDE);
        assert_eq!(layout.cc_next, CC_ELEM_NEXT);
    }

    #[test]
    fn plausible_names_reject_pointer_garbage() {
        assert!(plausible_name("sv_cheats"));
        assert!(plausible_name("cmd help text"));
        assert!(!plausible_name(""));
        assert!(!plausible_name("bad\0name"));
        assert!(!plausible_name(&"x".repeat(129)));
    }

    /// Every shipped candidate pair must be recoverable from live list data;
    /// otherwise the probe is decoration and the fallback is the only layout
    /// that ever wins.
    #[test]
    fn detects_every_shipped_candidate_layout_pair() {
        for cv in CV_LAYOUT_CANDIDATES {
            for cc in CC_LAYOUT_CANDIDATES {
                let mut mem = FakeMemory::new();
                let inst = build_registry(&mut mem, *cv, *cc);
                let layout = detect_layout(&mut mem, inst);
                assert_eq!(
                    (
                        layout.cv_base,
                        layout.cv_head,
                        layout.cv_stride,
                        layout.cv_next
                    ),
                    *cv,
                    "convar layout {cv:?} not recovered"
                );
                assert_eq!(
                    (
                        layout.cc_base,
                        layout.cc_head,
                        layout.cc_stride,
                        layout.cc_next
                    ),
                    *cc,
                    "concommand layout {cc:?} not recovered"
                );
            }
        }
    }

    #[test]
    fn an_empty_registry_keeps_the_fallback_layout() {
        let mut mem = FakeMemory::new();
        let inst = mem.alloc(0x200);
        let layout = detect_layout(&mut mem, inst);
        assert_eq!(layout.cv_base, OFF_CV_BASE);
        assert_eq!(layout.cc_base, OFF_CC_BASE);
    }

    #[test]
    fn decodes_each_convar_value_type_from_its_union() {
        let mut mem = FakeMemory::new();
        let info = mem.alloc(0x80);
        let name_ptr = mem.alloc_cstr("sv_gravity");
        mem.put_ptr(info + CVI_NAME, name_ptr);
        mem.put_u16(info + CVI_TYPE, 7); // float32
        mem.put_f32(info + CVI_VALUE, 800.0);
        let convar = read_convar(&mut mem, info).expect("float convar");
        assert_eq!(convar.name, "sv_gravity");
        assert_eq!(convar.type_name, "float32");
        assert_eq!(convar.value, "800");

        mem.put_u16(info + CVI_TYPE, 0); // bool
        mem.put_u8(info + CVI_VALUE, 1);
        assert_eq!(read_convar(&mut mem, info).expect("bool").value, "true");

        mem.put_u16(info + CVI_TYPE, 12); // vector3
        mem.put_f32(info + CVI_VALUE, 1.5);
        mem.put_f32(info + CVI_VALUE + 4, -2.0);
        mem.put_f32(info + CVI_VALUE + 8, 0.25);
        assert_eq!(
            read_convar(&mut mem, info).expect("vector3").value,
            "1.5 -2 0.25"
        );

        mem.put_u16(info + CVI_TYPE, 9); // string: char* in the union slot
        let value_ptr = mem.alloc_cstr("de_dust2");
        mem.put_ptr(info + CVI_VALUE, value_ptr);
        assert_eq!(
            read_convar(&mut mem, info).expect("string").value,
            "de_dust2"
        );
    }

    #[test]
    fn a_nameless_convar_is_rejected_rather_than_emitted_blank() {
        let mut mem = FakeMemory::new();
        let info = mem.alloc(0x80);
        assert!(read_convar(&mut mem, info).is_err());
        assert!(read_concommand(&mut mem, info).is_err());
    }

    /// Base VA of the synthetic tier0 image, away from where [`FakeMemory`]
    /// hands out object addresses.
    const BASE: u64 = 0x0000_7FFA_2000_0000;
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    /// Publish `target` through a global at `rva`, the way tier0 does.
    fn place(image: &mut [u8], rva: u64, target: u64) {
        image[rva as usize..][..8].copy_from_slice(&target.to_le_bytes());
    }

    /// A registry using the shipped fallback layout.
    fn default_registry(mem: &mut FakeMemory) -> u64 {
        build_registry(mem, CV_LAYOUT_CANDIDATES[0], CC_LAYOUT_CANDIDATES[0])
    }

    /// The point of the scan: `g_pCVar` is located by describing the registry,
    /// with no signature over the code that touches it.
    #[test]
    fn finds_the_cvar_registry_global_without_a_signature() {
        let mut mem = FakeMemory::new();
        let inst = default_registry(&mut mem);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, inst);

        assert_eq!(
            find_registry_in(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// The geometry is not assumed either: a build that moved the list arrays
    /// is still recognised, because the scan scores the same candidates the
    /// walker decodes with.
    #[test]
    fn every_shipped_registry_layout_is_recognised_by_the_scan() {
        for (index, cv) in CV_LAYOUT_CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let inst = build_registry(&mut mem, *cv, CC_LAYOUT_CANDIDATES[0]);
            let mut image = image();
            place(&mut image, DATA_RVA + 0x400, inst);

            assert_eq!(
                find_registry_in(&mut mem, &image, BASE, &ranges()),
                Some(BASE + DATA_RVA + 0x400),
                "convar layout {index} ({cv:?}) was not recognised"
            );
        }
    }

    #[test]
    fn a_module_without_a_registry_yields_nothing() {
        let mut mem = FakeMemory::new();
        assert_eq!(find_registry_in(&mut mem, &image(), BASE, &ranges()), None);
    }

    /// Two globals reaching *different* registries mean the scan cannot tell
    /// which one the game uses, and a wrong one dumps confident nonsense, so it
    /// declines. Aliases of one registry are not a contradiction and resolve.
    #[test]
    fn rival_registries_decline_while_aliases_resolve() {
        let mut mem = FakeMemory::new();
        let first = default_registry(&mut mem);
        let second = default_registry(&mut mem);

        let mut rivals = image();
        place(&mut rivals, DATA_RVA + 0x400, first);
        place(&mut rivals, DATA_RVA + 0x1200, second);
        assert_eq!(find_registry_in(&mut mem, &rivals, BASE, &ranges()), None);

        let mut aliases = image();
        place(&mut aliases, DATA_RVA + 0x400, first);
        place(&mut aliases, DATA_RVA + 0x1200, first);
        assert_eq!(
            find_registry_in(&mut mem, &aliases, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// An object whose convar list holds a single node is what a partially
    /// initialised tier0 looks like, so it is below the evidence floor.
    #[test]
    fn a_nearly_empty_registry_is_not_enough_evidence() {
        let mut mem = FakeMemory::new();
        let inst = mem.alloc(0x200);
        let (cv_base_off, cv_head_off, cv_stride, cv_next_off) = CV_LAYOUT_CANDIDATES[0];
        let cv_base = mem.alloc(cv_stride as usize);
        let info = mem.alloc(0x80);
        let name_ptr = mem.alloc_cstr("sv_cheats");
        mem.put_ptr(info + CVI_NAME, name_ptr);
        mem.put_u16(info + CVI_TYPE, 0);
        mem.put_ptr(cv_base, info);
        mem.put_u16(cv_base + cv_next_off, LIST_END);
        mem.put_ptr(inst + cv_base_off, cv_base);
        mem.put_u16(inst + cv_head_off, 0);

        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, inst);
        assert_eq!(find_registry_in(&mut mem, &image, BASE, &ranges()), None);
    }
}
