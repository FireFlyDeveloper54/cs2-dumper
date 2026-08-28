//! Read-only walker for the client.dll **CGameEventManager** — enumerates every
//! registered (legacy Source1) game event with its numeric id and typed field
//! schema, exactly as parsed from the `resource/*.gameevents` files.
//!
//! The walker probes a small set of compatible layouts against live event
//! names, then falls back to the historical layout when validation is
//! inconclusive. It is anchored on the `pGameEventManager` global, or — when
//! that pattern no longer matches — on [`find_manager`], which describes the
//! manager object itself and finds the global holding it in client.dll's
//! writable data.
//! ```text
//! *g_pGameEventManager  ->  CGameEventManager:
//! Default layout:
//!   +0x08  event count (u32)
//!   +0x10  descriptor array base ptr        (stride 88, indexed by event id)
//!   +0xC4  info-vector size/flags (u32, &0x7FFFFFFF)
//!   +0xC8  info-vector base ptr             (stride 32: name char* @+16, id u32 @+24)
//!
//! CGameEventDescriptor (88 bytes):
//!   +0x08  id (u32)   +0x0C  name-index (u32, into info-vector)
//!   +0x28  local flag (u8)
//!   +0x38  key count (u32)   +0x40  keys array base ptr   (key stride 72)
//!
//! Key (72 bytes):  +0x08 name char*   +0x38 description char*   +0x40 type (u32)
//! ```
//! Type ids (from the manager's own string->int table): 1 string, 2 float,
//! 3 int32(long), 4 int16(short), 5 byte, 6 bool, 7 uint64, 8 player_pawn,
//! 9 player_controller, 0 local.

use anyhow::{Result, bail};
use memflow::prelude::v1::*;
use serde::Serialize;

use crate::analysis::global_anchor::{self, AnchorScan, Head};

const MAX_EVENTS: u32 = 4096;
const MAX_KEYS: u32 = 512;

const M_COUNT: u64 = 0x08;
const M_DESC_BASE: u64 = 0x10;
const M_INFO_FLAGS: u64 = 0xC4;
const M_INFO_BASE: u64 = 0xC8;

const DESC_STRIDE: u64 = 88;
const D_ID: u64 = 0x08;
const D_NAME_IDX: u64 = 0x0C;
const D_LOCAL: u64 = 0x28;
const D_KEY_COUNT: u64 = 0x38;
const D_KEYS_BASE: u64 = 0x40;

const INFO_STRIDE: u64 = 32;
const INFO_NAME: u64 = 16;

const KEY_STRIDE: u64 = 72;
const K_NAME: u64 = 0x08;
const K_DESC: u64 = 0x38;
const K_TYPE: u64 = 0x40;

#[inline]
fn indexed_addr(base: u64, stride: u64, index: u64, extra: u64) -> Option<u64> {
    stride
        .checked_mul(index)
        .and_then(|delta| base.checked_add(delta))
        .and_then(|address| address.checked_add(extra))
}

#[derive(Clone, Copy, Debug)]
struct EventLayout {
    manager_count: u64,
    manager_desc_base: u64,
    manager_info_flags: u64,
    manager_info_base: u64,
    desc_stride: u64,
    desc_id: u64,
    desc_name_idx: u64,
    desc_local: u64,
    desc_key_count: u64,
    desc_keys_base: u64,
    info_stride: u64,
    info_name: u64,
    key_stride: u64,
    key_name: u64,
    key_desc: u64,
    key_type: u64,
}

impl Default for EventLayout {
    fn default() -> Self {
        Self {
            manager_count: M_COUNT,
            manager_desc_base: M_DESC_BASE,
            manager_info_flags: M_INFO_FLAGS,
            manager_info_base: M_INFO_BASE,
            desc_stride: DESC_STRIDE,
            desc_id: D_ID,
            desc_name_idx: D_NAME_IDX,
            desc_local: D_LOCAL,
            desc_key_count: D_KEY_COUNT,
            desc_keys_base: D_KEYS_BASE,
            info_stride: INFO_STRIDE,
            info_name: INFO_NAME,
            key_stride: KEY_STRIDE,
            key_name: K_NAME,
            key_desc: K_DESC,
            key_type: K_TYPE,
        }
    }
}

const LAYOUT_CANDIDATES: &[EventLayout] = &[
    EventLayout {
        manager_count: 0x08,
        manager_desc_base: 0x10,
        manager_info_flags: 0xC4,
        manager_info_base: 0xC8,
        desc_stride: 88,
        desc_id: 0x08,
        desc_name_idx: 0x0C,
        desc_local: 0x28,
        desc_key_count: 0x38,
        desc_keys_base: 0x40,
        info_stride: 32,
        info_name: 16,
        key_stride: 72,
        key_name: 0x08,
        key_desc: 0x38,
        key_type: 0x40,
    },
    EventLayout {
        manager_count: 0x10,
        manager_desc_base: 0x18,
        manager_info_flags: 0xCC,
        manager_info_base: 0xD0,
        desc_stride: 88,
        desc_id: 0x08,
        desc_name_idx: 0x0C,
        desc_local: 0x28,
        desc_key_count: 0x38,
        desc_keys_base: 0x40,
        info_stride: 32,
        info_name: 16,
        key_stride: 72,
        key_name: 0x08,
        key_desc: 0x38,
        key_type: 0x40,
    },
    EventLayout {
        manager_count: 0x08,
        manager_desc_base: 0x18,
        manager_info_flags: 0xC4,
        manager_info_base: 0xC8,
        desc_stride: 96,
        desc_id: 0x08,
        desc_name_idx: 0x0C,
        desc_local: 0x2C,
        desc_key_count: 0x40,
        desc_keys_base: 0x48,
        info_stride: 32,
        info_name: 16,
        key_stride: 72,
        key_name: 0x08,
        key_desc: 0x38,
        key_type: 0x40,
    },
];

#[derive(Debug, Serialize)]
pub struct GameEventField {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct GameEvent {
    pub name: String,
    pub id: u32,
    pub local: bool,
    pub fields: Vec<GameEventField>,
}

pub fn walk<P: MemoryView>(process: &mut P, manager_global_va: u64) -> Result<Vec<GameEvent>> {
    let manager = rd_u64(process, manager_global_va);
    if manager == 0 {
        bail!("g_pGameEventManager is null");
    }

    let layout = detect_layout(process, manager);
    let Some(count_addr) = manager.checked_add(layout.manager_count) else {
        bail!("event manager count address overflow");
    };
    let Some(desc_base_addr) = manager.checked_add(layout.manager_desc_base) else {
        bail!("event descriptor base address overflow");
    };
    let Some(info_flags_addr) = manager.checked_add(layout.manager_info_flags) else {
        bail!("event info flags address overflow");
    };
    let count = rd_u32(process, count_addr);
    let desc_base = rd_u64(process, desc_base_addr);
    let info_size = rd_u32(process, info_flags_addr) & 0x7FFF_FFFF;
    let info_base = if info_size != 0 {
        let Some(info_base_addr) = manager.checked_add(layout.manager_info_base) else {
            bail!("event info base address overflow");
        };
        rd_u64(process, info_base_addr)
    } else {
        0
    };
    if desc_base == 0 || count == 0 || count > MAX_EVENTS {
        bail!("game event manager looks unpopulated (count={count})");
    }

    let mut events = Vec::new();
    for id in 0..count {
        let Some(desc) = indexed_addr(desc_base, layout.desc_stride, id as u64, 0) else {
            break;
        };
        // Event name via the info-vector, indexed by the descriptor's name-index.
        let Some(name_idx_addr) = desc.checked_add(layout.desc_name_idx) else {
            continue;
        };
        let name_idx = rd_u32(process, name_idx_addr);
        let name = if info_base != 0 && name_idx < info_size {
            let Some(name_slot) = indexed_addr(
                info_base,
                layout.info_stride,
                name_idx as u64,
                layout.info_name,
            ) else {
                continue;
            };
            let np = rd_u64(process, name_slot);
            rd_cstr(process, np)
        } else {
            String::new()
        };
        if name.is_empty() {
            continue;
        }

        let Some(local_addr) = desc.checked_add(layout.desc_local) else {
            continue;
        };
        let Some(key_count_addr) = desc.checked_add(layout.desc_key_count) else {
            continue;
        };
        let Some(keys_base_addr) = desc.checked_add(layout.desc_keys_base) else {
            continue;
        };
        let local = rd_u8(process, local_addr) != 0;
        let key_count = rd_u32(process, key_count_addr);
        let keys_base = rd_u64(process, keys_base_addr);

        let mut fields = Vec::new();
        if keys_base != 0 && key_count <= MAX_KEYS {
            for k in 0..key_count {
                let Some(key) = indexed_addr(keys_base, layout.key_stride, k as u64, 0) else {
                    break;
                };
                let Some(kname_addr) = key.checked_add(layout.key_name) else {
                    continue;
                };
                let kname_ptr = rd_u64(process, kname_addr);
                let kname = rd_cstr(process, kname_ptr);
                if kname.is_empty() {
                    continue;
                }
                let Some(ktype_addr) = key.checked_add(layout.key_type) else {
                    continue;
                };
                let Some(kdesc_addr) = key.checked_add(layout.key_desc) else {
                    continue;
                };
                let ktype = rd_u32(process, ktype_addr);
                let kdesc_ptr = rd_u64(process, kdesc_addr);
                fields.push(GameEventField {
                    name: kname,
                    type_name: type_name(ktype),
                    description: rd_cstr(process, kdesc_ptr),
                });
            }
        }

        events.push(GameEvent {
            name,
            id: desc
                .checked_add(layout.desc_id)
                .map(|address| rd_u32(process, address))
                .unwrap_or_default(),
            local,
            fields,
        });
    }

    events.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(events)
}

fn detect_layout<P: MemoryView>(process: &mut P, manager: u64) -> EventLayout {
    let mut best = EventLayout::default();
    let mut best_score = 0usize;
    for candidate in LAYOUT_CANDIDATES {
        let score = score_layout(process, manager, *candidate);
        if score > best_score {
            best_score = score;
            best = *candidate;
        }
    }
    if best_score >= 2 {
        best
    } else {
        EventLayout::default()
    }
}

fn score_layout<P: MemoryView>(process: &mut P, manager: u64, layout: EventLayout) -> usize {
    let Some(count_addr) = manager.checked_add(layout.manager_count) else {
        return 0;
    };
    let Some(desc_base_addr) = manager.checked_add(layout.manager_desc_base) else {
        return 0;
    };
    let Some(info_flags_addr) = manager.checked_add(layout.manager_info_flags) else {
        return 0;
    };
    let Some(info_base_addr) = manager.checked_add(layout.manager_info_base) else {
        return 0;
    };
    let count = rd_u32(process, count_addr);
    let desc_base = rd_u64(process, desc_base_addr);
    let info_size = rd_u32(process, info_flags_addr) & 0x7FFF_FFFF;
    let info_base = rd_u64(process, info_base_addr);
    if !(1..=MAX_EVENTS).contains(&count)
        || desc_base < 0x10000
        || !(1..=8192).contains(&info_size)
        || info_base < 0x10000
    {
        return 0;
    }
    let mut score = 0;
    for id in 0..count.min(8) {
        let Some(desc) = indexed_addr(desc_base, layout.desc_stride, id as u64, 0) else {
            break;
        };
        let Some(name_idx_addr) = desc.checked_add(layout.desc_name_idx) else {
            continue;
        };
        let name_idx = rd_u32(process, name_idx_addr);
        if name_idx >= info_size {
            continue;
        }
        let Some(name_slot) = indexed_addr(
            info_base,
            layout.info_stride,
            name_idx as u64,
            layout.info_name,
        ) else {
            continue;
        };
        let name_ptr = rd_u64(process, name_slot);
        if plausible_name(&rd_cstr(process, name_ptr)) {
            score += 1;
        }
    }
    score
}

fn plausible_name(name: &str) -> bool {
    let len = name.len();
    (1..=128).contains(&len) && name.bytes().all(|b| b.is_ascii_graphic() || b == b'_')
}

// --- signature-free discovery of the `g_pGameEventManager` global ----------

/// Bytes of a candidate manager read in one block, covering the furthest
/// candidate field (`manager_info_base` at 0xD0).
const MANAGER_HEAD_SPAN: usize = 0xD8;

/// Named events a candidate must account for. [`score_layout`] looks at the
/// first eight descriptors, so this asks for half of them — a manager that is
/// registered at all has hundreds.
const MANAGER_MIN_EVIDENCE: usize = 4;

/// Every gate field comes out of the head block, so gating a candidate costs no
/// reads beyond the one the scan already made; the budget can be generous.
const MANAGER_SCAN: AnchorScan = AnchorScan {
    head_span: MANAGER_HEAD_SPAN,
    min_evidence: MANAGER_MIN_EVIDENCE,
    max_probes: 256,
};

/// Locate the `g_pGameEventManager` global in `module` by describing the
/// manager it points at, so the event dump survives a recompile that
/// invalidates the `pGameEventManager` signature.
pub fn find_manager<P: Process + MemoryView>(process: &mut P, module: &str) -> Option<u64> {
    global_anchor::find_in_module(process, module, MANAGER_SCAN, gate_manager, score_manager)
}

/// How much evidence `manager` presents as an event manager, under whichever
/// candidate layout fits it best.
fn score_manager<P: MemoryView>(process: &mut P, manager: u64) -> usize {
    LAYOUT_CANDIDATES
        .iter()
        .map(|candidate| score_layout(process, manager, *candidate))
        .max()
        .unwrap_or(0)
}

/// Cheap gate: under some candidate layout the manager holds a plausible event
/// count and two populated vectors. Every field is already in the head block,
/// so a pointer leading nowhere costs nothing beyond the scan's own read.
fn gate_manager<P: MemoryView>(_process: &mut P, head: &Head) -> bool {
    LAYOUT_CANDIDATES.iter().any(|layout| {
        let count = head.u32(layout.manager_count);
        let info_size = head.u32(layout.manager_info_flags) & 0x7FFF_FFFF;
        (1..=MAX_EVENTS).contains(&count)
            && head.u64(layout.manager_desc_base) >= 0x10000
            && (1..=8192).contains(&info_size)
            && head.u64(layout.manager_info_base) >= 0x10000
    })
}

/// The same scan against a caller-supplied module image, so the policy can be
/// exercised without a live process.
#[cfg(test)]
fn find_manager_in<P: MemoryView>(
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
        MANAGER_SCAN,
        gate_manager,
        score_manager,
    )
}

fn type_name(t: u32) -> &'static str {
    match t {
        0 => "local",
        1 => "string",
        2 => "float",
        3 => "int32",
        4 => "int16",
        5 => "byte",
        6 => "bool",
        7 => "uint64",
        8 => "player_pawn",
        9 => "player_controller",
        _ => "unknown",
    }
}

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    crate::analysis::read::u64_va(process, va)
}
fn rd_u32<P: MemoryView>(process: &mut P, va: u64) -> u32 {
    crate::analysis::read::u32_va(process, va)
}
fn rd_u8<P: MemoryView>(process: &mut P, va: u64) -> u8 {
    crate::analysis::read::u8_va(process, va)
}
fn rd_cstr<P: MemoryView>(process: &mut P, ptr: u64) -> String {
    crate::analysis::read::cstr(process, ptr)
}

#[cfg(test)]
mod tests {
    use super::{
        EventLayout, LAYOUT_CANDIDATES, detect_layout, find_manager_in, plausible_name, walk,
    };
    use crate::memory::fake::FakeMemory;

    /// One event built into the fake manager: name, id, local flag, and its
    /// `(field name, type id)` schema.
    type SampleEvent = (&'static str, u32, bool, &'static [(&'static str, u32)]);

    const SAMPLE: &[SampleEvent] = &[
        (
            "player_death",
            5,
            false,
            &[("userid", 9), ("attacker", 9), ("headshot", 6)],
        ),
        ("round_start", 6, false, &[("timelimit", 3)]),
        ("local_only", 7, true, &[]),
    ];

    /// Build a `CGameEventManager` laid out per `layout`, including the
    /// name info-vector the descriptors index into.
    fn build_manager(mem: &mut FakeMemory, layout: EventLayout) -> u64 {
        build_manager_from(mem, layout, SAMPLE)
    }

    /// The same, over an arbitrary event list, so the anchor scan can be given
    /// a manager carrying more than the walk tests need.
    fn build_manager_from(
        mem: &mut FakeMemory,
        layout: EventLayout,
        events: &[SampleEvent],
    ) -> u64 {
        let manager = mem.alloc(0x200);
        let desc_base = mem.alloc(layout.desc_stride as usize * events.len());
        let info_base = mem.alloc(layout.info_stride as usize * events.len());

        for (index, (name, id, local, fields)) in events.iter().enumerate() {
            let name_ptr = mem.alloc_cstr(name);
            mem.put_ptr(
                info_base + layout.info_stride * index as u64 + layout.info_name,
                name_ptr,
            );

            let desc = desc_base + layout.desc_stride * index as u64;
            mem.put_u32(desc + layout.desc_id, *id);
            mem.put_u32(desc + layout.desc_name_idx, index as u32);
            mem.put_u8(desc + layout.desc_local, u8::from(*local));
            mem.put_u32(desc + layout.desc_key_count, fields.len() as u32);
            if fields.is_empty() {
                continue;
            }
            let keys_base = mem.alloc(layout.key_stride as usize * fields.len());
            mem.put_ptr(desc + layout.desc_keys_base, keys_base);
            for (slot, (field, type_id)) in fields.iter().enumerate() {
                let key = keys_base + layout.key_stride * slot as u64;
                let field_ptr = mem.alloc_cstr(field);
                let desc_ptr = mem.alloc_cstr("field help");
                mem.put_ptr(key + layout.key_name, field_ptr);
                mem.put_ptr(key + layout.key_desc, desc_ptr);
                mem.put_u32(key + layout.key_type, *type_id);
            }
        }

        mem.put_u32(manager + layout.manager_count, events.len() as u32);
        mem.put_ptr(manager + layout.manager_desc_base, desc_base);
        mem.put_u32(manager + layout.manager_info_flags, events.len() as u32);
        mem.put_ptr(manager + layout.manager_info_base, info_base);
        manager
    }

    #[test]
    fn default_layout_preserves_event_offsets() {
        let layout = EventLayout::default();
        assert_eq!(layout.manager_count, 0x08);
        assert_eq!(layout.desc_stride, 88);
        assert_eq!(layout.key_stride, 72);
    }

    #[test]
    fn event_names_are_sanity_checked() {
        assert!(plausible_name("player_spawn"));
        assert!(!plausible_name(""));
        assert!(!plausible_name("bad name"));
    }

    #[test]
    fn detects_every_shipped_candidate_layout() {
        for (index, candidate) in LAYOUT_CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let manager = build_manager(&mut mem, *candidate);
            let detected = detect_layout(&mut mem, manager);
            assert_eq!(
                (
                    detected.manager_count,
                    detected.manager_desc_base,
                    detected.desc_stride,
                    detected.desc_local
                ),
                (
                    candidate.manager_count,
                    candidate.manager_desc_base,
                    candidate.desc_stride,
                    candidate.desc_local
                ),
                "candidate {index} was not recovered"
            );
        }
    }

    #[test]
    fn walks_events_with_their_typed_fields() {
        let mut mem = FakeMemory::new();
        let layout = EventLayout::default();
        let manager = build_manager(&mut mem, layout);
        let global = mem.alloc(0x8);
        mem.put_ptr(global, manager);

        let events = walk(&mut mem, global).expect("walk");

        // Sorted by name.
        let names: Vec<_> = events.iter().map(|event| event.name.as_str()).collect();
        assert_eq!(names, vec!["local_only", "player_death", "round_start"]);

        let death = &events[1];
        assert_eq!(death.id, 5);
        assert!(!death.local);
        let fields: Vec<_> = death
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.type_name))
            .collect();
        assert_eq!(
            fields,
            vec![
                ("userid", "player_controller"),
                ("attacker", "player_controller"),
                ("headshot", "bool"),
            ]
        );
        assert_eq!(death.fields[0].description, "field help");
        assert!(events[0].local);
        assert!(events[0].fields.is_empty());
    }

    #[test]
    fn a_null_manager_global_is_an_error_not_an_empty_dump() {
        let mut mem = FakeMemory::new();
        let global = mem.alloc(0x8);
        assert!(walk(&mut mem, global).is_err());
    }

    /// Base VA of the synthetic client image, away from where [`FakeMemory`]
    /// hands out object addresses.
    const BASE: u64 = 0x0000_7FFA_3000_0000;
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    /// Enough registered events to clear the evidence floor, which a
    /// half-initialised manager would not.
    const REGISTERED: &[SampleEvent] = &[
        ("player_death", 5, false, &[("userid", 9)]),
        ("player_spawn", 6, false, &[]),
        ("round_start", 7, false, &[("timelimit", 3)]),
        ("round_end", 8, false, &[]),
        ("bomb_planted", 9, false, &[("site", 3)]),
        ("bomb_defused", 10, false, &[]),
    ];

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    /// Publish `target` through a global at `rva`, the way client.dll does.
    fn place(image: &mut [u8], rva: u64, target: u64) {
        image[rva as usize..][..8].copy_from_slice(&target.to_le_bytes());
    }

    /// The point of the scan: `g_pGameEventManager` is located by describing the
    /// manager, with no signature over the code that touches it.
    #[test]
    fn finds_the_event_manager_global_without_a_signature() {
        let mut mem = FakeMemory::new();
        let manager = build_manager_from(&mut mem, EventLayout::default(), REGISTERED);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, manager);

        assert_eq!(
            find_manager_in(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// The geometry is not assumed either: a build that moved the descriptor or
    /// info vectors is still recognised, because the scan scores the same
    /// candidates the walker decodes with.
    #[test]
    fn every_shipped_layout_is_recognised_by_the_scan() {
        for (index, candidate) in LAYOUT_CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let manager = build_manager_from(&mut mem, *candidate, REGISTERED);
            let mut image = image();
            place(&mut image, DATA_RVA + 0x400, manager);

            assert_eq!(
                find_manager_in(&mut mem, &image, BASE, &ranges()),
                Some(BASE + DATA_RVA + 0x400),
                "candidate {index} was not recognised"
            );
        }
    }

    #[test]
    fn a_module_without_an_event_manager_yields_nothing() {
        let mut mem = FakeMemory::new();
        assert_eq!(find_manager_in(&mut mem, &image(), BASE, &ranges()), None);
    }

    /// A manager with a couple of named events is what one looks like before
    /// the `.gameevents` files are parsed, so it is below the evidence floor.
    #[test]
    fn a_barely_populated_manager_is_not_enough_evidence() {
        let mut mem = FakeMemory::new();
        let manager = build_manager_from(&mut mem, EventLayout::default(), &REGISTERED[..3]);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, manager);

        assert_eq!(find_manager_in(&mut mem, &image, BASE, &ranges()), None);
    }

    /// Two globals reaching *different* managers mean the scan cannot tell which
    /// one the game raises events through, so it declines. Aliases of one
    /// manager are not a contradiction and resolve to the first global.
    #[test]
    fn rival_managers_decline_while_aliases_resolve() {
        let mut mem = FakeMemory::new();
        let layout = EventLayout::default();
        let first = build_manager_from(&mut mem, layout, REGISTERED);
        let second = build_manager_from(&mut mem, layout, REGISTERED);

        let mut rivals = image();
        place(&mut rivals, DATA_RVA + 0x400, first);
        place(&mut rivals, DATA_RVA + 0x1200, second);
        assert_eq!(find_manager_in(&mut mem, &rivals, BASE, &ranges()), None);

        let mut aliases = image();
        place(&mut aliases, DATA_RVA + 0x400, first);
        place(&mut aliases, DATA_RVA + 0x1200, first);
        assert_eq!(
            find_manager_in(&mut mem, &aliases, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }
}
