//! Runtime validation for the chunked `CGameEntitySystem` list geometry.
//!
//! The list has been stable across many CS2 builds, but its surrounding
//! object has moved before. Probe a small set of compatible layouts against
//! live designer names so entity and weapon snapshots share one decision.

use memflow::prelude::v1::*;

pub const SLOT_INDEX_MASK: u32 = 0x1FF;
pub const HANDLE_INDEX_MASK: u32 = 0x7FFF;
pub const MAX_ENTITY_INDEX: u32 = HANDLE_INDEX_MASK + 1;

#[derive(Clone, Copy, Debug)]
pub struct EntityListLayout {
    pub chunk_array_base: u64,
    pub chunk_ptr_stride: u64,
    pub chunk_entry_stride: u64,
    pub identity_instance: u64,
    pub identity_designer_name: u64,
}

impl Default for EntityListLayout {
    fn default() -> Self {
        Self {
            chunk_array_base: 0x10,
            chunk_ptr_stride: 0x8,
            chunk_entry_stride: 0x70,
            identity_instance: 0x00,
            identity_designer_name: 0x20,
        }
    }
}

/// Layouts seen across shipped builds, most likely first. Public so the
/// signature-free anchor scan recognises the object by the same geometry the
/// walkers decode it with.
pub const CANDIDATES: &[EntityListLayout] = &[
    EntityListLayout {
        chunk_array_base: 0x10,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x70,
        identity_instance: 0x00,
        identity_designer_name: 0x20,
    },
    EntityListLayout {
        chunk_array_base: 0x18,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x70,
        identity_instance: 0x00,
        identity_designer_name: 0x20,
    },
    EntityListLayout {
        chunk_array_base: 0x08,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x70,
        identity_instance: 0x00,
        identity_designer_name: 0x20,
    },
    EntityListLayout {
        chunk_array_base: 0x10,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x68,
        identity_instance: 0x00,
        identity_designer_name: 0x20,
    },
    EntityListLayout {
        chunk_array_base: 0x10,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x78,
        identity_instance: 0x00,
        identity_designer_name: 0x20,
    },
    EntityListLayout {
        chunk_array_base: 0x10,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x70,
        identity_instance: 0x00,
        identity_designer_name: 0x18,
    },
    EntityListLayout {
        chunk_array_base: 0x10,
        chunk_ptr_stride: 0x8,
        chunk_entry_stride: 0x70,
        identity_instance: 0x00,
        identity_designer_name: 0x28,
    },
];

pub fn detect_layout<P: MemoryView>(process: &mut P, list: u64) -> EntityListLayout {
    let mut best = EntityListLayout::default();
    let mut best_score = 0usize;
    for candidate in CANDIDATES {
        let score = score_layout(process, list, *candidate);
        if score > best_score {
            best_score = score;
            best = *candidate;
        }
    }
    if best_score >= 2 {
        best
    } else {
        EntityListLayout::default()
    }
}

/// How well `list` matches *any* compatible layout: the count of live
/// identities the best-fitting geometry finds, saturating at 16.
///
/// [`detect_layout`] answers "which layout does this list use"; this answers
/// "is this a list at all", which is what [`crate::analysis::entity_anchor`]
/// needs to recognise the object without a signature.
pub fn score_list<P: MemoryView>(process: &mut P, list: u64) -> usize {
    CANDIDATES
        .iter()
        .map(|candidate| score_layout(process, list, *candidate))
        .max()
        .unwrap_or(0)
}

/// One live entity as the list identifies it, before any schema field is read.
#[derive(Clone, Debug)]
pub struct LiveEntity {
    pub index: u32,
    /// Designer name — `weapon_ak47`, `cs_gamerules`, `player`.
    pub classname: String,
    /// The object schema fields are decoded from.
    pub instance: u64,
}

/// Every live entity in `list`, in index order.
///
/// The walk is shared because three callers need the same thing from it and
/// disagreeing about the geometry would be worse than the duplication: the
/// entity snapshot decodes `C_BaseEntity` fields per entity, the offset recovery
/// in [`crate::analysis::dyn_offsets`] only wants entities identified by name,
/// and both must see the list the same way.
pub fn live_entities<P: MemoryView>(
    process: &mut P,
    list: u64,
    layout: EntityListLayout,
) -> Vec<LiveEntity> {
    let mut out = Vec::new();
    let mut cached_chunk_index = u32::MAX;
    let mut cached_chunk = 0u64;

    for index in 0..MAX_ENTITY_INDEX {
        let slot = index & HANDLE_INDEX_MASK;
        let chunk_index = slot >> 9;
        if chunk_index != cached_chunk_index {
            cached_chunk_index = chunk_index;
            let Some(chunk_slot) = list.checked_add(layout.chunk_array_base).and_then(|value| {
                layout
                    .chunk_ptr_stride
                    .checked_mul(chunk_index as u64)
                    .and_then(|stride| value.checked_add(stride))
            }) else {
                continue;
            };
            cached_chunk = rd_u64(process, chunk_slot);
        }
        if cached_chunk == 0 {
            continue;
        }
        let Some(ident) = layout
            .chunk_entry_stride
            .checked_mul((slot & SLOT_INDEX_MASK) as u64)
            .and_then(|stride| cached_chunk.checked_add(stride))
        else {
            continue;
        };
        let Some(instance_addr) = ident.checked_add(layout.identity_instance) else {
            continue;
        };
        let instance = rd_u64(process, instance_addr);
        if instance == 0 {
            continue;
        }
        let Some(name_addr) = ident.checked_add(layout.identity_designer_name) else {
            continue;
        };
        let name_ptr = rd_u64(process, name_addr);
        let classname = rd_cstr(process, name_ptr);
        if classname.is_empty() {
            continue;
        }
        out.push(LiveEntity {
            index,
            classname,
            instance,
        });
    }

    out
}

fn score_layout<P: MemoryView>(process: &mut P, list: u64, layout: EntityListLayout) -> usize {
    if list < 0x10000 {
        return 0;
    }
    // Chunk 0 must sit exactly at `chunk_array_base`. Without this gate a
    // candidate whose base is one slot too early still sees the whole array
    // (it just starts with a junk slot) and ties with the correct layout,
    // which the first-wins tie-break would then resolve the wrong way.
    let Some(first_chunk_slot) = list.checked_add(layout.chunk_array_base) else {
        return 0;
    };
    if rd_u64(process, first_chunk_slot) < 0x10000 {
        return 0;
    }
    let mut score = 0;
    for chunk_index in 0..8u64 {
        let Some(chunk_slot) = list.checked_add(layout.chunk_array_base).and_then(|value| {
            layout
                .chunk_ptr_stride
                .checked_mul(chunk_index)
                .and_then(|stride| value.checked_add(stride))
        }) else {
            break;
        };
        let chunk = rd_u64(process, chunk_slot);
        if chunk < 0x10000 {
            continue;
        }
        for slot in 0..32u64 {
            let Some(ident) = layout
                .chunk_entry_stride
                .checked_mul(slot)
                .and_then(|stride| chunk.checked_add(stride))
            else {
                continue;
            };
            let Some(inst_addr) = ident.checked_add(layout.identity_instance) else {
                continue;
            };
            let Some(name_addr) = ident.checked_add(layout.identity_designer_name) else {
                continue;
            };
            let inst = rd_u64(process, inst_addr);
            let name_ptr = rd_u64(process, name_addr);
            if inst >= 0x10000 && plausible_name(&rd_cstr(process, name_ptr)) {
                score += 1;
                if score >= 16 {
                    return score;
                }
            }
        }
    }
    score
}

/// A designer name is short printable text (`weapon_ak47`, `worldent`). Public
/// so the anchor scan's cheap gate spells "looks like an entity" the same way
/// the layout probe does.
pub fn plausible_name(name: &str) -> bool {
    let len = name.len();
    (1..=128).contains(&len) && name.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    crate::analysis::read::u64_va(process, va)
}

fn rd_cstr<P: MemoryView>(process: &mut P, ptr: u64) -> String {
    crate::analysis::read::cstr(process, ptr)
}

/// Test-only builders for a `CGameEntitySystem`-shaped list. Shared so the
/// entity-snapshot and weapon walkers are exercised against one description of
/// the geometry instead of two hand-rolled copies that can drift apart.
#[cfg(test)]
pub mod fixture {
    use std::collections::BTreeMap;

    use super::{EntityListLayout, HANDLE_INDEX_MASK, SLOT_INDEX_MASK};
    use crate::memory::fake::FakeMemory;

    /// Builds a list incrementally so a test can place identities at arbitrary
    /// entity indices, including indices that land in a later chunk.
    pub struct ListBuilder {
        layout: EntityListLayout,
        list: u64,
        chunks: BTreeMap<u32, u64>,
    }

    impl ListBuilder {
        pub fn new(mem: &mut FakeMemory) -> Self {
            Self {
                layout: EntityListLayout::default(),
                list: mem.alloc(0x400),
                chunks: BTreeMap::new(),
            }
        }

        /// Reserve chunk `chunk_index`, publishing its pointer in the chunk
        /// array the way the game does.
        fn chunk(&mut self, mem: &mut FakeMemory, chunk_index: u32) -> u64 {
            if let Some(chunk) = self.chunks.get(&chunk_index) {
                return *chunk;
            }
            let slots = SLOT_INDEX_MASK as usize + 1;
            let chunk = mem.alloc(self.layout.chunk_entry_stride as usize * slots);
            mem.put_ptr(
                self.list
                    + self.layout.chunk_array_base
                    + self.layout.chunk_ptr_stride * chunk_index as u64,
                chunk,
            );
            self.chunks.insert(chunk_index, chunk);
            chunk
        }

        /// VA of the `CEntityIdentity` slot entity `index` lives in.
        pub fn identity(&mut self, mem: &mut FakeMemory, index: u32) -> u64 {
            let i = index & HANDLE_INDEX_MASK;
            let chunk = self.chunk(mem, i >> 9);
            chunk + self.layout.chunk_entry_stride * (i & SLOT_INDEX_MASK) as u64
        }

        /// Place a live identity at `index` and return its instance VA, which is
        /// where a walker decodes schema fields from.
        pub fn place(&mut self, mem: &mut FakeMemory, index: u32, classname: &str) -> u64 {
            let ident = self.identity(mem, index);
            let instance = mem.alloc(0x600);
            let name = mem.alloc_cstr(classname);
            mem.put_ptr(ident + self.layout.identity_instance, instance);
            mem.put_ptr(ident + self.layout.identity_designer_name, name);
            instance
        }

        /// VA of the list object itself, which is what a global points at.
        pub fn list(&self) -> u64 {
            self.list
        }

        /// Publish the list through a global pointer, the way a walk finds it.
        pub fn global(&self, mem: &mut FakeMemory) -> u64 {
            let global = mem.alloc(0x8);
            mem.put_ptr(global, self.list());
            global
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CANDIDATES, EntityListLayout, detect_layout, plausible_name};
    use crate::memory::fake::FakeMemory;

    /// Build a `CGameEntitySystem`-shaped object using `layout`, with
    /// `per_chunk` live identities in each of `chunks` chunks.
    fn build_list(
        mem: &mut FakeMemory,
        layout: EntityListLayout,
        chunks: usize,
        per_chunk: usize,
    ) -> u64 {
        let list = mem.alloc(0x100);
        for chunk_index in 0..chunks as u64 {
            let chunk = mem.alloc(layout.chunk_entry_stride as usize * 64);
            mem.put_ptr(
                list + layout.chunk_array_base + layout.chunk_ptr_stride * chunk_index,
                chunk,
            );
            for slot in 0..per_chunk as u64 {
                let ident = chunk + layout.chunk_entry_stride * slot;
                let instance = mem.alloc(0x10);
                let name = mem.alloc_cstr("weapon_ak47");
                mem.put_ptr(ident + layout.identity_instance, instance);
                mem.put_ptr(ident + layout.identity_designer_name, name);
            }
        }
        list
    }

    fn same_layout(a: EntityListLayout, b: EntityListLayout) -> bool {
        a.chunk_array_base == b.chunk_array_base
            && a.chunk_ptr_stride == b.chunk_ptr_stride
            && a.chunk_entry_stride == b.chunk_entry_stride
            && a.identity_instance == b.identity_instance
            && a.identity_designer_name == b.identity_designer_name
    }

    #[test]
    fn rejects_pointer_like_entity_names() {
        assert!(plausible_name("weapon_ak47"));
        assert!(plausible_name("worldent"));
        assert!(!plausible_name(""));
        assert!(!plausible_name("bad\0name"));
    }

    /// The point of the probe: a build that moved the chunk array or widened
    /// the identity stride is detected from live data, not from a constant.
    #[test]
    fn detects_every_shipped_candidate_layout_from_live_data() {
        for (index, candidate) in CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let list = build_list(&mut mem, *candidate, 2, 8);
            let detected = detect_layout(&mut mem, list);
            assert!(
                same_layout(detected, *candidate),
                "candidate {index} ({candidate:?}) was not recovered, got {detected:?}"
            );
        }
    }

    #[test]
    fn falls_back_to_the_compatible_layout_without_enough_evidence() {
        let mut mem = FakeMemory::new();
        // A single live identity is below the two-hit confidence floor.
        let moved = CANDIDATES[1];
        let list = build_list(&mut mem, moved, 1, 1);
        assert!(same_layout(
            detect_layout(&mut mem, list),
            EntityListLayout::default()
        ));
    }

    #[test]
    fn an_unreadable_list_pointer_does_not_panic_or_invent_a_layout() {
        let mut mem = FakeMemory::new();
        assert!(same_layout(
            detect_layout(&mut mem, 0),
            EntityListLayout::default()
        ));
        assert!(same_layout(
            detect_layout(&mut mem, 0x7FF6_DEAD_0000),
            EntityListLayout::default()
        ));
    }
}
