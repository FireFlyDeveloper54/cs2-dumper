//! Signature-free discovery of the `CGameEntitySystem` global.
//!
//! The entity walks (and the weapon snapshot built on them) start from a global
//! pointer in `client.dll` that today is located by a hand-authored byte
//! pattern. That pattern describes the *code* that touches the global, so every
//! Valve recompile can invalidate it and cost a manual re-authoring — while the
//! object itself is perfectly recognisable: a chunked array of
//! `CEntityIdentity` whose live slots carry an instance pointer and a printable
//! designer name (`weapon_ak47`, `worldent`).
//!
//! So the global is found by description instead. Every 8-byte-aligned slot of
//! the module's writable data is treated as a candidate pointer, and the one
//! whose target validates best under [`entity_list::score_list`] wins. The
//! geometry is not assumed: scoring tries the same candidate layouts the
//! walkers decode with, so a build that moved the chunk array is still found.
//!
//! Two properties keep this honest. It declines when two *different* objects
//! tie, because a wrong entity list dumps confident nonsense while a missing
//! one only loses a section. And it is bounded: a module's data holds far more
//! pointers than can be followed over a slow connector, so distinct targets and
//! full validations are both capped, and the cheap gate costs one read for a
//! pointer that leads nowhere.

use std::collections::BTreeMap;

use memflow::prelude::v1::*;

use crate::analysis::entity_list::{self, EntityListLayout};
use crate::analysis::global_anchor::{self, AnchorScan, Head};

/// Live identities a candidate must account for. [`entity_list::score_list`]
/// stops counting at 16, so this asks for half a probe's worth of evidence.
const MIN_EVIDENCE: usize = 8;

/// Bytes read to gate one candidate chunk, covering every candidate layout's
/// `identity_instance` and `identity_designer_name`.
const IDENTITY_SPAN: usize = 0x30;

/// Scoring a list walks up to eight chunks of thirty-two slots under seven
/// layouts, so the probe budget is deliberately small; the gate needs a
/// readable designer name, and junk almost never gets that far.
const SCAN: AnchorScan = AnchorScan {
    // Covers every candidate layout's `chunk_array_base`.
    head_span: 0x20,
    min_evidence: MIN_EVIDENCE,
    max_probes: 64,
};

/// Locate `module`'s entity-system global by scanning its writable data.
pub fn find_in_module<P: Process + MemoryView>(process: &mut P, module: &str) -> Option<u64> {
    global_anchor::find_in_module(
        process,
        module,
        SCAN,
        looks_like_list,
        entity_list::score_list,
    )
}

/// Scan `ranges` (`(rva, size)` pairs into `image`, a live copy of the module at
/// `base`) for the global pointing at the entity system, returning the VA of
/// the *global* — what a walker dereferences — not of the object.
pub fn find_entity_system<P: MemoryView>(
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
        SCAN,
        looks_like_list,
        entity_list::score_list,
    )
}

/// Cheap gate: under some candidate layout, chunk 0 exists and its first
/// identity is live and carries a printable designer name.
fn looks_like_list<P: MemoryView>(mem: &mut P, head: &Head) -> bool {
    let mut chunks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

    entity_list::CANDIDATES
        .iter()
        .any(|layout| identity_is_live(mem, head, &mut chunks, *layout))
}

/// One layout's verdict on the gated object, reusing chunk reads across the
/// layouts that agree on where the chunk array starts.
fn identity_is_live<P: MemoryView>(
    mem: &mut P,
    head: &Head,
    chunks: &mut BTreeMap<u64, Vec<u8>>,
    layout: EntityListLayout,
) -> bool {
    let chunk = head.u64(layout.chunk_array_base);
    if chunk < 0x10000 {
        return false;
    }
    let identity = chunks
        .entry(chunk)
        .or_insert_with(|| read_block(mem, chunk, IDENTITY_SPAN));
    if block_u64(identity, layout.identity_instance) < 0x10000 {
        return false;
    }
    let name_ptr = block_u64(identity, layout.identity_designer_name);
    name_ptr >= 0x10000 && entity_list::plausible_name(&read_cstr(mem, name_ptr))
}

/// Bytes at `va`, or empty when nothing there is readable. A block that runs
/// off the end of a mapped region keeps what it got, and [`block_u64`] then
/// reads the truncated tail as null.
fn read_block<P: MemoryView>(mem: &mut P, va: u64, len: usize) -> Vec<u8> {
    mem.read_raw(Address::from(va), len)
        .data_part()
        .unwrap_or_default()
}

fn block_u64(block: &[u8], at: u64) -> u64 {
    let at = at as usize;
    block
        .get(at..at + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn read_cstr<P: MemoryView>(mem: &mut P, va: u64) -> String {
    mem.read_utf8_lossy(Address::from(va), 128)
        .data_part()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{MIN_EVIDENCE, find_entity_system};
    use crate::analysis::entity_list::{self, EntityListLayout};
    use crate::memory::fake::FakeMemory;

    /// Base VA of the synthetic module image, well away from where
    /// [`FakeMemory`] hands out object addresses.
    const BASE: u64 = 0x0000_7FFA_1000_0000;
    /// RVA and size of its writable data section.
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    /// Publish `target` through a global at `rva`, the way the game does.
    fn place(image: &mut [u8], rva: u64, target: u64) {
        image[rva as usize..][..8].copy_from_slice(&target.to_le_bytes());
    }

    /// A `CGameEntitySystem`-shaped object using `layout`, with `live` live
    /// identities in chunk 0.
    fn list(mem: &mut FakeMemory, layout: EntityListLayout, live: usize) -> u64 {
        let list = mem.alloc(0x100);
        let chunk = mem.alloc(layout.chunk_entry_stride as usize * 64);
        mem.put_ptr(list + layout.chunk_array_base, chunk);
        for slot in 0..live as u64 {
            let identity = chunk + layout.chunk_entry_stride * slot;
            let instance = mem.alloc(0x10);
            let name = mem.alloc_cstr("weapon_ak47");
            mem.put_ptr(identity + layout.identity_instance, instance);
            mem.put_ptr(identity + layout.identity_designer_name, name);
        }
        list
    }

    /// The point of the scan: the global is located by describing the object it
    /// points at, with no signature over the code that touches it.
    #[test]
    fn finds_the_entity_system_global_without_a_signature() {
        let mut mem = FakeMemory::new();
        let list = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, list);

        assert_eq!(
            find_entity_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// The geometry is not assumed either: a build that moved the chunk array
    /// or widened the identity stride is still recognised.
    #[test]
    fn every_shipped_layout_is_recognised_by_the_scan() {
        for (index, layout) in entity_list::CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let list = list(&mut mem, *layout, MIN_EVIDENCE);
            let mut image = image();
            place(&mut image, DATA_RVA + 0x400, list);

            assert_eq!(
                find_entity_system(&mut mem, &image, BASE, &ranges()),
                Some(BASE + DATA_RVA + 0x400),
                "layout {index} ({layout:?}) was not recognised"
            );
        }
    }

    #[test]
    fn a_module_without_an_entity_system_yields_nothing() {
        let mut mem = FakeMemory::new();
        assert_eq!(
            find_entity_system(&mut mem, &image(), BASE, &ranges()),
            None
        );
    }

    /// A handful of live identities is what a torn-down or not-yet-populated
    /// object looks like too, so it is not enough to publish an anchor on.
    #[test]
    fn a_nearly_empty_list_is_not_enough_evidence() {
        let mut mem = FakeMemory::new();
        let list = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE - 1);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, list);

        assert_eq!(find_entity_system(&mut mem, &image, BASE, &ranges()), None);
    }

    /// The game publishes the entity system through more than one pointer.
    /// Those are aliases of one object, not a contradiction, so the scan still
    /// resolves it — and reports the first global, which is stable across runs.
    #[test]
    fn aliases_of_one_entity_system_still_resolve() {
        let mut mem = FakeMemory::new();
        let list = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, list);
        place(&mut image, DATA_RVA + 0x1200, list);

        assert_eq!(
            find_entity_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// Two globals reaching *different* objects mean the scan does not actually
    /// know which one the game walks, and a wrong entity list dumps confident
    /// nonsense, so it must decline.
    #[test]
    fn two_unrelated_entity_systems_are_declined_rather_than_guessed() {
        let mut mem = FakeMemory::new();
        let first = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let second = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, first);
        place(&mut image, DATA_RVA + 0x1200, second);

        assert_eq!(find_entity_system(&mut mem, &image, BASE, &ranges()), None);
    }

    /// Stronger evidence wins outright, and settles an earlier tie rather than
    /// inheriting it: the object accounting for more live entities is the one
    /// the game walks.
    #[test]
    fn the_global_reaching_the_most_entities_wins() {
        let mut mem = FakeMemory::new();
        let weak_a = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let weak_b = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let strong = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE + 4);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, weak_a);
        place(&mut image, DATA_RVA + 0x800, weak_b);
        place(&mut image, DATA_RVA + 0xC00, strong);

        assert_eq!(
            find_entity_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0xC00)
        );
    }

    /// A pointer back into the scanned module is some other global; the entity
    /// system is heap-allocated, so following those would only cost reads.
    #[test]
    fn pointers_into_the_module_itself_are_not_followed() {
        let mut mem = FakeMemory::new();
        let list = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let mut image = image();
        // A self-referential slot, then the real global. The first must not
        // consume the probe budget or the result.
        place(&mut image, DATA_RVA + 0x400, BASE + DATA_RVA);
        place(&mut image, DATA_RVA + 0x800, list);

        assert_eq!(
            find_entity_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x800)
        );
    }

    /// Sections are described by the caller; a range past the end of the image
    /// is clipped instead of panicking.
    #[test]
    fn a_range_beyond_the_image_is_clipped() {
        let mut mem = FakeMemory::new();
        let list = list(&mut mem, EntityListLayout::default(), MIN_EVIDENCE);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, list);

        let oversized = vec![(DATA_RVA, DATA_SIZE * 16)];
        assert_eq!(
            find_entity_system(&mut mem, &image, BASE, &oversized),
            Some(BASE + DATA_RVA + 0x400)
        );
    }
}
