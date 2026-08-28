//! Runtime-validated discovery of a schema class's **static** fields.
//!
//! `SchemaClassInfoData` carries a `SchemaStaticFieldData_t` array alongside the
//! instance-field array, but its position has moved between builds and this
//! crate's struct definition covers the slot with padding. Hardcoding an offset
//! would silently emit pointer garbage on the next update, so instead a small
//! set of compatible layouts is probed against *every* class binding in the
//! process and one is accepted only when it validates broadly and unambiguously.
//! When nothing validates, no static fields are emitted at all — the dump loses
//! a section rather than gaining a fabricated one.
//!
//! ```text
//! SchemaClassInfoData:
//!   +0x24  field count (i16)
//!   +0x26  candidate static-field count (i16)
//!   +0x28  candidate static-field count (i16)
//!   +0x30  instance field array
//!   +0x38  candidate static-field array
//!
//! SchemaStaticFieldData_t (stride 0x18):
//!   +0x00  name char*   +0x08  CSchemaType*   +0x10  instance void*
//!
//! CSchemaType:
//!   +0x08  name char*
//! ```

use memflow::prelude::v1::*;
use serde::{Deserialize, Serialize};

/// A single static member of a schema class.
///
/// The runtime address is deliberately **not** emitted: it moves with ASLR on
/// every launch, so it would make two dumps of the same build differ. The index
/// is what a consumer needs to look the member up through the schema system.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaticField {
    pub name: String,
    pub type_name: String,
    pub index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticFieldLayout {
    /// i16 count of static fields within the class binding.
    pub count: u64,
    /// Pointer to the static-field array within the class binding.
    pub array: u64,
    pub stride: u64,
    pub entry_name: u64,
    pub entry_type: u64,
    pub entry_instance: u64,
}

/// Layouts seen across shipped builds, most likely first. A candidate only ever
/// matters if it validates, so an extra entry costs a few reads and never
/// corrupts the result.
pub const CANDIDATES: &[StaticFieldLayout] = &[
    StaticFieldLayout {
        count: 0x26,
        array: 0x38,
        stride: 0x18,
        entry_name: 0x00,
        entry_type: 0x08,
        entry_instance: 0x10,
    },
    StaticFieldLayout {
        count: 0x28,
        array: 0x38,
        stride: 0x18,
        entry_name: 0x00,
        entry_type: 0x08,
        entry_instance: 0x10,
    },
    StaticFieldLayout {
        count: 0x26,
        array: 0x38,
        stride: 0x20,
        entry_name: 0x00,
        entry_type: 0x08,
        entry_instance: 0x10,
    },
    StaticFieldLayout {
        count: 0x28,
        array: 0x50,
        stride: 0x18,
        entry_name: 0x00,
        entry_type: 0x08,
        entry_instance: 0x10,
    },
    StaticFieldLayout {
        count: 0x26,
        array: 0x38,
        stride: 0x18,
        entry_name: 0x00,
        entry_type: 0x10,
        entry_instance: 0x08,
    },
];

/// Offset of the type name within a `CSchemaType`.
const TYPE_NAME: u64 = 0x08;

/// No real class declares more statics than this; a larger count means the
/// candidate is reading something that is not a count.
const MAX_STATIC_FIELDS: i16 = 1024;

/// How many entries of one class are inspected while scoring.
const PROBE_ENTRIES: i16 = 8;

/// Total validated entries a layout must produce across the sampled bindings
/// before it is trusted at all.
const MIN_EVIDENCE: usize = 16;

/// How far ahead of the runner-up the winner must be. Two candidates that both
/// half-validate mean the geometry is not actually understood, and emitting
/// either would be a guess.
const DOMINANCE: usize = 2;

/// Pick the layout the process itself supports, or `None` when the evidence is
/// weak or ambiguous.
pub fn detect_layout<P: MemoryView>(mem: &mut P, binding_vas: &[u64]) -> Option<StaticFieldLayout> {
    let mut scores: Vec<(StaticFieldLayout, usize)> = CANDIDATES
        .iter()
        .map(|candidate| {
            let score = binding_vas
                .iter()
                .map(|va| score_binding(mem, *va, *candidate))
                .sum();
            (*candidate, score)
        })
        .collect();
    scores.sort_by_key(|(_, score)| std::cmp::Reverse(*score));

    let (best, best_score) = *scores.first()?;
    if best_score < MIN_EVIDENCE {
        return None;
    }
    let runner_up = scores.get(1).map(|(_, score)| *score).unwrap_or(0);
    (best_score >= runner_up.saturating_mul(DOMINANCE)).then_some(best)
}

/// Number of entries of `binding_va` that look like real static fields under
/// `layout`. A binding with no statics contributes nothing either way.
fn score_binding<P: MemoryView>(mem: &mut P, binding_va: u64, layout: StaticFieldLayout) -> usize {
    let Some(count) = plausible_count(mem, binding_va, layout) else {
        return 0;
    };
    let Some(array_addr) = binding_va.checked_add(layout.array) else {
        return 0;
    };
    let array = rd_u64(mem, array_addr);
    if array < 0x10000 {
        return 0;
    }
    (0..count.min(PROBE_ENTRIES))
        .filter(|index| read_entry(mem, array, *index as u16, layout).is_some())
        .count()
}

fn plausible_count<P: MemoryView>(
    mem: &mut P,
    binding_va: u64,
    layout: StaticFieldLayout,
) -> Option<i16> {
    let count_addr = binding_va.checked_add(layout.count)?;
    let count = rd_i16(mem, count_addr);
    (1..=MAX_STATIC_FIELDS).contains(&count).then_some(count)
}

/// Decode one entry, returning `None` when it does not look like a static field.
fn read_entry<P: MemoryView>(
    mem: &mut P,
    array: u64,
    index: u16,
    layout: StaticFieldLayout,
) -> Option<StaticField> {
    let entry = layout
        .stride
        .checked_mul(index as u64)
        .and_then(|delta| array.checked_add(delta))?;
    // A static field always has storage; a null instance means this is not one.
    let instance_addr = entry.checked_add(layout.entry_instance)?;
    if rd_u64(mem, instance_addr) < 0x10000 {
        return None;
    }
    let name_addr = entry.checked_add(layout.entry_name)?;
    let name_ptr = rd_u64(mem, name_addr);
    let name = rd_cstr(mem, name_ptr);
    if !plausible_ident(&name) {
        return None;
    }
    let type_addr = entry.checked_add(layout.entry_type)?;
    let type_ptr = rd_u64(mem, type_addr);
    if type_ptr < 0x10000 {
        return None;
    }
    let type_name_addr = type_ptr.checked_add(TYPE_NAME)?;
    let type_name_ptr = rd_u64(mem, type_name_addr);
    let type_name = rd_cstr(mem, type_name_ptr);
    if !plausible_type_name(&type_name) {
        return None;
    }
    Some(StaticField {
        name,
        type_name: type_name.replace(' ', ""),
        index,
    })
}

/// Read every static field of one class binding under an already-validated
/// layout. Entries that fail validation are skipped rather than guessed at, so
/// a partially-torn-down binding degrades to fewer rows instead of garbage.
pub fn read_static_fields<P: MemoryView>(
    mem: &mut P,
    binding_va: u64,
    layout: StaticFieldLayout,
) -> Vec<StaticField> {
    let Some(count) = plausible_count(mem, binding_va, layout) else {
        return Vec::new();
    };
    let Some(array_addr) = binding_va.checked_add(layout.array) else {
        return Vec::new();
    };
    let array = rd_u64(mem, array_addr);
    if array < 0x10000 {
        return Vec::new();
    }
    (0..count)
        .filter_map(|index| read_entry(mem, array, index as u16, layout))
        .collect()
}

fn plausible_ident(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= 128
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Type names are richer than identifiers (`CUtlVector< int >`, `char*`), so
/// they are only checked for being printable, bounded text.
fn plausible_type_name(name: &str) -> bool {
    let len = name.len();
    (1..=256).contains(&len)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn rd_u64<P: MemoryView>(mem: &mut P, va: u64) -> u64 {
    crate::analysis::read::u64_va(mem, va)
}

fn rd_i16<P: MemoryView>(mem: &mut P, va: u64) -> i16 {
    crate::analysis::read::i16_va(mem, va)
}

fn rd_cstr<P: MemoryView>(mem: &mut P, ptr: u64) -> String {
    crate::analysis::read::cstr(mem, ptr)
}

#[cfg(test)]
mod tests {
    use super::{
        CANDIDATES, MIN_EVIDENCE, StaticFieldLayout, detect_layout, plausible_ident,
        plausible_type_name, read_static_fields,
    };
    use crate::memory::fake::FakeMemory;

    /// Statics laid into every fake binding: (name, type name).
    const SAMPLE: &[(&str, &str)] = &[
        ("m_bIsDefault", "bool"),
        ("s_flTickInterval", "float32"),
        ("sm_pInstance", "CGameRules*"),
    ];

    /// Build a `SchemaClassInfoData`-shaped binding whose static-field array
    /// uses `layout`, and return its VA plus the array's VA.
    fn build_binding_with_array(
        mem: &mut FakeMemory,
        layout: StaticFieldLayout,
        statics: usize,
    ) -> (u64, u64) {
        let binding = mem.alloc(0x80);
        if statics == 0 {
            return (binding, 0);
        }
        let array = mem.alloc(layout.stride as usize * statics);
        mem.put_u16(binding + layout.count, statics as u16);
        mem.put_ptr(binding + layout.array, array);
        for (index, (name, type_name)) in SAMPLE.iter().cycle().take(statics).enumerate() {
            let entry = array + layout.stride * index as u64;
            let name_ptr = mem.alloc_cstr(name);
            let type_name_ptr = mem.alloc_cstr(type_name);
            // A `CSchemaType` keeps its name at +0x08.
            let type_ptr = mem.alloc(0x20);
            mem.put_ptr(type_ptr + super::TYPE_NAME, type_name_ptr);
            let storage = mem.alloc(0x10);
            mem.put_ptr(entry + layout.entry_name, name_ptr);
            mem.put_ptr(entry + layout.entry_type, type_ptr);
            mem.put_ptr(entry + layout.entry_instance, storage);
        }
        (binding, array)
    }

    fn build_binding(mem: &mut FakeMemory, layout: StaticFieldLayout, statics: usize) -> u64 {
        build_binding_with_array(mem, layout, statics).0
    }

    /// Enough bindings for the probe to clear its evidence floor.
    fn build_bindings(mem: &mut FakeMemory, layout: StaticFieldLayout) -> Vec<u64> {
        (0..MIN_EVIDENCE)
            .map(|_| build_binding(mem, layout, SAMPLE.len()))
            .collect()
    }

    #[test]
    fn only_identifier_shaped_names_are_accepted() {
        assert!(plausible_ident("m_bIsDefault"));
        assert!(plausible_ident("_s_count"));
        assert!(!plausible_ident(""));
        assert!(!plausible_ident("9lives"));
        assert!(!plausible_ident("m_b IsDefault"));
        assert!(!plausible_ident("m_b\u{1}IsDefault"));
    }

    #[test]
    fn type_names_may_be_templated_but_must_be_printable() {
        assert!(plausible_type_name("CUtlVector< int >"));
        assert!(plausible_type_name("char*"));
        assert!(!plausible_type_name(""));
        assert!(!plausible_type_name("bad\u{0}type"));
    }

    /// The point of the probe: a build that moved the static-field array is
    /// followed from live evidence instead of a hardcoded offset.
    #[test]
    fn every_shipped_candidate_layout_is_recovered_from_live_data() {
        for (index, candidate) in CANDIDATES.iter().enumerate() {
            let mut mem = FakeMemory::new();
            let bindings = build_bindings(&mut mem, *candidate);
            assert_eq!(
                detect_layout(&mut mem, &bindings),
                Some(*candidate),
                "candidate {index} was not recovered"
            );
        }
    }

    #[test]
    fn reads_every_static_field_of_a_binding_in_declaration_order() {
        let mut mem = FakeMemory::new();
        let layout = CANDIDATES[0];
        let binding = build_binding(&mut mem, layout, SAMPLE.len());

        let found = read_static_fields(&mut mem, binding, layout);
        let seen: Vec<_> = found
            .iter()
            .map(|field| (field.name.as_str(), field.type_name.as_str(), field.index))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("m_bIsDefault", "bool", 0),
                ("s_flTickInterval", "float32", 1),
                ("sm_pInstance", "CGameRules*", 2),
            ]
        );
    }

    #[test]
    fn a_single_binding_is_not_enough_evidence_to_emit_anything() {
        let mut mem = FakeMemory::new();
        let binding = build_binding(&mut mem, CANDIDATES[0], SAMPLE.len());
        assert_eq!(detect_layout(&mut mem, &[binding]), None);
    }

    #[test]
    fn a_process_with_no_bindings_yields_no_layout() {
        let mut mem = FakeMemory::new();
        assert_eq!(detect_layout(&mut mem, &[]), None);
    }

    /// Two candidates that validate equally well mean the geometry is not
    /// actually understood. Emitting either would be a guess dressed up as a
    /// measurement, so the probe must decline.
    #[test]
    fn an_ambiguous_probe_is_declined_rather_than_guessed() {
        let layout = CANDIDATES[0];
        let mut mem = FakeMemory::new();
        let bindings: Vec<u64> = (0..MIN_EVIDENCE)
            .map(|_| {
                let binding = mem.alloc(0x80);
                let array = mem.alloc(layout.stride as usize * SAMPLE.len());
                mem.put_u16(binding + layout.count, SAMPLE.len() as u16);
                mem.put_ptr(binding + layout.array, array);
                for (index, (name, type_name)) in SAMPLE.iter().enumerate() {
                    let entry = array + layout.stride * index as u64;
                    let name_ptr = mem.alloc_cstr(name);
                    mem.put_ptr(entry + layout.entry_name, name_ptr);
                    // Both pointer slots look like a `CSchemaType`, so the
                    // type/instance ordering cannot be told apart.
                    for slot in [layout.entry_type, layout.entry_instance] {
                        let type_name_ptr = mem.alloc_cstr(type_name);
                        let type_ptr = mem.alloc(0x20);
                        mem.put_ptr(type_ptr + super::TYPE_NAME, type_name_ptr);
                        mem.put_ptr(entry + slot, type_ptr);
                    }
                }
                binding
            })
            .collect();

        assert_eq!(detect_layout(&mut mem, &bindings), None);
    }

    #[test]
    fn a_class_with_no_statics_reads_as_empty_not_as_garbage() {
        let mut mem = FakeMemory::new();
        let layout = CANDIDATES[0];
        let binding = build_binding(&mut mem, layout, 0);
        assert!(read_static_fields(&mut mem, binding, layout).is_empty());
    }

    #[test]
    fn a_count_without_an_array_reads_as_empty() {
        let mut mem = FakeMemory::new();
        let layout = CANDIDATES[0];
        let binding = mem.alloc(0x80);
        mem.put_u16(binding + layout.count, 4);
        assert!(read_static_fields(&mut mem, binding, layout).is_empty());
    }

    #[test]
    fn an_absurd_count_is_rejected_instead_of_walked() {
        let mut mem = FakeMemory::new();
        let layout = CANDIDATES[0];
        let binding = build_binding(&mut mem, layout, SAMPLE.len());
        mem.put_u16(binding + layout.count, 0x7FFF);
        assert!(read_static_fields(&mut mem, binding, layout).is_empty());
    }

    /// A binding caught mid-teardown loses rows; it must not gain fabricated
    /// ones, and the surviving rows keep their real declaration indices.
    #[test]
    fn an_entry_that_fails_validation_is_skipped_not_invented() {
        let mut mem = FakeMemory::new();
        let layout = CANDIDATES[0];
        let (binding, array) = build_binding_with_array(&mut mem, layout, SAMPLE.len());
        mem.put_ptr(array + layout.stride + layout.entry_instance, 0);

        let found = read_static_fields(&mut mem, binding, layout);
        let seen: Vec<_> = found
            .iter()
            .map(|field| (field.name.as_str(), field.index))
            .collect();
        assert_eq!(seen, vec![("m_bIsDefault", 0), ("sm_pInstance", 2)]);
    }
}
