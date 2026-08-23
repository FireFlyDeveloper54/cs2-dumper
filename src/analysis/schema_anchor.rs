//! Signature-free discovery of the `SchemaSystem` global.
//!
//! The canonical route to the schema system is a byte pattern in
//! `schemasystem.dll` (`lea r14, [rip+X]`), which breaks whenever Valve
//! recompiles that function and has to be re-authored by hand. The object it
//! points at, though, is a global in the module's writable data — so it can be
//! found by *describing* it instead of describing the code that references it:
//! walk every 8-byte-aligned slot of the data sections and keep the one that
//! reads back as a type-scope vector whose scopes carry real names.
//!
//! ```text
//! SchemaSystem:
//!   +0x190  type scope count (i32)
//!   +0x198  type scope array  (CSchemaSystemTypeScope**)
//!   +0x280  registration count (i32)
//!
//! CSchemaSystemTypeScope:
//!   +0x08   name char[256]   ("client.dll", "!GlobalTypes", ...)
//! ```
//!
//! This is engine-generic: nothing here is specific to CS2's build, so the
//! schema dump survives an update that invalidates the signature, and works
//! against other Source 2 titles. When the evidence is weak or two unrelated
//! candidates tie, no address is returned — a missing schema dump is recoverable
//! and a wrong one is not.

use std::collections::BTreeSet;

use memflow::prelude::v1::*;

/// Offsets within `SchemaSystem`; see [`crate::source2::SchemaSystem`].
const TYPE_SCOPES_COUNT: usize = 0x190;
const TYPE_SCOPES_DATA: usize = 0x198;
const REGISTRATION_COUNT: usize = 0x280;

/// Bytes of the object a candidate must have entirely inside the section, so a
/// slot near the end of the data is never completed with unrelated memory.
const SPAN: usize = REGISTRATION_COUNT + 4;

/// `CSchemaSystemTypeScope::name`.
const SCOPE_NAME: u64 = 0x08;

/// Matches the ceiling `validate_schema_system` enforces on a pattern hit.
const MAX_SCOPES: i32 = 512;

/// A registration count beyond this is not a count.
const MAX_REGISTRATIONS: i32 = 1_000_000;

/// How many scopes of one candidate are named-checked.
const PROBE_SCOPES: usize = 8;

/// Distinctly-named scopes a candidate needs. Every Source 2 game registers at
/// least `!GlobalTypes` plus one module, so a lone name is not evidence.
const MIN_SCOPES: usize = 2;

/// Scan `ranges` (`(rva, size)` pairs into `image`, a live copy of the module at
/// `base`) for the module's `SchemaSystem`, returning its VA.
///
/// `image` supplies the cheap gates so the scan costs no reads per slot; only
/// candidates that pass them are followed into the live process.
pub fn find_schema_system<P: MemoryView>(
    mem: &mut P,
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
) -> Option<u64> {
    // (VA, scope array, distinct named scopes)
    let mut best: Option<(u64, u64, usize)> = None;
    let mut ambiguous = false;

    for &(rva, size) in ranges {
        let start = rva as usize;
        let end = start.saturating_add(size as usize).min(image.len());
        let mut offset = start.next_multiple_of(8);

        while offset + SPAN <= end {
            if let Some((array, score)) = score_candidate(mem, image, offset) {
                let va = base + offset as u64;
                match best {
                    None => best = Some((va, array, score)),
                    Some((_, best_array, best_score)) => {
                        if score > best_score {
                            // Strictly better evidence dominates every earlier
                            // candidate, including any that tied with each other.
                            best = Some((va, array, score));
                            ambiguous = false;
                        } else if score == best_score && array != best_array {
                            ambiguous = true;
                        }
                    }
                }
            }
            offset += 8;
        }
    }

    let (va, _, _) = best?;
    (!ambiguous).then_some(va)
}

/// Gate one slot on the image bytes, then score it against live memory.
/// Returns the candidate's scope array and how many distinct scope names it
/// resolved, or `None` when it does not look like a schema system at all.
fn score_candidate<P: MemoryView>(
    mem: &mut P,
    image: &[u8],
    offset: usize,
) -> Option<(u64, usize)> {
    let count = rd_i32(image, offset + TYPE_SCOPES_COUNT)?;
    if !(1..=MAX_SCOPES).contains(&count) {
        return None;
    }
    let registrations = rd_i32(image, offset + REGISTRATION_COUNT)?;
    if !(1..=MAX_REGISTRATIONS).contains(&registrations) {
        return None;
    }
    let array = rd_u64(image, offset + TYPE_SCOPES_DATA)?;
    if array < 0x10000 {
        return None;
    }
    let score = score_scopes(mem, array, count);
    (score >= MIN_SCOPES).then_some((array, score))
}

/// Distinct plausible scope names reachable from a candidate's array. Counting
/// *distinct* names rejects a run of repeated pointers, which would otherwise
/// score as well as the real vector.
fn score_scopes<P: MemoryView>(mem: &mut P, array: u64, count: i32) -> usize {
    let sampled = (count as usize).min(PROBE_SCOPES);
    let mut names = BTreeSet::new();
    for index in 0..sampled {
        let scope = read_u64(mem, array + 8 * index as u64);
        if scope < 0x10000 {
            continue;
        }
        let name = read_cstr(mem, scope + SCOPE_NAME);
        if plausible_scope_name(&name) {
            names.insert(name);
        }
    }
    names.len()
}

/// Scope names are short printable tokens (`client.dll`, `!GlobalTypes`).
fn plausible_scope_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_graphic())
}

fn rd_i32(image: &[u8], at: usize) -> Option<i32> {
    let bytes = image.get(at..at + 4)?;
    Some(i32::from_le_bytes(bytes.try_into().ok()?))
}

fn rd_u64(image: &[u8], at: usize) -> Option<u64> {
    let bytes = image.get(at..at + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64<P: MemoryView>(mem: &mut P, va: u64) -> u64 {
    mem.read::<u64>(Address::from(va)).data_part().unwrap_or(0)
}

fn read_cstr<P: MemoryView>(mem: &mut P, va: u64) -> String {
    mem.read_utf8_lossy(Address::from(va), 64)
        .data_part()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        MIN_SCOPES, REGISTRATION_COUNT, SCOPE_NAME, SPAN, TYPE_SCOPES_COUNT, TYPE_SCOPES_DATA,
        find_schema_system, plausible_scope_name,
    };
    use crate::memory::fake::FakeMemory;

    /// Base VA of the synthetic module image.
    const BASE: u64 = 0x0000_7FFA_1000_0000;
    /// RVA and size of its writable data section.
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    const SCOPES: &[&str] = &["!GlobalTypes", "client.dll", "server.dll"];

    /// The image keeps slack past the data section, so a candidate straddling
    /// the section boundary is representable and must still be rejected.
    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize + SPAN]
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    /// Allocate a live type-scope array whose scopes carry `names`.
    fn alloc_scopes(mem: &mut FakeMemory, names: &[&str]) -> u64 {
        let array = mem.alloc_ptrs(names.len().max(1));
        for (index, name) in names.iter().enumerate() {
            let scope = mem.alloc(0x200);
            let name_ptr = scope + SCOPE_NAME;
            mem.put_cstr(name_ptr, name);
            mem.put_ptr(array + 8 * index as u64, scope);
        }
        array
    }

    /// Lay a `SchemaSystem` into the image at `rva`, pointing at `array`.
    fn place(image: &mut [u8], rva: u64, count: i32, array: u64, registrations: i32) {
        let at = rva as usize;
        image[at + TYPE_SCOPES_COUNT..][..4].copy_from_slice(&count.to_le_bytes());
        image[at + TYPE_SCOPES_DATA..][..8].copy_from_slice(&array.to_le_bytes());
        image[at + REGISTRATION_COUNT..][..4].copy_from_slice(&registrations.to_le_bytes());
    }

    #[test]
    fn scope_names_are_short_printable_tokens() {
        assert!(plausible_scope_name("client.dll"));
        assert!(plausible_scope_name("!GlobalTypes"));
        assert!(!plausible_scope_name(""));
        assert!(!plausible_scope_name("client dll"));
        assert!(!plausible_scope_name(&"a".repeat(65)));
    }

    /// The point of the scan: the schema system is located by describing the
    /// object, with no signature over the code that references it.
    #[test]
    fn finds_the_schema_system_without_a_signature() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(
            &mut image,
            DATA_RVA + 0x400,
            SCOPES.len() as i32,
            array,
            4096,
        );

        assert_eq!(
            find_schema_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    #[test]
    fn a_data_section_without_a_schema_system_yields_nothing() {
        let mut mem = FakeMemory::new();
        assert_eq!(
            find_schema_system(&mut mem, &image(), BASE, &ranges()),
            None
        );
    }

    #[test]
    fn an_absurd_scope_count_is_rejected_instead_of_walked() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, 0x7FFF_FFFF, array, 4096);

        assert_eq!(find_schema_system(&mut mem, &image, BASE, &ranges()), None);
    }

    #[test]
    fn a_registration_count_of_zero_is_not_a_live_schema_system() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, SCOPES.len() as i32, array, 0);

        assert_eq!(find_schema_system(&mut mem, &image, BASE, &ranges()), None);
    }

    /// A run of repeated pointers has as many "scopes" as the real vector, so
    /// only *distinct* names count as evidence.
    #[test]
    fn a_vector_of_one_repeated_scope_is_not_enough_evidence() {
        let mut mem = FakeMemory::new();
        let scope = mem.alloc(0x200);
        mem.put_cstr(scope + SCOPE_NAME, "client.dll");
        let array = mem.alloc_ptrs(8);
        for index in 0..8u64 {
            mem.put_ptr(array + 8 * index, scope);
        }
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, 8, array, 4096);

        assert_eq!(find_schema_system(&mut mem, &image, BASE, &ranges()), None);
    }

    #[test]
    fn scopes_without_names_are_not_evidence() {
        let mut mem = FakeMemory::new();
        // Real pointers, but the scopes hold no readable name.
        let array = mem.alloc_ptrs(4);
        for index in 0..4u64 {
            let scope = mem.alloc(0x200);
            mem.put_ptr(array + 8 * index, scope);
        }
        let mut image = image();
        place(&mut image, DATA_RVA + 0x400, 4, array, 4096);

        assert_eq!(find_schema_system(&mut mem, &image, BASE, &ranges()), None);
    }

    /// Two candidates describing *different* schema systems mean the scan does
    /// not actually know which one the game uses, so it must decline.
    #[test]
    fn two_unrelated_candidates_are_declined_rather_than_guessed() {
        let mut mem = FakeMemory::new();
        let first = alloc_scopes(&mut mem, SCOPES);
        let second = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(
            &mut image,
            DATA_RVA + 0x400,
            SCOPES.len() as i32,
            first,
            4096,
        );
        place(
            &mut image,
            DATA_RVA + 0x1000,
            SCOPES.len() as i32,
            second,
            4096,
        );

        assert_eq!(find_schema_system(&mut mem, &image, BASE, &ranges()), None);
    }

    /// Two slots that reach the *same* type-scope vector are two views of one
    /// object, not a contradiction, so the scan still resolves it.
    #[test]
    fn aliases_of_one_schema_system_still_resolve() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(
            &mut image,
            DATA_RVA + 0x400,
            SCOPES.len() as i32,
            array,
            4096,
        );
        place(
            &mut image,
            DATA_RVA + 0x1000,
            SCOPES.len() as i32,
            array,
            4096,
        );

        assert_eq!(
            find_schema_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0x400)
        );
    }

    /// Stronger evidence wins outright: a candidate naming more scopes is the
    /// real object, and it settles an earlier tie rather than inheriting it.
    #[test]
    fn the_candidate_naming_the_most_scopes_wins() {
        let mut mem = FakeMemory::new();
        let weak_a = alloc_scopes(&mut mem, &SCOPES[..MIN_SCOPES]);
        let weak_b = alloc_scopes(&mut mem, &SCOPES[..MIN_SCOPES]);
        let strong = alloc_scopes(&mut mem, &["a.dll", "b.dll", "c.dll", "d.dll"]);
        let mut image = image();
        place(
            &mut image,
            DATA_RVA + 0x400,
            MIN_SCOPES as i32,
            weak_a,
            4096,
        );
        place(
            &mut image,
            DATA_RVA + 0x800,
            MIN_SCOPES as i32,
            weak_b,
            4096,
        );
        place(&mut image, DATA_RVA + 0xC00, 4, strong, 4096);

        assert_eq!(
            find_schema_system(&mut mem, &image, BASE, &ranges()),
            Some(BASE + DATA_RVA + 0xC00)
        );
    }

    /// A section whose tail is shorter than the object must not be completed
    /// with whatever follows it in the image.
    #[test]
    fn a_candidate_that_does_not_fit_the_section_is_not_read() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        let rva = DATA_RVA + DATA_SIZE - SPAN as u64 + 8;
        place(&mut image, rva, SCOPES.len() as i32, array, 4096);

        assert_eq!(
            find_schema_system(&mut mem, &image, BASE, &ranges()),
            None,
            "the object extends past the section and must not be trusted"
        );
    }

    /// Sections are described by the caller; a range past the end of the image
    /// is clipped instead of panicking.
    #[test]
    fn a_range_beyond_the_image_is_clipped() {
        let mut mem = FakeMemory::new();
        let array = alloc_scopes(&mut mem, SCOPES);
        let mut image = image();
        place(
            &mut image,
            DATA_RVA + 0x400,
            SCOPES.len() as i32,
            array,
            4096,
        );

        let oversized = vec![(DATA_RVA, DATA_SIZE * 16)];
        assert_eq!(
            find_schema_system(&mut mem, &image, BASE, &oversized),
            Some(BASE + DATA_RVA + 0x400)
        );
    }
}
