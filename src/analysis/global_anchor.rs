//! Finding a module's globals by describing the object they point at.
//!
//! Every anchor in this crate that is resolved by a byte pattern describes the
//! *code* that touches a global, so a recompile can invalidate it and cost a
//! hand re-authoring. The objects themselves — the schema system, the entity
//! system, the convar registry, the game-event manager — are all recognisable
//! from their own contents, and they all live behind a pointer in some module's
//! writable data. This is the machinery shared by those scans; each caller
//! supplies only what "recognisable" means for its object.
//!
//! The scan walks every 8-byte-aligned slot of the writable data, treats the
//! qword there as a candidate pointer, and keeps the target that scores best.
//! Three rules keep it honest and affordable:
//!
//! - **Aliases collapse, rivals decline.** A game publishes one object through
//!   several globals; those are the same evidence seen twice, so the first
//!   global wins. Two *different* objects with equal top scores mean the scan
//!   cannot tell which one the game uses, and a wrong anchor dumps confident
//!   nonsense while a missing one only loses a section — so it returns nothing.
//! - **Gating is one read.** The head of a candidate object is read as a single
//!   block, so a pointer leading nowhere costs one read rather than one per
//!   field a caller wants to look at.
//! - **The work is bounded.** A module's data holds far more pointers than can
//!   be followed over a slow connector, so distinct targets and full scorings
//!   are both capped. A missing signature must not become a hang.
//!
//! The same writable data answers a question in the other direction, and
//! [`find_publishing_global`] asks it: given an object this crate already
//! located some other way, which global names it? That is how an offset symbol
//! for an object with no describable contents of its own — one recognised by
//! *where it was found*, such as an entity walked out of the entity list — can
//! still be recovered without a signature.

use std::collections::BTreeMap;

use memflow::prelude::v1::*;

use pelite::pe64::PeView;

use crate::analysis::module_data;

/// Distinct pointer values followed into the process. Reached only by a module
/// with an implausible amount of pointer-shaped data, and then the scan gives
/// up rather than spending the rest of the dump's time budget.
const MAX_TARGETS: usize = 1 << 17;

/// Highest canonical user-mode address; a kernel pointer is not the object.
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Slots reported by [`globals_holding`] before it stops looking. It exists to
/// answer "is this object published exactly once?", and two is already "no".
const MAX_ALIASES: usize = 8;

/// How much evidence one anchor scan demands, and how much work it may spend
/// getting it. Both are per-object: recognising an entity list costs orders of
/// magnitude more reads than recognising a game-event manager.
#[derive(Clone, Copy, Debug)]
pub struct AnchorScan {
    /// Bytes of a candidate object read in one block for the cheap gate.
    pub head_span: usize,
    /// Score a candidate needs before it may be published at all.
    pub min_evidence: usize,
    /// Candidates that pass the gate and may be scored in full.
    pub max_probes: usize,
}

/// The head of a candidate object, read once so that gating it costs a single
/// read. Fields past what was readable come back null, which every gate reads
/// as "not my object".
pub struct Head(Vec<u8>);

impl Head {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn u64(&self, at: u64) -> u64 {
        self.at(at, crate::analysis::read::u64_le_at).unwrap_or(0)
    }

    pub fn u32(&self, at: u64) -> u32 {
        self.at(at, crate::analysis::read::u32_le_at).unwrap_or(0)
    }

    pub fn u16(&self, at: u64) -> u16 {
        self.at(at, crate::analysis::read::u16_le_at).unwrap_or(0)
    }

    fn at<T>(&self, at: u64, load: impl FnOnce(&[u8], usize) -> Option<T>) -> Option<T> {
        let offset = usize::try_from(at).ok()?;
        load(&self.0, offset)
    }
}

/// Locate a global in `module` by describing what it points at.
///
/// `gate` is asked about every distinct pointer the writable data holds, so it
/// must be cheap; `score` is asked only about the survivors, and returns how
/// much evidence the target actually presents.
pub fn find_in_module<P, G, S>(
    process: &mut P,
    module: &str,
    scan: AnchorScan,
    gate: G,
    score: S,
) -> Option<u64>
where
    P: Process + MemoryView,
    G: FnMut(&mut P, &Head) -> bool,
    S: FnMut(&mut P, u64) -> usize,
{
    let (base, image) = module_data::read_image(process, module).ok()?;
    let ranges = module_data::writable_ranges(&PeView::from_bytes(&image).ok()?);
    find_global(process, &image, base, &ranges, scan, gate, score)
}

/// Scan `ranges` (`(rva, size)` pairs into `image`, a live copy of the module at
/// `base`) and return the VA of the *global* — what a walker dereferences — not
/// of the object it points at.
pub fn find_global<P, G, S>(
    mem: &mut P,
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
    scan: AnchorScan,
    mut gate: G,
    mut score: S,
) -> Option<u64>
where
    P: MemoryView,
    G: FnMut(&mut P, &Head) -> bool,
    S: FnMut(&mut P, u64) -> usize,
{
    // (global VA, object VA, evidence)
    let mut best: Option<(u64, u64, usize)> = None;
    let mut ambiguous = false;
    let mut probes = 0usize;

    for (slot, object) in candidate_slots(image, base, ranges) {
        if probes >= scan.max_probes {
            break;
        }
        let head = read_head(mem, object, scan.head_span);
        if head.is_empty() || !gate(mem, &head) {
            continue;
        }
        probes += 1;
        let evidence = score(mem, object);
        if evidence < scan.min_evidence {
            continue;
        }
        match best {
            None => best = Some((slot, object, evidence)),
            Some((_, best_object, best_evidence)) => {
                if evidence > best_evidence {
                    // Strictly better evidence dominates every earlier
                    // candidate, including any that tied with each other.
                    best = Some((slot, object, evidence));
                    ambiguous = false;
                } else if evidence == best_evidence && object != best_object {
                    ambiguous = true;
                }
            }
        }
    }

    let (slot, _, _) = best?;
    (!ambiguous).then_some(slot)
}

/// `(global VA, target)` for each distinct pointer the writable data holds, in
/// address order. Distinct targets are collapsed to their first global because
/// several globals pointing at one object are aliases, not rival candidates.
fn candidate_slots(image: &[u8], base: u64, ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let image_end = base.saturating_add(image.len() as u64);
    let mut targets: BTreeMap<u64, u64> = BTreeMap::new();

    for &(rva, size) in ranges {
        let start = (rva as usize).min(image.len());
        let end = start.saturating_add(size as usize).min(image.len());
        let mut offset = start.next_multiple_of(8);

        while offset
            .checked_add(8)
            .is_some_and(|candidate_end| candidate_end <= end)
            && targets.len() < MAX_TARGETS
        {
            let Some(target) = crate::analysis::read::u64_le_at(image, offset) else {
                break;
            };
            // These objects are heap-allocated and pointer-aligned, so a
            // pointer back into the module's own image is a different global.
            if (0x10000..USER_SPACE_END).contains(&target)
                && target % 8 == 0
                && !(base..image_end).contains(&target)
                && let Some(slot) = base.checked_add(offset as u64)
            {
                targets.entry(target).or_insert(slot);
            }
            offset += 8;
        }
    }

    let mut slots: Vec<(u64, u64)> = targets
        .into_iter()
        .map(|(target, slot)| (slot, target))
        .collect();
    slots.sort_unstable();
    slots
}

/// Slots in the writable data whose qword *is* `object`, in address order, up
/// to `MAX_ALIASES` — enough to tell "one" from "several" without collecting a
/// list nobody reads.
pub fn globals_holding(image: &[u8], base: u64, ranges: &[(u64, u64)], object: u64) -> Vec<u64> {
    let mut slots = Vec::new();

    for &(rva, size) in ranges {
        let start = (rva as usize).min(image.len());
        let end = start.saturating_add(size as usize).min(image.len());
        let mut offset = start.next_multiple_of(8);

        while offset
            .checked_add(8)
            .is_some_and(|candidate_end| candidate_end <= end)
            && slots.len() < MAX_ALIASES
        {
            if crate::analysis::read::u64_le_at(image, offset) == Some(object)
                && let Some(slot) = base.checked_add(offset as u64)
            {
                slots.push(slot);
            }
            offset += 8;
        }
    }

    slots
}

/// VA of the global that publishes `object`, or `None` when the module holds no
/// pointer to it — or more than one.
///
/// This is the inverse of [`find_global`]. There, a candidate object is
/// recognised by its own contents; here the object was already located by other
/// dynamic means — an entity walked out of the entity list, a pointer read at a
/// dumped schema offset — and only the name of the global that publishes it is
/// missing. A pointer that specific needs no scoring.
///
/// It does need to be the *only* one. An offset symbol is a promise about which
/// slot a consumer dereferences, and several slots holding one object are
/// indistinguishable from here: some are the global the game maintains, others
/// are copies that were correct when they were written. Picking among them would
/// be a guess, so a tie declines and the symbol stays missing.
pub fn find_publishing_global(
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
    object: u64,
) -> Option<u64> {
    match globals_holding(image, base, ranges, object).as_slice() {
        [slot] => Some(*slot),
        _ => None,
    }
}

fn read_head<P: MemoryView>(mem: &mut P, va: u64, len: usize) -> Head {
    Head(
        mem.read_raw(Address::from(va), len)
            .data_part()
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{AnchorScan, Head, find_global};
    use crate::memory::fake::FakeMemory;
    use memflow::prelude::v1::{MemoryView, PartialResultExt};

    const BASE: u64 = 0x0000_7FFA_1000_0000;
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    /// Stands in for whatever a real gate recognises.
    const MAGIC: u64 = 0x0BAD_C0DE_0BAD_C0DE;

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    fn place(image: &mut [u8], rva: u64, target: u64) {
        image[rva as usize..][..8].copy_from_slice(&target.to_le_bytes());
    }

    /// An object a gate can recognise, carrying its own evidence.
    fn object(mem: &mut FakeMemory, magic: u64, evidence: usize) -> u64 {
        let object = mem.alloc(0x20);
        mem.put_u64(object, magic);
        mem.put_u64(object + 8, evidence as u64);
        object
    }

    fn gate(_mem: &mut FakeMemory, head: &Head) -> bool {
        head.u64(0) == MAGIC
    }

    /// The probe budget is what stops a missing signature from turning into a
    /// hang, and it is spent in address order: a scan that runs out gives up
    /// rather than reporting the best of what it happened to reach.
    #[test]
    fn the_probe_budget_bounds_the_scan_and_declines_when_it_runs_out() {
        let mut mem = FakeMemory::new();
        let weak: Vec<u64> = (0..4).map(|_| object(&mut mem, MAGIC, 1)).collect();
        let strong = object(&mut mem, MAGIC, 5);
        let mut image = image();
        for (index, object) in weak.iter().enumerate() {
            place(&mut image, DATA_RVA + 0x100 * index as u64, *object);
        }
        place(&mut image, DATA_RVA + 0x800, strong);

        let scan = |max_probes| AnchorScan {
            head_span: 0x20,
            min_evidence: 5,
            max_probes,
        };
        let scored = Cell::new(0usize);
        let score = |mem: &mut FakeMemory, object: u64| {
            scored.set(scored.get() + 1);
            mem.read::<u64>(object.saturating_add(8).into())
                .data_part()
                .unwrap_or(0) as usize
        };
        let ranges = [(DATA_RVA, DATA_SIZE)];

        assert_eq!(
            find_global(&mut mem, &image, BASE, &ranges, scan(2), gate, &score),
            None,
            "the strong candidate is past the budget and must not be guessed at"
        );
        assert_eq!(
            scored.get(),
            2,
            "the budget caps full scorings, not gate calls"
        );

        assert_eq!(
            find_global(&mut mem, &image, BASE, &ranges, scan(8), gate, &score),
            Some(BASE + DATA_RVA + 0x800)
        );
    }

    /// The gate is what makes scanning a whole module affordable: a pointer it
    /// rejects, and one leading nowhere at all, must never reach the scorer.
    #[test]
    fn rejected_and_unreadable_targets_are_never_scored() {
        let mut mem = FakeMemory::new();
        let other = object(&mut mem, 0xDEAD_BEEF, 99);
        let mut image = image();
        place(&mut image, DATA_RVA + 0x100, other);
        // Never mapped, so reading its head fails outright.
        place(&mut image, DATA_RVA + 0x200, 0x0000_7FF0_0000_0000);

        let mut scored = 0usize;
        let scan = AnchorScan {
            head_span: 0x20,
            min_evidence: 1,
            max_probes: 64,
        };
        let found = find_global(
            &mut mem,
            &image,
            BASE,
            &[(DATA_RVA, DATA_SIZE)],
            scan,
            gate,
            |_mem, _object| {
                scored += 1;
                99
            },
        );

        assert_eq!(found, None);
        assert_eq!(scored, 0);
    }

    /// The inverse direction: an object located some other way is named by the
    /// one global that holds it, and a second holder makes the name a guess.
    #[test]
    fn a_uniquely_published_object_is_named_by_its_global() {
        use super::{find_publishing_global, globals_holding};

        const OBJECT: u64 = 0x0000_01F2_3456_7890;
        let ranges = [(DATA_RVA, DATA_SIZE)];
        let mut image = image();
        place(&mut image, DATA_RVA + 0x120, OBJECT);
        // A neighbouring global holding something else must not interfere.
        place(&mut image, DATA_RVA + 0x128, OBJECT + 8);

        assert_eq!(
            find_publishing_global(&image, BASE, &ranges, OBJECT),
            Some(BASE + DATA_RVA + 0x120)
        );

        // A copy of the pointer elsewhere in the section: both slots read alike
        // from here, so the scan cannot promise which one a consumer should
        // dereference.
        place(&mut image, DATA_RVA + 0x900, OBJECT);
        assert_eq!(globals_holding(&image, BASE, &ranges, OBJECT).len(), 2);
        assert_eq!(find_publishing_global(&image, BASE, &ranges, OBJECT), None);
    }

    /// An object the module never points at yields nothing, and a null one is
    /// not "found" in the zero-filled data either.
    #[test]
    fn an_unpublished_object_yields_no_global() {
        let ranges = [(DATA_RVA, DATA_SIZE)];
        let image = image();

        assert_eq!(
            super::find_publishing_global(&image, BASE, &ranges, 0x0000_01F2_3456_7890),
            None
        );
        assert_eq!(
            super::find_publishing_global(&image, BASE, &ranges, 0),
            None
        );
    }
}
