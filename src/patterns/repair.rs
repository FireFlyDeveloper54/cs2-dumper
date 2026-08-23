//! Post-update signature repair ("self-healing" patterns).
//!
//! When a game update rewrites a few bytes inside a signature, the pattern
//! stops matching entirely and the affected offset silently disappears from
//! the dump. Repair takes the failed pattern, finds the location in `.text`
//! that still matches the largest share of its constrained bytes, and emits a
//! relaxed pattern with only the drifted positions wildcarded.
//!
//! The repaired pattern keeps the original length and byte positions, so it is
//! a drop-in replacement in the database: any `extra_off` / `rel32` / `riprel`
//! resolution anchored on the match address keeps working unchanged. Leading
//! and trailing wildcards are therefore deliberately *not* trimmed.
//!
//! Everything here operates on plain byte slices, so it is fully exercised by
//! unit tests without a live process.

use serde::Serialize;

use super::{byte_matches, find_all_pattern, parse_ida};

/// Minimum share of the original pattern's constrained bytes that must still
/// match before a candidate is worth reporting.
const MIN_SIMILARITY: f32 = 0.80;

/// A pattern constrained by fewer bytes than this is too weak to relax
/// further — repairing it would produce noise instead of a usable signature.
const MIN_CONSTRAINED: usize = 8;

/// Upper bound on repair attempts per run. Each attempt is a full `.text`
/// sweep, so this keeps a badly stale database from stalling the dump.
pub(crate) const MAX_REPAIR_ATTEMPTS: usize = 64;

/// A repair suggestion for one failed pattern.
#[derive(Clone, Debug, Serialize)]
pub struct PatternRepair {
    pub name: String,
    pub module: String,
    /// The database pattern that no longer matches.
    pub original: String,
    /// Same length and anchor, with the drifted byte positions wildcarded.
    pub repaired: String,
    /// Resolution kind carried over from the failed entry, so the suggestion
    /// can be written straight back into a `--pattern-file`.
    pub resolve: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel_off: Option<usize>,
    pub extra_off: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// Where the relaxed pattern matched, relative to the module base.
    pub candidate_rva: u64,
    pub candidate_va: u64,
    /// Bytes the original pattern constrained (full bytes and half bytes).
    pub constrained_bytes: u32,
    /// How many of those still match at the candidate location.
    pub matched_bytes: u32,
    pub similarity: f32,
    /// Byte positions inside the pattern that drifted.
    pub mismatch_offsets: Vec<u32>,
    /// How many places in `.text` the repaired pattern matches.
    pub repaired_matches: u32,
    /// `true` when the repaired pattern is unique and can be pasted into the
    /// database as-is.
    pub unique: bool,
    /// `true` when `--auto-repair` re-scanned with this pattern and the result
    /// resolved cleanly, so the offset was recovered in this same run.
    pub applied: bool,
}

/// Raw repair result before module/name metadata is attached.
pub(crate) struct Candidate {
    pub offset: usize,
    pub matched: u32,
    pub constrained: u32,
    pub mismatches: Vec<u32>,
    pub repaired: String,
    pub repaired_matches: u32,
}

/// Render the unique suggestions as a `--pattern-file` document, so a broken
/// database can be patched by re-running with the emitted file instead of
/// hand-editing signatures.
///
/// Ambiguous suggestions are left out: loading them would replace a missing
/// offset with a possibly wrong one.
pub fn render_pattern_file(repairs: &[PatternRepair]) -> Option<String> {
    let patterns: Vec<_> = repairs
        .iter()
        .filter(|repair| repair.unique)
        .map(|repair| {
            let mut entry = serde_json::json!({
                "name": repair.name,
                "module": repair.module,
                "pattern": repair.repaired,
                "resolve": repair.resolve,
                "extra_off": repair.extra_off,
            });
            if let Some(rel_off) = repair.rel_off {
                entry["rel_off"] = rel_off.into();
            }
            if let Some(prototype) = repair.prototype.as_deref() {
                entry["prototype"] = prototype.into();
            }
            entry
        })
        .collect();
    if patterns.is_empty() {
        return None;
    }
    serde_json::to_string_pretty(&serde_json::json!({ "patterns": patterns })).ok()
}

/// Find the best relaxed form of `original` inside `hay`.
///
/// Returns `None` when the pattern is unparsable, too weak to relax, or when
/// nothing in `hay` retains enough of it to be a credible candidate.
pub(crate) fn suggest(original: &str, hay: &[u8]) -> Option<Candidate> {
    let (bytes, mask) = parse_ida(original).ok()?;
    if bytes.is_empty() || bytes.len() > hay.len() {
        return None;
    }

    let constrained: Vec<usize> = (0..mask.len()).filter(|&i| mask[i] != 0).collect();
    if constrained.len() < MIN_CONSTRAINED {
        return None;
    }

    let (offset, matched) = best_partial_match(hay, &bytes, &mask, &constrained)?;
    let similarity = matched as f32 / constrained.len() as f32;
    if similarity < MIN_SIMILARITY {
        return None;
    }

    let mismatches: Vec<u32> = constrained
        .iter()
        .copied()
        .filter(|&i| !byte_matches(hay[offset + i], bytes[i], mask[i]))
        .map(|i| i as u32)
        .collect();

    let repaired = render_relaxed(&bytes, &mask, &mismatches);
    let remaining = constrained.len() - mismatches.len();
    if remaining < MIN_CONSTRAINED {
        return None;
    }

    let (repaired_bytes, repaired_mask) = parse_ida(&repaired).ok()?;
    let repaired_matches = find_all_pattern(hay, &repaired_bytes, &repaired_mask).len();

    Some(Candidate {
        offset,
        matched,
        constrained: constrained.len() as u32,
        mismatches,
        repaired,
        repaired_matches: u32::try_from(repaired_matches).unwrap_or(u32::MAX),
    })
}

/// Slide the pattern over `hay` and return the offset that satisfies the most
/// constrained positions, together with that count.
///
/// Ties keep the first (lowest) offset, which makes the result deterministic.
fn best_partial_match(
    hay: &[u8],
    bytes: &[u8],
    mask: &[u8],
    constrained: &[usize],
) -> Option<(usize, u32)> {
    let last = hay.len().checked_sub(bytes.len())?;
    let mut best_offset = 0usize;
    let mut best_score = 0usize;

    for offset in 0..=last {
        let mut score = 0usize;
        let mut left = constrained.len();
        for &i in constrained {
            left -= 1;
            if byte_matches(hay[offset + i], bytes[i], mask[i]) {
                score += 1;
            } else if score + left <= best_score {
                // Cannot beat the incumbent even if everything else matches.
                score = 0;
                break;
            }
        }
        if score > best_score {
            best_score = score;
            best_offset = offset;
        }
    }

    if best_score == 0 {
        return None;
    }
    Some((best_offset, best_score as u32))
}

/// Re-render an IDA pattern, replacing the drifted positions with `?`.
fn render_relaxed(bytes: &[u8], mask: &[u8], mismatches: &[u32]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    for (i, (value, mask)) in bytes.iter().zip(mask.iter()).enumerate() {
        if mismatches.contains(&(i as u32)) {
            out.push("?".to_string());
        } else {
            out.push(token(*value, *mask));
        }
    }
    out.join(" ")
}

fn token(value: u8, mask: u8) -> String {
    match mask {
        0xFF => format!("{value:02X}"),
        0xF0 => format!("{:X}?", value >> 4),
        0x0F => format!("?{:X}", value & 0x0F),
        _ => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REPAIR_ATTEMPTS, suggest};

    #[test]
    fn wildcards_only_the_drifted_bytes() {
        // The build changed one byte in the middle of the signature.
        let mut hay = vec![0x90u8; 64];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0xF9,
        ];
        hay[16..16 + func.len()].copy_from_slice(&func);

        let original = "48 89 5C 24 08 57 48 83 EC 20 8B F9";
        let candidate = suggest(original, &hay).expect("repair candidate");

        assert_eq!(candidate.offset, 16);
        assert_eq!(candidate.constrained, 12);
        assert_eq!(candidate.matched, 11);
        assert_eq!(candidate.mismatches, vec![9]);
        assert_eq!(candidate.repaired, "48 89 5C 24 08 57 48 83 EC ? 8B F9");
        assert_eq!(candidate.repaired_matches, 1);
    }

    #[test]
    fn keeps_existing_wildcards_and_half_bytes() {
        let mut hay = vec![0x00u8; 48];
        let func = [
            0x48u8, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0x4C, 0x8D, 0x35, 0x48, 0x8B, 0xCB, 0xE8,
        ];
        hay[8..8 + func.len()].copy_from_slice(&func);

        let original = "48 8B 05 ? ? ? ? 4? 8D 3D 48 8B CB E8";
        let candidate = suggest(original, &hay).expect("repair candidate");

        assert_eq!(candidate.offset, 8);
        // The four `?` tokens are unconstrained and never counted; `4?`
        // survives because only its high nibble is constrained.
        assert_eq!(candidate.constrained, 10);
        assert_eq!(candidate.matched, 9);
        assert_eq!(candidate.mismatches, vec![9]);
        assert_eq!(candidate.repaired, "48 8B 05 ? ? ? ? 4? 8D ? 48 8B CB E8");
        assert_eq!(candidate.repaired_matches, 1);
    }

    #[test]
    fn rejects_patterns_that_drifted_beyond_recognition() {
        let hay = vec![0xCCu8; 128];
        assert!(suggest("48 89 5C 24 08 57 48 83 EC 20 8B F9", &hay).is_none());
    }

    #[test]
    fn rejects_patterns_too_weak_to_relax_further() {
        let mut hay = vec![0x90u8; 32];
        hay[4..8].copy_from_slice(&[0x48, 0x8B, 0x01, 0xC3]);
        // Only four constrained bytes: relaxing any of them is meaningless.
        assert!(suggest("48 8B 01 C3", &hay).is_none());
    }

    #[test]
    fn reports_a_still_matching_pattern_with_no_mismatches() {
        // Failure came from resolution, not from matching: the report should
        // say so rather than invent drift.
        let mut hay = vec![0x90u8; 64];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xF9,
        ];
        hay[32..32 + func.len()].copy_from_slice(&func);

        let original = "48 89 5C 24 08 57 48 83 EC 20 8B F9";
        let candidate = suggest(original, &hay).expect("repair candidate");
        assert!(candidate.mismatches.is_empty());
        assert_eq!(candidate.repaired, original);
        assert_eq!(candidate.matched, candidate.constrained);
    }

    #[test]
    fn flags_a_repair_that_is_no_longer_unique() {
        let mut hay = vec![0x90u8; 96];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0xF9,
        ];
        hay[8..8 + func.len()].copy_from_slice(&func);
        let mut twin = func;
        twin[9] = 0x40;
        hay[48..48 + twin.len()].copy_from_slice(&twin);

        let candidate = suggest("48 89 5C 24 08 57 48 83 EC 20 8B F9", &hay)
            .expect("repair candidate for duplicated prologue");
        assert_eq!(candidate.mismatches, vec![9]);
        assert_eq!(candidate.repaired_matches, 2);
    }

    #[test]
    fn attempt_budget_is_bounded() {
        assert!(MAX_REPAIR_ATTEMPTS > 0 && MAX_REPAIR_ATTEMPTS <= 256);
    }

    /// Repair sweeps a whole `.text` section, so cost matters on patch day.
    /// Run with `cargo test --release -- --ignored repair_of_a_realistic`.
    #[test]
    #[ignore = "timing-sensitive; meaningful only in release mode"]
    fn repair_of_a_realistic_text_section_stays_fast() {
        // client.dll's .text is on the order of 16 MiB.
        let mut hay = vec![0x90u8; 16 * 1024 * 1024];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0xF9, 0x33, 0xDB,
        ];
        let at = hay.len() - 4096;
        hay[at..at + func.len()].copy_from_slice(&func);

        let start = std::time::Instant::now();
        let candidate = suggest("48 89 5C 24 08 57 48 83 EC 20 8B F9 33 DB", &hay)
            .expect("repair candidate at the end of the section");
        let elapsed = start.elapsed();

        assert_eq!(candidate.offset, at);
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "one repair sweep took {elapsed:?}"
        );
    }

    #[test]
    fn pruning_still_finds_a_better_candidate_further_along() {
        // A weak partial match comes first; the real function is later. The
        // score-pruning fast path must not let the earlier one win.
        let mut hay = vec![0x11u8; 160];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x8B, 0xF9, 0x33, 0xDB,
        ];
        let mut weak = func;
        weak[0] = 0x40;
        weak[3] = 0x28;
        weak[10] = 0x8A;
        hay[16..16 + weak.len()].copy_from_slice(&weak);
        let mut better = func;
        better[12] = 0x32;
        hay[96..96 + better.len()].copy_from_slice(&better);

        let candidate = suggest("48 89 5C 24 08 57 48 83 EC 20 8B F9 33 DB", &hay)
            .expect("repair candidate for the later, closer match");
        assert_eq!(candidate.offset, 96);
        assert_eq!(candidate.mismatches, vec![12]);
        assert_eq!(candidate.matched, 13);
        assert_eq!(candidate.repaired_matches, 1);
    }
}
