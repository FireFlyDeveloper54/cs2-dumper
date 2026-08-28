//! PE/section-aware IDA-style Pattern scanner for CS2 modules.
//!
//! This module is the Rust port + evolution of the C++ `EnhancedScanner`
//! from the standalone Pattern-dumper.  It supports:
//!
//!   * IDA-style patterns (`"48 8B ? ? ? ? E8"`) scoped to a module's
//!     `.text` section (with fallback to `.rdata`/`.data` for globals).
//!   * Automatic relative address resolution:
//!       - `Rel32`     : follow E8/E9 disp32 to call/jump target
//!       - `RipRel`    : follow 48 8B/8D/89 05/0D disp32 to data/global
//!       - `StringRef` : locate a unique string in `.rdata`, find the
//!         `.text` LEA that references it, walk back to the function prologue —
//!         the Ghidra "find by string" workflow, robust across CS2 patches.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use memflow::prelude::v1::*;
use pelite::pe64::{Pe, PeView};
use rayon::prelude::*;

use crate::analysis::module_data::ascii_lower_cow;
use crate::analysis::read::i32_le_at;
use crate::ui;

pub mod database;
pub mod offsets_writer;
pub mod repair;
pub mod writers;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveKind {
    None,
    Rel32 { rel_off: usize },
    RipRel { rel_off: usize },
    StringRef,
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub name: &'static str,
    pub module: &'static str,
    /// IDA-style bytes, or — for `StringRef` — the literal string to search.
    pub needle: &'static str,
    pub resolve: ResolveKind,
    pub extra_off: i64,
    /// IDA / Hex-Rays C-style function prototype, e.g.
    /// `__int64 __fastcall(__int64 a1, float *a2)`.  When present this is
    /// emitted into all generated artefacts (hpp typedef body, rs doc
    /// comment, md column) so consumers can hook with the real argument
    /// list instead of the generic `void __fastcall(void*, ...)` shape.
    /// Empty string means "not yet recovered".
    pub prototype: &'static str,
}

/// Owned variant used for a user-maintained JSON signature file. Keeping the
/// built-in database static avoids a startup allocation; external entries are
/// converted to this form and are scanned by the exact same engine.
#[derive(Clone, Debug)]
pub struct PatternSpec {
    pub name: String,
    pub module: String,
    pub needle: String,
    pub resolve: ResolveKind,
    pub extra_off: i64,
    pub prototype: String,
}

/// Common accessors for builtin [`Pattern`]s and file-loaded [`PatternSpec`]s.
///
/// Public because [`scan_all_with_options`] is generic over this trait.
pub trait PatternLike {
    fn name(&self) -> &str;
    fn module(&self) -> &str;
    fn needle(&self) -> &str;
    fn resolve(&self) -> ResolveKind;
    fn extra_off(&self) -> i64;
    fn prototype(&self) -> &str;
    fn needle_cow(&self) -> Cow<'static, str>;
    fn display_name_cow(&self) -> Cow<'static, str>;
}

impl PatternLike for Pattern {
    fn name(&self) -> &str {
        self.name
    }
    fn module(&self) -> &str {
        self.module
    }
    fn needle(&self) -> &str {
        self.needle
    }
    fn resolve(&self) -> ResolveKind {
        self.resolve
    }
    fn extra_off(&self) -> i64 {
        self.extra_off
    }
    fn prototype(&self) -> &str {
        self.prototype
    }
    fn needle_cow(&self) -> Cow<'static, str> {
        Cow::Borrowed(self.needle)
    }
    fn display_name_cow(&self) -> Cow<'static, str> {
        match display_name(self.name) {
            Cow::Borrowed(s) => Cow::Borrowed(s),
            Cow::Owned(s) => Cow::Owned(s),
        }
    }
}

impl PatternLike for PatternSpec {
    fn name(&self) -> &str {
        &self.name
    }
    fn module(&self) -> &str {
        &self.module
    }
    fn needle(&self) -> &str {
        &self.needle
    }
    fn resolve(&self) -> ResolveKind {
        self.resolve
    }
    fn extra_off(&self) -> i64 {
        self.extra_off
    }
    fn prototype(&self) -> &str {
        &self.prototype
    }
    fn needle_cow(&self) -> Cow<'static, str> {
        Cow::Owned(self.needle.clone())
    }
    fn display_name_cow(&self) -> Cow<'static, str> {
        Cow::Owned(display_name(&self.name).into_owned())
    }
}

impl From<&Pattern> for PatternSpec {
    fn from(value: &Pattern) -> Self {
        Self {
            name: value.name.to_string(),
            module: value.module.to_string(),
            needle: value.needle.to_string(),
            resolve: value.resolve,
            extra_off: value.extra_off,
            prototype: value.prototype.to_string(),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum PatternFile {
    List(Vec<ExternalPattern>),
    Wrapped { patterns: Vec<ExternalPattern> },
}

#[derive(Debug, serde::Deserialize)]
struct ExternalPattern {
    name: String,
    module: String,
    #[serde(alias = "needle")]
    pattern: String,
    #[serde(default)]
    resolve: ExternalResolve,
    #[serde(default)]
    rel_off: Option<usize>,
    #[serde(default)]
    extra_off: i64,
    #[serde(default)]
    prototype: String,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExternalResolve {
    #[default]
    Raw,
    Rel32,
    Riprel,
    #[serde(alias = "stringref", alias = "string-ref")]
    StringRef,
}

/// Load user patterns. A duplicate `(module, name)` replaces the built-in
/// entry; a new key is appended. Entries are validated before attaching to CS2.
pub fn load_pattern_file(path: &Path) -> Result<Vec<PatternSpec>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read pattern file {}", path.display()))?;
    let entries = match serde_json::from_str::<PatternFile>(&raw)
        .with_context(|| format!("invalid pattern JSON in {}", path.display()))?
    {
        PatternFile::List(entries) => entries,
        PatternFile::Wrapped { patterns } => patterns,
    };
    let mut keys = BTreeSet::new();
    entries
        .into_iter()
        .map(|entry| {
            if entry.name.trim().is_empty() || entry.module.trim().is_empty() {
                return Err(anyhow!("pattern name and module must not be empty"));
            }
            let resolve = match entry.resolve {
                ExternalResolve::Raw => ResolveKind::None,
                ExternalResolve::Rel32 => ResolveKind::Rel32 {
                    rel_off: entry.rel_off.ok_or_else(|| {
                        anyhow!(
                            "{}::{} uses rel32 but has no rel_off",
                            entry.module,
                            entry.name
                        )
                    })?,
                },
                ExternalResolve::Riprel => ResolveKind::RipRel {
                    rel_off: entry.rel_off.ok_or_else(|| {
                        anyhow!(
                            "{}::{} uses riprel but has no rel_off",
                            entry.module,
                            entry.name
                        )
                    })?,
                },
                ExternalResolve::StringRef => ResolveKind::StringRef,
            };
            match resolve {
                ResolveKind::StringRef => {
                    if entry.pattern.is_empty() {
                        return Err(anyhow!(
                            "string reference {}::{} must not be empty",
                            entry.module,
                            entry.name
                        ));
                    }
                }
                _ => {
                    parse_ida(&entry.pattern).with_context(|| {
                        format!("invalid pattern {}::{}", entry.module, entry.name)
                    })?;
                }
            }
            if !keys.insert(pattern_key(&entry.module, &entry.name)) {
                return Err(anyhow!(
                    "duplicate external pattern {}::{}",
                    entry.module,
                    entry.name
                ));
            }
            Ok(PatternSpec {
                name: entry.name,
                module: entry.module,
                needle: entry.pattern,
                resolve,
                extra_off: entry.extra_off,
                prototype: entry.prototype,
            })
        })
        .collect()
}

pub fn merged_patterns(builtins: &[Pattern], external: Vec<PatternSpec>) -> Vec<PatternSpec> {
    let mut merged: Vec<PatternSpec> = builtins.iter().map(PatternSpec::from).collect();
    let mut positions: BTreeMap<String, usize> = merged
        .iter()
        .enumerate()
        .map(|(index, pattern)| (pattern_key(&pattern.module, &pattern.name), index))
        .collect();
    for pattern in external {
        let key = pattern_key(&pattern.module, &pattern.name);
        if let Some(index) = positions.get(&key).copied() {
            merged[index] = pattern;
        } else {
            positions.insert(key, merged.len());
            merged.push(pattern);
        }
    }
    merged
}

fn pattern_key(module: &str, name: &str) -> String {
    format!("{}::{}", ascii_lower_cow(module), ascii_lower_cow(name))
}

fn canonical_module_name(module: &str) -> Cow<'_, str> {
    ascii_lower_cow(module.trim())
}

thread_local! {
    static CACHE_LOOKUP_KEY: RefCell<String> = const { RefCell::new(String::new()) };
}

fn push_ascii_lower(buf: &mut String, text: &str) {
    buf.extend(text.bytes().map(|b| char::from(b.to_ascii_lowercase())));
}

fn cache_lookup_key(module: &str, name: &str) -> String {
    let mut key = String::with_capacity(module.len() + 1 + name.len());
    push_ascii_lower(&mut key, module);
    key.push('\0');
    push_ascii_lower(&mut key, name);
    key
}

/// Previous-run `patterns.json` keyed by lowercase `module\0name`.
/// Built once on the dump thread so the rayon scan is O(1) per signature
/// instead of a linear walk of every cached hit. Lookups reuse a
/// thread-local buffer so workers do not allocate a key per signature.
pub struct PatternCacheIndex<'a> {
    by_name: HashMap<String, &'a CachedPatternHit>,
}

impl<'a> PatternCacheIndex<'a> {
    pub fn from_cache(cache: Option<&'a PatternCache>) -> Self {
        let Some(cache) = cache else {
            return Self {
                by_name: HashMap::new(),
            };
        };
        let mut by_name = HashMap::with_capacity(cache.hits.len());
        for hit in &cache.hits {
            by_name.insert(cache_lookup_key(&hit.module, &hit.name), hit);
        }
        Self { by_name }
    }

    pub fn get(&self, module: &str, name: &str, pattern: &str) -> Option<&'a CachedPatternHit> {
        if self.by_name.is_empty() {
            return None;
        }
        CACHE_LOOKUP_KEY.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            push_ascii_lower(&mut buf, module);
            buf.push('\0');
            push_ascii_lower(&mut buf, name);
            let hit = *self.by_name.get(buf.as_str())?;
            (hit.pattern == pattern).then_some(hit)
        })
    }
}

fn intern_module_name(name: &str) -> Arc<str> {
    let canon = canonical_module_name(name);
    crate::analysis::module_data::intern_loaded_name(canon.as_ref())
        .unwrap_or_else(|| Arc::from(canon.as_ref()))
}

fn intern_cached_module(name: &Arc<str>) -> Arc<str> {
    match canonical_module_name(name.as_ref()) {
        Cow::Borrowed(s) if std::ptr::eq(s.as_ptr(), name.as_ref().as_ptr()) => {
            crate::analysis::module_data::intern_loaded_name(s).unwrap_or_else(|| Arc::clone(name))
        }
        other => crate::analysis::module_data::intern_loaded_name(other.as_ref())
            .unwrap_or_else(|| Arc::from(other.as_ref())),
    }
}

fn serialize_arc_str<S: serde::Serializer>(
    value: &Arc<str>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct PatternHit {
    pub name: Cow<'static, str>,
    #[serde(serialize_with = "serialize_arc_str")]
    pub module: Arc<str>,
    pub resolve: &'static str,
    pub pattern: Cow<'static, str>,
    /// IDA / Hex-Rays C-style function prototype recovered for this
    /// Pattern, e.g. `__int64 __fastcall(__int64 a1, float *a2)`.
    /// Copied verbatim from `Pattern::prototype` so the JSON / hpp / rs
    /// / md emitters can render real argument lists for hookers.  `None`
    /// when no prototype has been recorded yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// 24 bytes of the resolved function's prologue, formatted as an
    /// IDA-style space-separated hex pattern (no wildcards).  Useful as a
    /// drop-in Pattern on builds where the database pattern is missing
    /// (e.g. `StringRef` entries) or has gone stale.  `None` for misses or
    /// when the resolved RVA falls outside the module's `.text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// Auto-synthesised IDA pattern at the resolved RVA, with `?`
    /// wildcards on relocatable bytes (CALL/JMP rel32 displacements,
    /// RIP-relative LEA/MOV displacements).  Designed to be the
    /// shortest unique-in-`.text` pattern for the resolved function;
    /// safe to paste straight into IDA / x64dbg / ReClass.NET.  `None`
    /// when the resolved RVA is outside `.text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_synth: Option<String>,
    pub found: bool,
    /// The stale database pattern this hit was recovered from, set only when
    /// `--auto-repair` replaced a drifted signature. Automation that must not
    /// trust relaxed signatures can reject any hit that carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaired_from: Option<String>,
    pub match_rva: Option<u64>,
    pub match_va: Option<u64>,
    pub rva: Option<u64>,
    pub va: Option<u64>,
    /// Number of distinct matches the pattern produced.
    /// `1` is ideal; `>1` means the pattern is ambiguous and should be tightened.
    pub matches: u32,
    /// Uniqueness confidence derived from the number of distinct matches.
    /// `1.0` means a unique match; ambiguous matches degrade toward zero.
    #[serde(default)]
    pub confidence: f32,
    pub error: Option<String>,
}

#[derive(Default, Debug, serde::Serialize)]
pub struct PatternReport {
    pub total: usize,
    pub found: usize,
    pub modules: Vec<String>,
    #[serde(default)]
    pub cache_hits: usize,
    #[serde(default)]
    pub cache_misses: usize,
    pub hits: Vec<PatternHit>,
    /// Relaxed replacements suggested for patterns that stopped matching.
    /// Empty (and omitted from JSON) on a fully healthy database.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<repair::PatternRepair>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CachedPatternHit {
    pub name: String,
    pub module: String,
    pub pattern: String,
    pub found: bool,
    pub match_rva: Option<u64>,
    #[serde(default)]
    pub matches: u32,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct PatternCache {
    #[serde(default)]
    pub hits: Vec<CachedPatternHit>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Knobs for one scan pass. Defaults keep the historical behaviour: suggest
/// repairs for stale patterns, but never act on them.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanOptions {
    /// Re-scan with a repaired pattern and keep the result when it resolves
    /// cleanly, instead of only reporting the suggestion.
    pub auto_repair: bool,
}

pub fn scan_all_with_options<P, S>(
    process: &mut P,
    sigs: &[S],
    cache: Option<&PatternCache>,
    options: ScanOptions,
) -> Result<PatternReport>
where
    P: Process + MemoryView,
    S: PatternLike + Sync,
{
    let mut module_cache: BTreeMap<String, ModuleCache> = BTreeMap::new();
    for sig in sigs {
        let key = canonical_module_name(sig.module());
        if module_cache.contains_key(key.as_ref()) {
            continue;
        }
        match ModuleCache::load(process, sig.module()) {
            Ok(mc) => {
                module_cache.insert(key.into_owned(), mc);
            }
            Err(e) => {
                log::warn!("module load failed for {}: {}", sig.module(), e);
            }
        }
    }

    let mut report = PatternReport {
        total: sigs.len(),
        modules: module_cache.keys().cloned().collect(),
        ..Default::default()
    };

    ui::step(format_args!("scanning {} patterns", sigs.len()));
    let cache_index = PatternCacheIndex::from_cache(cache);
    let scanned: Vec<(PatternHit, bool)> = sigs
        .par_iter()
        .map(|sig| {
            let cached = cache_index.get(sig.module(), sig.name(), sig.needle());
            match module_cache.get(canonical_module_name(sig.module()).as_ref()) {
                Some(mc) => scan_one_cached(mc, sig, cached),
                None => (PatternHit::fail(sig, "module not loaded"), false),
            }
        })
        .collect();

    let total = sigs.len();
    let mut ambiguous = 0u32;
    let mut repair_attempts = 0usize;
    let mut repairs_skipped = 0usize;
    for (idx, (sig, (mut hit, used_cache))) in sigs.iter().zip(scanned).enumerate() {
        ui::progress(idx + 1, total, sig.name());

        if cache.is_some() {
            if used_cache {
                report.cache_hits += 1;
            } else {
                report.cache_misses += 1;
            }
        }

        if !hit.found {
            if matches!(sig.resolve(), ResolveKind::StringRef) {
                // A `stringref` needle is a literal, not a byte pattern.
            } else if repair_attempts >= repair::MAX_REPAIR_ATTEMPTS {
                repairs_skipped += 1;
            } else if let Some(mc) = module_cache.get(canonical_module_name(sig.module()).as_ref()) {
                repair_attempts += 1;
                if let Some((suggestion, recovered)) = try_repair(mc, sig, options.auto_repair) {
                    log::warn!(
                        "{} drifted: {:.0}% of its bytes still match at {:#X}; suggested pattern `{}`{}",
                        hit.name,
                        suggestion.similarity * 100.0,
                        suggestion.candidate_va,
                        suggestion.repaired,
                        if suggestion.applied {
                            " (applied)"
                        } else if suggestion.unique {
                            ""
                        } else {
                            " (not unique — tighten before use)"
                        }
                    );
                    report.repairs.push(suggestion);
                    if let Some(recovered) = recovered {
                        hit = recovered;
                    }
                }
            }
        }

        if hit.found {
            if hit.matches > 1 {
                ambiguous += 1;
            }
            ui::found(
                &hit.name,
                hit.va.unwrap_or(0),
                &format!("[{}, {}]", hit.resolve, hit.module),
            );
            report.found += 1;
        } else {
            ui::not_found(&hit.name, hit.error.as_deref().unwrap_or("no hit"));
        }
        report.hits.push(hit);
    }
    ui::progress_clear();

    if ambiguous > 0 {
        log::warn!(
            "{} Pattern(s) matched more than once in their .text section — consider tightening",
            ambiguous
        );
    }

    if !report.repairs.is_empty() {
        log::warn!(
            "{} stale Pattern(s) have a suggested replacement in patterns.repair.json",
            report.repairs.len()
        );
    }

    if repairs_skipped > 0 {
        log::warn!(
            "repair budget of {} sweep(s) exhausted; {} more failed Pattern(s) were not analysed",
            repair::MAX_REPAIR_ATTEMPTS,
            repairs_skipped
        );
    }

    Ok(report)
}

/// Build a repair suggestion for a pattern that no longer matches its module.
fn repair_pattern<S: PatternLike>(mc: &ModuleCache, sig: &S) -> Option<repair::PatternRepair> {
    let candidate = repair::suggest(sig.needle(), mc.text())?;
    let candidate_rva = (mc.text_rva as u64).checked_add(candidate.offset as u64)?;
    let candidate_va = mc.base.checked_add(candidate_rva)?;
    Some(repair::PatternRepair {
        name: display_name(sig.name()).into_owned(),
        module: intern_cached_module(&mc.name).to_string(),
        original: sig.needle().to_string(),
        repaired: candidate.repaired,
        resolve: kind_name(sig.resolve()),
        rel_off: rel_off_of(sig.resolve()),
        extra_off: sig.extra_off(),
        prototype: Some(sig.prototype())
            .filter(|proto| !proto.is_empty())
            .map(str::to_string),
        candidate_rva,
        candidate_va,
        constrained_bytes: candidate.constrained,
        matched_bytes: candidate.matched,
        similarity: candidate.matched as f32 / candidate.constrained.max(1) as f32,
        mismatch_offsets: candidate.mismatches,
        repaired_matches: candidate.repaired_matches,
        unique: candidate.repaired_matches == 1,
        applied: false,
    })
}

/// Suggest a repair and, when `auto` is set, verify it by re-scanning with the
/// relaxed pattern. The retry only wins if it resolves as cleanly as a normal
/// hit would, so a plausible-looking but unresolvable candidate is reported
/// without being applied.
fn try_repair<S: PatternLike>(
    mc: &ModuleCache,
    sig: &S,
    auto: bool,
) -> Option<(repair::PatternRepair, Option<PatternHit>)> {
    let mut suggestion = repair_pattern(mc, sig)?;
    if !auto || !suggestion.unique || suggestion.mismatch_offsets.is_empty() {
        return Some((suggestion, None));
    }
    let retry = PatternSpec {
        name: sig.name().to_string(),
        module: sig.module().to_string(),
        needle: suggestion.repaired.clone(),
        resolve: sig.resolve(),
        extra_off: sig.extra_off(),
        prototype: sig.prototype().to_string(),
    };
    let mut hit = scan_one(mc, &retry);
    if !hit.found {
        return Some((suggestion, None));
    }
    suggestion.applied = true;
    hit.repaired_from = Some(suggestion.original.clone());
    Some((suggestion, Some(hit)))
}

fn rel_off_of(kind: ResolveKind) -> Option<usize> {
    match kind {
        ResolveKind::Rel32 { rel_off } | ResolveKind::RipRel { rel_off } => Some(rel_off),
        ResolveKind::None | ResolveKind::StringRef => None,
    }
}

fn scan_one_cached<S: PatternLike>(
    mc: &ModuleCache,
    sig: &S,
    cached: Option<&CachedPatternHit>,
) -> (PatternHit, bool) {
    if let Some(hit) = cached.and_then(|hit| validate_cached_hit(mc, sig, hit)) {
        return (hit, true);
    }
    (scan_one(mc, sig), false)
}

fn validate_cached_hit<S: PatternLike>(
    mc: &ModuleCache,
    sig: &S,
    cached: &CachedPatternHit,
) -> Option<PatternHit> {
    if !cached.found || matches!(sig.resolve(), ResolveKind::StringRef) {
        return None;
    }
    let (bytes, mask) = parse_ida(sig.needle()).ok()?;
    let match_rva = usize::try_from(cached.match_rva?).ok()?;
    let end = match_rva.checked_add(bytes.len())?;
    if end > mc.image.len() {
        return None;
    }
    if !bytes
        .iter()
        .zip(mask.iter())
        .enumerate()
        .all(|(i, (expected, mask))| byte_matches(mc.image[match_rva + i], *expected, *mask))
    {
        return None;
    }
    let match_va = mc.base.checked_add(match_rva as u64)?;
    let resolved = resolve(mc, sig, match_rva as u32, match_va);
    if resolved.2.is_some()
        || (resolution_score(mc, sig.resolve(), resolved.0) == 0
            && !matches!(sig.resolve(), ResolveKind::None))
    {
        return None;
    }
    Some(PatternHit {
        name: sig.display_name_cow(),
        module: intern_cached_module(&mc.name),
        resolve: kind_name(sig.resolve()),
        pattern: sig.needle_cow(),
        prototype: opt_proto(sig.name(), sig.prototype()),
        bytes: capture_prologue(mc, resolved.0),
        // Local reloc-wildcarded synth from the bytes at this RVA. Uniqueness
        // walks of `.text` stay on the cold scan that first discovered the hit.
        pattern_synth: synthesize_pattern_local(mc, resolved.0),
        found: true,
        repaired_from: None,
        match_rva: Some(match_rva as u64),
        match_va: Some(match_va),
        rva: Some(resolved.0),
        va: Some(resolved.1),
        matches: cached.matches.max(1),
        confidence: confidence_for_matches(cached.matches.max(1)),
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Module cache — full image + PeView
// ---------------------------------------------------------------------------

struct ModuleCache {
    name: Arc<str>,
    base: u64,
    image: Arc<[u8]>,
    text_rva: u32,
    text_size: u32,
    rdata_rva: u32,
    rdata_size: u32,
}

impl ModuleCache {
    fn load<P: Process + MemoryView>(process: &mut P, module: &str) -> Result<Self> {
        let info = process
            .module_by_name(module)
            .with_context(|| format!("module {} not present in process", module))?;

        let (_base, image) = crate::analysis::module_data::read_pe_image(process, module)
            .with_context(|| format!("failed to read image of {}", module))?;

        let view = PeView::from_bytes(&image).context("invalid PE image")?;

        let mut text_rva = 0u32;
        let mut text_size = 0u32;
        let mut rdata_rva = 0u32;
        let mut rdata_size = 0u32;

        for section in view.section_headers() {
            let name = section.name().unwrap_or("");
            match name {
                ".text" => {
                    text_rva = section.VirtualAddress;
                    text_size = section.VirtualSize;
                }
                ".rdata" => {
                    rdata_rva = section.VirtualAddress;
                    rdata_size = section.VirtualSize;
                }
                _ => {}
            }
        }

        if text_size == 0 {
            return Err(anyhow!(".text section missing in {}", module));
        }

        Ok(Self {
            name: intern_module_name(module),
            base: info.base.to_umem(),
            image,
            text_rva,
            text_size,
            rdata_rva,
            rdata_size,
        })
    }

    #[inline]
    fn text(&self) -> &[u8] {
        let lo = (self.text_rva as usize).min(self.image.len());
        let hi = lo.saturating_add(self.text_size as usize);
        if lo >= self.image.len() {
            return &[];
        }
        &self.image[lo..hi.min(self.image.len())]
    }

    #[inline]
    fn rdata(&self) -> Option<&[u8]> {
        if self.rdata_size == 0 {
            return None;
        }
        let lo = self.rdata_rva as usize;
        if lo >= self.image.len() {
            return None;
        }
        let hi = lo.saturating_add(self.rdata_size as usize);
        self.image.get(lo..hi.min(self.image.len()))
    }
}

// ---------------------------------------------------------------------------
// IDA pattern parser
// ---------------------------------------------------------------------------

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_ida(pattern: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(pattern.len() / 3);
    let mut mask = Vec::with_capacity(pattern.len() / 3);

    for tok in pattern.split_ascii_whitespace() {
        if tok == "?" || tok == "??" {
            bytes.push(0);
            mask.push(0);
            continue;
        }
        let raw = tok.as_bytes();
        if raw.len() != 2 {
            return Err(anyhow!("invalid pattern token '{}'", tok));
        }
        let (value, nibble_mask) = match (raw[0], raw[1]) {
            (b'?', lo) => {
                let low = hex_nibble(lo).ok_or_else(|| anyhow!("invalid hex nibble '{}'", tok))?;
                (low, 0x0F)
            }
            (hi, b'?') => {
                let high = hex_nibble(hi).ok_or_else(|| anyhow!("invalid hex nibble '{}'", tok))?;
                (high << 4, 0xF0)
            }
            (hi, lo) => {
                let high = hex_nibble(hi).ok_or_else(|| anyhow!("invalid hex byte '{}'", tok))?;
                let low = hex_nibble(lo).ok_or_else(|| anyhow!("invalid hex byte '{}'", tok))?;
                ((high << 4) | low, 0xFF)
            }
        };
        bytes.push(value);
        mask.push(nibble_mask);
    }

    if bytes.is_empty() {
        return Err(anyhow!("empty pattern"));
    }
    if !mask.iter().any(|fixed| *fixed != 0) {
        return Err(anyhow!("pattern must contain at least one concrete byte"));
    }
    Ok((bytes, mask))
}

fn byte_matches(actual: u8, expected: u8, mask: u8) -> bool {
    (actual & mask) == (expected & mask)
}

/// IDA-style scan over a raw buffer. This is the inner loop of the module
/// scanner; benches drive it directly so they measure the shipped matcher.
pub fn find_ida(hay: &[u8], needle: &str) -> Result<Vec<usize>> {
    let (bytes, mask) = parse_ida(needle)?;
    Ok(find_all_pattern(hay, &bytes, &mask))
}

/// Walk every match of `(bytes, mask)` in `hay`. `visit` returns whether to
/// keep searching. Full scans and synth uniqueness share this so a first-byte
/// skip cannot diverge from the reported offsets.
fn visit_pattern_matches(
    hay: &[u8],
    bytes: &[u8],
    mask: &[u8],
    mut visit: impl FnMut(usize) -> bool,
) {
    let need = bytes.len();
    if need == 0 || hay.len() < need || mask.len() < need {
        return;
    }
    let first = bytes[0];
    let first_mask = mask[0];
    let first_exact = first_mask == 0xFF;
    let first_wild = first_mask == 0;
    let last_start = hay.len() - need;
    let mut i = 0usize;
    while i <= last_start {
        if first_exact {
            match hay[i..=last_start].iter().position(|&b| b == first) {
                Some(delta) => i += delta,
                None => return,
            }
        } else if !first_wild && !byte_matches(hay[i], first, first_mask) {
            i += 1;
            continue;
        }

        let mut ok = true;
        for j in 1..need {
            if !byte_matches(hay[i + j], bytes[j], mask[j]) {
                ok = false;
                break;
            }
        }
        if ok && !visit(i) {
            return;
        }
        i += 1;
    }
}

fn find_all_pattern(hay: &[u8], bytes: &[u8], mask: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    visit_pattern_matches(hay, bytes, mask, |offset| {
        out.push(offset);
        true
    });
    out
}

/// Exact byte search used by `StringRef`. Same first-byte skip as the IDA
/// matcher, including overlapping matches.
fn visit_exact_matches(hay: &[u8], needle: &[u8], mut visit: impl FnMut(usize) -> bool) {
    if needle.is_empty() || hay.len() < needle.len() {
        return;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0usize;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|&b| b == first) {
            Some(delta) => i += delta,
            None => return,
        }
        if hay[i..].starts_with(needle) && !visit(i) {
            return;
        }
        i += 1;
    }
}

#[cfg(test)]
fn find_all_exact(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    visit_exact_matches(hay, needle, |offset| {
        out.push(offset);
        true
    });
    out
}

// ---------------------------------------------------------------------------
// Core scan + resolve
// ---------------------------------------------------------------------------

fn scan_one<S: PatternLike>(mc: &ModuleCache, sig: &S) -> PatternHit {
    scan_pattern(mc, sig)
}

fn scan_pattern<S: PatternLike>(mc: &ModuleCache, sig: &S) -> PatternHit {
    if matches!(sig.resolve(), ResolveKind::StringRef) {
        return scan_string_ref(mc, sig);
    }
    let (bytes, mask) = match parse_ida(sig.needle()) {
        Ok(v) => v,
        Err(e) => return PatternHit::fail(sig, &format!("bad pattern: {}", e)),
    };

    // Scan all useful regions. `.text` remains the preferred source, but a
    // stale `.text` false-positive must not prevent a valid `.rdata`/image
    // candidate from being selected.
    let text_hits = find_all_pattern(mc.text(), &bytes, &mask)
        .into_iter()
        .filter_map(|offset| {
            u32::try_from(offset)
                .ok()
                .and_then(|offset| mc.text_rva.checked_add(offset))
        })
        .collect::<Vec<_>>();
    let rdata_hits = mc
        .rdata()
        .map(|rd| {
            find_all_pattern(rd, &bytes, &mask)
                .into_iter()
                .filter_map(|offset| {
                    u32::try_from(offset)
                        .ok()
                        .and_then(|offset| mc.rdata_rva.checked_add(offset))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let image_hits = find_all_pattern(&mc.image, &bytes, &mask)
        .into_iter()
        .filter_map(|offset| u32::try_from(offset).ok())
        .collect::<Vec<_>>();

    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for (rvas, region_score) in [(&text_hits, 30i32), (&rdata_hits, 20), (&image_hits, 0)] {
        for &rva in rvas.iter() {
            if seen.insert(rva) {
                candidates.push((rva, region_score));
            }
        }
    }

    if candidates.is_empty() {
        return PatternHit::fail(sig, "pattern not found");
    }
    let matches = candidates.len().min(u32::MAX as usize) as u32;

    // A stale signature can match multiple instruction sequences. Prefer a
    // candidate whose resolved target is inside the expected image/section,
    // while retaining deterministic first-match behavior when scores tie.
    let mut selected = None;
    let mut selected_score = i32::MIN;
    let mut first_error = None;
    for (match_rva, region_score) in candidates {
        let Some(match_va) = mc.base.checked_add(match_rva as u64) else {
            continue;
        };
        let resolved = resolve(mc, sig, match_rva, match_va);
        if let Some(error) = resolved.2.as_ref() {
            first_error.get_or_insert_with(|| error.clone());
            continue;
        }
        let target_score = resolution_score(mc, sig.resolve(), resolved.0);
        if target_score == 0 && !matches!(sig.resolve(), ResolveKind::None) {
            continue;
        }
        let score = region_score + target_score;
        if score > selected_score {
            selected_score = score;
            selected = Some((match_rva, resolved.0, resolved.1));
        }
    }

    let Some((match_rva, res_rva, res_va)) = selected else {
        return PatternHit::fail(
            sig,
            first_error.as_deref().unwrap_or("unable to resolve match"),
        );
    };

    let Some(match_va) = mc.base.checked_add(match_rva as u64) else {
        return PatternHit::fail(sig, "match address overflow");
    };

    PatternHit {
        name: sig.display_name_cow(),
        module: intern_cached_module(&mc.name),
        resolve: kind_name(sig.resolve()),
        pattern: sig.needle_cow(),
        prototype: opt_proto(sig.name(), sig.prototype()),
        bytes: capture_prologue(mc, res_rva),
        pattern_synth: synthesize_pattern(mc, res_rva),
        found: true,
        repaired_from: None,
        match_rva: Some(match_rva as u64),
        match_va: Some(match_va),
        rva: Some(res_rva),
        va: Some(res_va),
        matches,
        confidence: confidence_for_matches(matches),
        error: None,
    }
}

fn scan_string_ref<S: PatternLike>(mc: &ModuleCache, sig: &S) -> PatternHit {
    let needle = sig.needle().as_bytes();
    if needle.is_empty() {
        return PatternHit::fail(sig, "empty string reference");
    }

    let mut string_rvas = Vec::new();
    for (region_rva, region) in [
        (mc.rdata_rva, mc.rdata().unwrap_or(&[])),
        (0, mc.image.as_ref()),
    ] {
        visit_exact_matches(region, needle, |offset| {
            if let Some(rva) = u32::try_from(offset)
                .ok()
                .and_then(|offset| region_rva.checked_add(offset))
                && !string_rvas.contains(&rva)
            {
                string_rvas.push(rva);
            }
            true
        });
    }
    if string_rvas.is_empty() {
        return PatternHit::fail(sig, "string reference not found");
    }

    let xrefs: Vec<u32> = string_rvas
        .iter()
        .flat_map(|&rva| find_string_xrefs(mc, rva))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if xrefs.is_empty() {
        return PatternHit::fail(sig, "string reference has no RIP-relative xref");
    }
    let match_rva = xrefs[0];
    let Some(match_va) = mc.base.checked_add(match_rva as u64) else {
        return PatternHit::fail(sig, "match address overflow");
    };
    let resolved_rva = find_function_start(mc, match_rva);
    let Some(resolved_va) = mc.base.checked_add(resolved_rva) else {
        return PatternHit::fail(sig, "resolved address overflow");
    };

    PatternHit {
        name: sig.display_name_cow(),
        module: intern_cached_module(&mc.name),
        resolve: kind_name(sig.resolve()),
        pattern: sig.needle_cow(),
        prototype: opt_proto(sig.name(), sig.prototype()),
        bytes: capture_prologue(mc, resolved_rva),
        pattern_synth: synthesize_pattern(mc, resolved_rva),
        found: true,
        repaired_from: None,
        match_rva: Some(match_rva as u64),
        match_va: Some(match_va),
        rva: Some(resolved_rva),
        va: Some(resolved_va),
        matches: xrefs.len().min(u32::MAX as usize) as u32,
        confidence: confidence_for_matches(xrefs.len().min(u32::MAX as usize) as u32),
        error: None,
    }
}

fn is_rip_lead_byte(b: u8) -> bool {
    matches!(b, 0x40..=0x4F | 0x8B | 0x8D | 0x89)
}

fn find_string_xrefs(mc: &ModuleCache, string_rva: u32) -> Vec<u32> {
    let text = mc.text();
    let text_base = mc.text_rva as usize;
    let Some(string_va) = mc.base.checked_add(string_rva as u64) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < text.len() {
        match text[i..].iter().position(|&b| is_rip_lead_byte(b)) {
            Some(delta) => i += delta,
            None => break,
        }
        // REX is decoded at its own byte; the following opcode is not a
        // separate RIP instruction.
        if i > 0 && (0x40..=0x4F).contains(&text[i - 1]) {
            i += 1;
            continue;
        }
        let Some(absolute) = text_base.checked_add(i) else {
            break;
        };
        if rip_target_at(mc, absolute) == Some(string_va)
            && let Ok(absolute) = u32::try_from(absolute)
        {
            out.push(absolute);
        }
        i += 1;
    }
    out
}

#[inline]
fn confidence_for_matches(matches: u32) -> f32 {
    match matches {
        0 => 0.0,
        1 => 1.0,
        n => 1.0 / n as f32,
    }
}

fn rip_target_at(mc: &ModuleCache, rva: usize) -> Option<u64> {
    let image = &mc.image;
    if rva >= image.len() {
        return None;
    }
    let b0 = image[rva];
    if (0x40..=0x4F).contains(&b0) && rva.checked_add(7)? <= image.len() {
        let op = image[rva + 1];
        let modrm = image[rva + 2];
        if matches!(op, 0x8B | 0x8D | 0x89) && (modrm & 0xC7) == 0x05 {
            let disp = i32_le_at(image, rva + 3)? as i64;
            return relative_target(mc.base, rva, 7, disp);
        }
    }
    if matches!(b0, 0x8B | 0x8D | 0x89) && rva.checked_add(6)? <= image.len() {
        let modrm = image[rva + 1];
        if (modrm & 0xC7) == 0x05 {
            let disp = i32_le_at(image, rva + 2)? as i64;
            return relative_target(mc.base, rva, 6, disp);
        }
    }
    None
}

fn find_function_start(mc: &ModuleCache, xref_rva: u32) -> u64 {
    let lo = mc.text_rva as u64;
    let start = (xref_rva as u64).saturating_sub(0x1000).max(lo);
    for rva in (start..=xref_rva as u64).rev() {
        let i = rva as usize;
        let image = &mc.image;
        if i.checked_add(2).is_none_or(|end| end > image.len()) {
            continue;
        }
        let prologue = (matches!(image[i], 0x40..=0x4F) && matches!(image[i + 1], 0x53..=0x57))
            || (image[i] == 0x4C
                && i + 3 <= image.len()
                && image[i + 1] == 0x8B
                && image[i + 2] == 0xDC)
            || (image[i] == 0x48
                && i + 3 <= image.len()
                && image[i + 1] == 0x83
                && image[i + 2] == 0xEC)
            || (image[i] == 0x48
                && i + 4 <= image.len()
                && image[i + 1] == 0x89
                && image[i + 2] == 0x5C);
        if prologue {
            return rva;
        }
    }
    xref_rva as u64
}

fn resolution_score(mc: &ModuleCache, kind: ResolveKind, rva: u64) -> i32 {
    let image_len = mc.image.len() as u64;
    let in_image = rva < image_len;
    let text_lo = mc.text_rva as u64;
    let text_hi = text_lo.saturating_add(mc.text_size as u64);
    let in_text = rva >= text_lo && rva < text_hi;
    match kind {
        ResolveKind::None => {
            if in_image {
                2
            } else {
                0
            }
        }
        ResolveKind::Rel32 { .. } => {
            if in_text {
                5
            } else if in_image {
                2
            } else {
                0
            }
        }
        ResolveKind::RipRel { .. } => {
            if in_image {
                5
            } else {
                0
            }
        }
        ResolveKind::StringRef => {
            if in_text {
                5
            } else {
                0
            }
        }
    }
}

/// Read up to 24 bytes from the resolved RVA and format them as a
/// space-separated, fully-concrete IDA pattern.  Returns `None` if the
/// RVA is not inside the module's `.text` window.
fn capture_prologue(mc: &ModuleCache, rva: u64) -> Option<String> {
    let lo = rva as usize;
    let text_lo = mc.text_rva as usize;
    let text_hi = text_lo.saturating_add(mc.text_size as usize);
    if lo < text_lo || lo >= text_hi {
        return None;
    }
    let hi = lo.saturating_add(24).min(text_hi).min(mc.image.len());
    let slice = mc.image.get(lo..hi)?;
    if slice.is_empty() {
        return None;
    }
    let mut s = String::with_capacity(slice.len() * 3);
    for (i, b) in slice.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        push_hex_byte(&mut s, *b);
    }
    Some(s)
}

fn relative_target(base: u64, rva: usize, instruction_len: u64, disp: i64) -> Option<u64> {
    let target = base as i128 + rva as i128 + instruction_len as i128 + disp as i128;
    (0..=u64::MAX as i128).contains(&target).then_some(target as u64)
}

fn resolve<S: PatternLike>(
    mc: &ModuleCache,
    sig: &S,
    match_rva: u32,
    match_va: u64,
) -> (u64, u64, Option<String>) {
    match sig.resolve() {
        ResolveKind::None => adjusted_target(mc, match_va, sig.extra_off()),
        ResolveKind::Rel32 { rel_off } | ResolveKind::RipRel { rel_off } => {
            let Some(idx) = (match_rva as usize).checked_add(rel_off) else {
                return (0, 0, Some("disp32 offset overflow".into()));
            };
            let Some(end) = idx.checked_add(4) else {
                return (0, 0, Some("disp32 offset overflow".into()));
            };
            if end > mc.image.len() {
                return (0, 0, Some("disp32 out of image".into()));
            }
            let Some(disp) = crate::analysis::read::i32_le(&mc.image[idx..end]) else {
                return (0, 0, Some("disp32 out of image".into()));
            };
            let disp = disp as i64;
            let target_va =
                match_va as i128 + rel_off as i128 + 4 + disp as i128 + sig.extra_off() as i128;
            if target_va < mc.base as i128 || target_va > u64::MAX as i128 {
                return (
                    0,
                    0,
                    Some("resolved target outside module address space".into()),
                );
            }
            let target_va = target_va as u64;
            checked_module_target(mc, target_va, "resolved")
        }
        ResolveKind::StringRef => (match_rva as u64, match_va, None),
    }
}

fn adjusted_target(mc: &ModuleCache, match_va: u64, extra_off: i64) -> (u64, u64, Option<String>) {
    let target_va = match_va as i128 + extra_off as i128;
    if target_va < mc.base as i128 || target_va > u64::MAX as i128 {
        return (
            0,
            0,
            Some("adjusted target outside module address space".into()),
        );
    }
    checked_module_target(mc, target_va as u64, "adjusted")
}

fn checked_module_target(
    mc: &ModuleCache,
    target_va: u64,
    operation: &str,
) -> (u64, u64, Option<String>) {
    let Some(target_rva) = target_va.checked_sub(mc.base) else {
        return (
            0,
            0,
            Some(format!("{operation} target outside module address space")),
        );
    };
    if target_rva >= mc.image.len() as u64 {
        return (
            0,
            0,
            Some(format!("{operation} target outside module image")),
        );
    }
    (target_rva, target_va, None)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn kind_name(k: ResolveKind) -> &'static str {
    match k {
        ResolveKind::None => "raw",
        ResolveKind::Rel32 { .. } => "rel32",
        ResolveKind::RipRel { .. } => "riprel",
        ResolveKind::StringRef => "stringref",
    }
}

impl PatternHit {
    fn fail<S: PatternLike>(sig: &S, err: &str) -> Self {
        Self {
            name: sig.display_name_cow(),
            module: intern_module_name(sig.module()),
            resolve: kind_name(sig.resolve()),
            pattern: sig.needle_cow(),
            prototype: opt_proto(sig.name(), sig.prototype()),
            bytes: None,
            pattern_synth: None,
            found: false,
            repaired_from: None,
            match_rva: None,
            match_va: None,
            rva: None,
            va: None,
            matches: 0,
            confidence: 0.0,
            error: Some(err.to_string()),
        }
    }
}

fn display_name(raw: &str) -> Cow<'_, str> {
    if raw.is_empty() {
        return Cow::Borrowed("");
    }
    if let Some(idx) = raw.rfind("::") {
        return Cow::Owned(raw[idx + 2..].to_string());
    }
    if raw.starts_with("m_")
        || raw.starts_with("dw")
        || raw.starts_with("g_")
        || raw.starts_with("C_")
        || raw.ends_with("_t")
    {
        return Cow::Borrowed(raw);
    }

    let parts: Vec<&str> = raw.split('_').filter(|p| !p.is_empty()).collect();
    if parts.len() > 1 {
        let head = parts[0];
        // Only strip the leading token when it is genuinely a C++ class prefix
        // (`CCSPlayer`, `CBaseEntity`, `IGameSystem`) — i.e. `C`/`I` followed by
        // an uppercase letter. An ordinary verb head like `SetAbsOrigin` or
        // `PhysicsRunThink` must NOT be stripped, otherwise a descriptive name
        // collapses to a meaningless fragment (`SetAbsOrigin_Pawn` -> `Pawn`).
        let mut hc = head.chars();
        let looks_like_class = matches!(hc.next(), Some('C') | Some('I'))
            && hc.next().map(|c| c.is_ascii_uppercase()).unwrap_or(false);
        if looks_like_class {
            // Keep every segment after the class prefix so multi-word method
            // names survive (`CCSPlayer_RunCommand_Context` -> `RunCommand_Context`).
            let rest = parts[1..].join("_");
            // Only strip when the remainder reads as a real method name (starts
            // uppercase). Otherwise keep the full name so we don't reduce it to a
            // meaningless fragment (`CSGOInput_ptr` -> `ptr`).
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
            {
                return Cow::Owned(rest);
            }
        }
    }
    Cow::Borrowed(raw)
}

fn opt_proto(sig_name: &str, p: &str) -> Option<String> {
    if p.is_empty() {
        return None;
    }

    if sig_name == "CreateMove" {
        return Some("bool __fastcall CreateMove(void* pthis, int nSlot, float flInputSampleTime, bool bActive)".to_string());
    }

    let display = display_name(sig_name);
    let mut out = p.to_string();
    if let Some(start) = out.find("sub_") {
        let mut end = start + 4;
        while end < out.len() && out.as_bytes()[end].is_ascii_hexdigit() {
            end += 1;
        }
        out.replace_range(start..end, display.as_ref());
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Auto-tightened pattern synthesiser
// ---------------------------------------------------------------------------

const SYNTH_LENGTHS: [usize; 7] = [16, 20, 24, 28, 32, 40, 48];

fn synth_window(mc: &ModuleCache, rva: u64, len: usize) -> Option<&[u8]> {
    let lo = usize::try_from(rva).ok()?;
    let text_lo = mc.text_rva as usize;
    let text_hi = text_lo.saturating_add(mc.text_size as usize);
    if lo < text_lo || lo >= text_hi {
        return None;
    }
    let cap = text_hi.min(mc.image.len());
    let hi = lo.saturating_add(len).min(cap);
    if hi <= lo {
        return None;
    }
    mc.image.get(lo..hi).filter(|bytes| !bytes.is_empty())
}

/// Cache-path synth: reloc wildcards from the bytes at `rva`. Does not count
/// matches in `.text`, so a still-valid cached RVA is accepted even when the
/// prologue is duplicated.
fn synthesize_pattern_local(mc: &ModuleCache, rva: u64) -> Option<String> {
    let bytes = synth_window(mc, rva, SYNTH_LENGTHS[0])?;
    Some(format_ida(bytes, &relocatable_mask(bytes)))
}

/// Build the shortest unique-in-`.text` IDA pattern at `rva`, with `?`
/// wildcards on bytes that look like rel32 displacements (CALL/JMP near,
/// jcc near, RIP-relative LEA/MOV).  The result is deterministic and
/// safe to paste into IDA, x64dbg, ReClass.NET, etc. without any
/// post-processing.
///
/// Strategy:
///   1. read N bytes from `rva` (try 16, 24, 32, 40, 48 in order)
///   2. mark suspected rel32 displacements as wildcards
///   3. count matches of the masked pattern within the module's `.text`
///   4. accept the first length whose match count is exactly 1
///   5. if none unique, return the longest-attempted pattern as a
///      best-effort fallback (consumers can still tighten by hand)
fn synthesize_pattern(mc: &ModuleCache, rva: u64) -> Option<String> {
    let mut best = None;
    for &len in &SYNTH_LENGTHS {
        let Some(bytes) = synth_window(mc, rva, len) else {
            break;
        };
        let mask = relocatable_mask(bytes);
        let count = count_matches_capped(mc.text(), bytes, &mask, 2);
        // We always match ourselves once; require uniqueness.
        if count == 1 {
            return Some(format_ida(bytes, &mask));
        }
        best = Some(format_ida(bytes, &mask));
    }
    best
}

/// Mark bytes that are part of a rel32 displacement as wildcards.
/// Conservative: only handles instructions whose layout is well known,
/// leaves everything else as-is.  Over-matching is fine — a wildcard
/// just means "don't care", which only loosens the pattern.
fn relocatable_mask(bytes: &[u8]) -> Vec<u8> {
    let mut mask = vec![0xFF; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // E8 cd / E9 cd  — call / jmp near, rel32
        if (b == 0xE8 || b == 0xE9) && i + 5 <= bytes.len() {
            for j in 0..4 {
                mask[i + 1 + j] = 0;
            }
            i += 5;
            continue;
        }

        // 0F 8x cd  — jcc near, rel32
        if b == 0x0F && i + 6 <= bytes.len() && (bytes[i + 1] & 0xF0) == 0x80 {
            for j in 0..4 {
                mask[i + 2 + j] = 0;
            }
            i += 6;
            continue;
        }

        // REX.W (48..4F) + 8B/89/8D/03/0B/13/1B/23/2B/33/3B/85 + ModR/M
        // with mod=00 rm=101  (RIP-relative addressing)
        if (b & 0xF8) == 0x48 && i + 7 <= bytes.len() {
            let op2 = bytes[i + 1];
            let modrm = bytes[i + 2];
            let rip_rel_op = matches!(
                op2,
                0x03 | 0x0B | 0x13 | 0x1B | 0x23 | 0x2B | 0x33 | 0x3B | 0x85 | 0x89 | 0x8B | 0x8D
            );
            if rip_rel_op && (modrm & 0xC7) == 0x05 {
                for j in 0..4 {
                    mask[i + 3 + j] = 0;
                }
                i += 7;
                continue;
            }
        }

        // Plain MOV/LEA RIP-rel without REX prefix (32-bit dest).
        if (b == 0x8B || b == 0x89 || b == 0x8D) && i + 6 <= bytes.len() {
            let modrm = bytes[i + 1];
            if (modrm & 0xC7) == 0x05 {
                for j in 0..4 {
                    mask[i + 2 + j] = 0;
                }
                i += 6;
                continue;
            }
        }

        i += 1;
    }
    mask
}

/// Count matches of `(bytes, mask)` in `hay`, but stop early after
/// `cap` matches — we only need to distinguish "1" from ">=2".
fn count_matches_capped(hay: &[u8], bytes: &[u8], mask: &[u8], cap: usize) -> usize {
    if cap == 0 {
        return 0;
    }
    let mut count = 0usize;
    visit_pattern_matches(hay, bytes, mask, |_| {
        count += 1;
        count < cap
    });
    count
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

#[inline]
fn push_hex_nibble(s: &mut String, nibble: u8) {
    s.push(HEX_UPPER[(nibble & 0x0F) as usize] as char);
}

#[inline]
fn push_hex_byte(s: &mut String, b: u8) {
    push_hex_nibble(s, b >> 4);
    push_hex_nibble(s, b);
}

fn format_ida(bytes: &[u8], mask: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        match mask[i] {
            0 => s.push('?'),
            0xFF => push_hex_byte(&mut s, *b),
            0xF0 => {
                push_hex_nibble(&mut s, b >> 4);
                s.push('?');
            }
            0x0F => {
                s.push('?');
                push_hex_nibble(&mut s, b & 0x0F);
            }
            _ => push_hex_byte(&mut s, *b),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn temp_pattern_file(body: &str) -> std::path::PathBuf {
        // The clock on Windows is coarser than the gap between two tests
        // creating files, so a timestamp alone can hand two parallel tests the
        // same path; an atomic sequence cannot.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "cs2-dumper-pattern-test-{}-{}.json",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, body).expect("write pattern file");
        path
    }

    #[test]
    fn external_patterns_override_and_extend_builtins() {
        let builtins = [Pattern {
            name: "Existing",
            module: "client.dll",
            needle: "48 8B 01",
            resolve: ResolveKind::None,
            extra_off: 0,
            prototype: "",
        }];
        let path = temp_pattern_file(
            r#"{"patterns":[
                {"name":"Existing","module":"CLIENT.DLL","pattern":"48 8B 02"},
                {"name":"NewAnchor","module":"engine2.dll","pattern":"E8 ? ? ? ?","resolve":"rel32","rel_off":1}
            ]}"#,
        );
        let external = load_pattern_file(&path).expect("parse external patterns");
        let merged = merged_patterns(&builtins, external);
        std::fs::remove_file(path).expect("remove pattern file");

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].needle, "48 8B 02");
        assert!(matches!(
            merged[1].resolve,
            ResolveKind::Rel32 { rel_off: 1 }
        ));
    }

    #[test]
    fn external_pattern_file_rejects_duplicate_keys() {
        let path = temp_pattern_file(
            r#"[
                {"name":"Same","module":"client.dll","pattern":"48 8B 01"},
                {"name":"Same","module":"CLIENT.DLL","pattern":"48 8B 02"}
            ]"#,
        );
        let error = load_pattern_file(&path).expect_err("duplicate must fail");
        std::fs::remove_file(path).expect("remove pattern file");
        assert!(error.to_string().contains("duplicate external pattern"));
    }

    #[test]
    fn external_pattern_file_accepts_non_ida_string_references() {
        let path = temp_pattern_file(
            r#"[
                {"name":"ByText","module":"client.dll","pattern":"not an IDA pattern","resolve":"string_ref"}
            ]"#,
        );
        let patterns = load_pattern_file(&path).expect("string reference must load");
        std::fs::remove_file(path).expect("remove pattern file");

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].needle, "not an IDA pattern");
        assert_eq!(patterns[0].resolve, ResolveKind::StringRef);

        let path = temp_pattern_file(
            r#"[
                {"name":"Empty","module":"client.dll","pattern":"","resolve":"string_ref"}
            ]"#,
        );
        let error = load_pattern_file(&path).expect_err("empty string reference must fail");
        std::fs::remove_file(path).expect("remove pattern file");
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn pattern_requires_a_concrete_byte() {
        let error = parse_ida("? ?? ?").expect_err("all-wildcard pattern must fail");
        assert!(error.to_string().contains("concrete byte"));
    }

    #[test]
    fn ida_parser_supports_half_byte_wildcards() {
        let (bytes, mask) = parse_ida("4? ?A ??").expect("parse nibble wildcards");
        assert_eq!(bytes, vec![0x40, 0x0A, 0x00]);
        assert_eq!(mask, vec![0xF0, 0x0F, 0x00]);
        assert_eq!(
            find_all_pattern(&[0x4F, 0x1A, 0xCC, 0x40, 0x0A, 0xDD], &bytes, &mask),
            vec![0, 3]
        );
        assert_eq!(format_ida(&bytes, &mask), "4? ?A ?");
        let (lower, lower_mask) = parse_ida("ab CD").expect("mixed-case hex");
        assert_eq!(lower, vec![0xAB, 0xCD]);
        assert_eq!(lower_mask, vec![0xFF, 0xFF]);
    }

    #[test]
    fn exact_byte_search_counts_overlapping_matches() {
        assert_eq!(find_all_exact(b"aaaa", b"aa"), vec![0, 1, 2]);
        assert_eq!(find_all_exact(b"abc", b"z"), Vec::<usize>::new());
    }

    #[test]
    fn string_ref_resolves_rip_xref_and_function_start() {
        let mut image = vec![0u8; 64];
        image[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        image[4..11].copy_from_slice(&[0x48, 0x8D, 0x0D, 0, 0, 0, 0]);
        let target_rva = 32u32;
        let next_rva = 11u32;
        let disp = (target_rva as i64 - next_rva as i64) as i32;
        image[7..11].copy_from_slice(&disp.to_le_bytes());
        image[32..45].copy_from_slice(b"UniqueString\0");
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 16,
            rdata_rva: 32,
            rdata_size: 32,
        };
        let pattern = Pattern {
            name: "StringAnchoredFunction",
            module: "client.dll",
            needle: "UniqueString",
            resolve: ResolveKind::StringRef,
            extra_off: 0,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(4));
        assert_eq!(hit.rva, Some(0));
        assert_eq!(hit.matches, 1);
    }

    #[test]
    fn stale_pattern_gets_a_repair_suggestion_anchored_in_text() {
        // `.text` starts at RVA 0x1000, and the byte at pattern offset 9
        // drifted, exactly like a post-update signature break.
        let mut image = vec![0x90u8; 0x2000];
        let func = [
            0x48u8, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x8B, 0xF9,
        ];
        image[0x1100..0x1100 + func.len()].copy_from_slice(&func);
        let module = ModuleCache {
            name: "CLIENT.DLL".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0x1000,
            text_size: 0x1000,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "dwDriftedFunction",
            module: "client.dll",
            needle: "48 89 5C 24 08 57 48 83 EC 20 8B F9",
            resolve: ResolveKind::None,
            extra_off: 0,
            prototype: "",
        };

        assert!(!scan_pattern(&module, &pattern).found);

        let repair = repair_pattern(&module, &pattern).expect("repair suggestion");
        assert_eq!(repair.module, "client.dll");
        assert_eq!(repair.repaired, "48 89 5C 24 08 57 48 83 EC ? 8B F9");
        assert_eq!(repair.candidate_rva, 0x1100);
        assert_eq!(repair.candidate_va, module.base + 0x1100);
        assert_eq!(repair.mismatch_offsets, vec![9]);
        assert!(repair.unique);
        assert!(repair.similarity > 0.9);
        // Enough metadata to write the suggestion back into a --pattern-file.
        assert_eq!(repair.resolve, "raw");
        assert_eq!(repair.rel_off, None);
        assert!(!repair.applied);
    }

    #[test]
    fn auto_repair_recovers_the_offset_and_records_provenance() {
        let mut image = vec![0x90u8; 0x2000];
        // 40 53 48 83 EC 20 48 8B 05 <disp32> 8B C8 C3 — a riprel global load
        // whose register-encoding byte drifted from 0D to 05.
        let stub = [
            0x40u8, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8B,
            0xC8, 0xC3,
        ];
        let at = 0x1100usize;
        image[at..at + stub.len()].copy_from_slice(&stub);
        let disp = 0x400i32;
        image[at + 9..at + 13].copy_from_slice(&disp.to_le_bytes());
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0x1000,
            text_size: 0x1000,
            rdata_rva: 0,
            rdata_size: 0,
        };
        // The database still expects `48 8B 0D` (rcx) at that position.
        let pattern = Pattern {
            name: "dwStaleGlobal",
            module: "client.dll",
            needle: "40 53 48 83 EC 20 48 8B 0D ? ? ? ? 8B C8 C3",
            resolve: ResolveKind::RipRel { rel_off: 9 },
            extra_off: 0,
            prototype: "void*",
        };

        assert!(!scan_pattern(&module, &pattern).found);
        // Without --auto-repair the suggestion is reported but not used.
        let (suggestion, hit) = try_repair(&module, &pattern, false).expect("suggestion");
        assert!(!suggestion.applied);
        assert!(hit.is_none());
        assert_eq!(suggestion.resolve, "riprel");
        assert_eq!(suggestion.rel_off, Some(9));
        assert_eq!(suggestion.prototype.as_deref(), Some("void*"));
        assert_eq!(suggestion.mismatch_offsets, vec![8]);

        let (suggestion, hit) = try_repair(&module, &pattern, true).expect("applied repair");
        assert!(suggestion.applied);
        let hit = hit.expect("recovered hit");
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(0x1100));
        // 0x1100 + 9 + 4 (end of the instruction) + 0x400.
        assert_eq!(hit.rva, Some(0x150D));
        assert_eq!(
            hit.repaired_from.as_deref(),
            Some("40 53 48 83 EC 20 48 8B 0D ? ? ? ? 8B C8 C3")
        );
        assert_eq!(hit.pattern, suggestion.repaired);
    }

    #[test]
    fn repair_patch_file_is_loadable_and_skips_ambiguous_entries() {
        let unique = repair::PatternRepair {
            name: "dwUnique".into(),
            module: "client.dll".into(),
            original: "48 8B 0D ? ? ? ?".into(),
            repaired: "48 8B ? ? ? ? ?".into(),
            resolve: "riprel",
            rel_off: Some(3),
            extra_off: -0x10,
            prototype: Some("void*".into()),
            candidate_rva: 0x1000,
            candidate_va: 0x0001_8000_1000,
            constrained_bytes: 12,
            matched_bytes: 11,
            similarity: 0.9,
            mismatch_offsets: vec![2],
            repaired_matches: 1,
            unique: true,
            applied: false,
        };
        let ambiguous = repair::PatternRepair {
            name: "dwAmbiguous".into(),
            repaired_matches: 4,
            unique: false,
            ..unique.clone()
        };

        let patch = repair::render_pattern_file(&[unique, ambiguous]).expect("patch document");
        let path = std::env::temp_dir().join(format!(
            "cs2-dumper-repair-patch-{}.json",
            std::process::id()
        ));
        fs::write(&path, patch).expect("write patch");
        let loaded = load_pattern_file(&path).expect("patch is a valid --pattern-file");
        let _ = fs::remove_file(&path);

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "dwUnique");
        assert_eq!(loaded[0].needle, "48 8B ? ? ? ? ?");
        assert_eq!(loaded[0].resolve, ResolveKind::RipRel { rel_off: 3 });
        assert_eq!(loaded[0].extra_off, -0x10);
        assert_eq!(loaded[0].prototype, "void*");
    }

    #[test]
    fn repair_patch_file_is_empty_when_nothing_is_unique() {
        assert!(repair::render_pattern_file(&[]).is_none());
    }

    #[test]
    fn find_all_pattern_counts_overlapping_matches() {
        let (bytes, mask) = parse_ida("AA AA").expect("parse pattern");
        assert_eq!(
            find_all_pattern(&[0xAA, 0xAA, 0xAA], &bytes, &mask),
            vec![0, 1]
        );
        assert_eq!(
            find_ida(&[0xAA, 0xAA, 0xAA], "AA AA").expect("find_ida"),
            vec![0, 1]
        );
    }

    fn client_text_module(image: Vec<u8>) -> ModuleCache {
        let text_size = u32::try_from(image.len()).expect("test image fits u32");
        ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size,
            rdata_rva: 0,
            rdata_size: 0,
        }
    }

    fn raw_client_pattern(name: &'static str, needle: &'static str) -> Pattern {
        Pattern {
            name,
            module: "client.dll",
            needle,
            resolve: ResolveKind::None,
            extra_off: 0,
            prototype: "",
        }
    }

    fn cached_hit(pattern: &Pattern, match_rva: u64, matches: u32) -> CachedPatternHit {
        CachedPatternHit {
            name: pattern.name.to_string(),
            module: pattern.module.to_string(),
            pattern: pattern.needle.to_string(),
            found: true,
            match_rva: Some(match_rva),
            matches,
        }
    }

    /// 16-byte prologue with a CALL rel32 so synth must wildcard the displacement.
    const PLANTED_PREFIX16: [u8; 16] = [
        0x48, 0x83, 0xEC, 0x28, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x90,
        0x90,
    ];
    const PLANTED_UNIQUE4: [u8; 4] = [0x4C, 0x8B, 0xDC, 0x90];
    const PLANTED_SITE_A: usize = 32;
    const PLANTED_SITE_B: usize = 80;
    const PLANTED_NEEDLE: &str = "48 83 EC 28 E8";

    fn planted_unique_prologue_image() -> Vec<u8> {
        let mut image = vec![0xCCu8; 160];
        image[PLANTED_SITE_A..PLANTED_SITE_A + 16].copy_from_slice(&PLANTED_PREFIX16);
        image[PLANTED_SITE_A + 16..PLANTED_SITE_A + 20].copy_from_slice(&PLANTED_UNIQUE4);
        image[PLANTED_SITE_B..PLANTED_SITE_B + 16].copy_from_slice(&PLANTED_PREFIX16);
        image
    }

    #[test]
    fn uncached_scan_emits_unique_reloc_wildcarded_synth() {
        let module = client_text_module(planted_unique_prologue_image());
        let pattern = raw_client_pattern("PlantedPrologue", PLANTED_NEEDLE);
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(PLANTED_SITE_A as u64));

        let synth = hit
            .pattern_synth
            .as_deref()
            .expect("cold-path hit emits synth");
        assert!(
            synth.split_ascii_whitespace().any(|tok| tok.contains('?')),
            "rel32 displacement must be wildcarded: {synth}"
        );
        let tokens: Vec<&str> = synth.split_ascii_whitespace().collect();
        assert!(
            tokens.len() >= 20,
            "16-byte prefix is planted twice, unique length must grow: {synth}"
        );

        let text = module.text();
        assert_eq!(
            find_ida(text, synth).expect("shipped finder parses synth"),
            vec![PLANTED_SITE_A]
        );
        let short = tokens[..16].join(" ");
        assert_eq!(
            find_ida(text, &short).expect("shipped finder parses 16-byte prefix").len(),
            2,
            "the 16-byte prefix must stay ambiguous so uniqueness actually chose a longer synth"
        );
    }

    #[test]
    fn cached_rva_matches_uncached_scan_without_uniqueness() {
        let module = client_text_module(planted_unique_prologue_image());
        let pattern = raw_client_pattern("PlantedPrologue", PLANTED_NEEDLE);
        let (uncached, used_cold) = scan_one_cached(&module, &pattern, None);
        assert!(!used_cold);
        assert!(uncached.found);
        assert_eq!(uncached.match_rva, Some(PLANTED_SITE_A as u64));

        let cached = cached_hit(
            &pattern,
            uncached.match_rva.expect("uncached match RVA"),
            uncached.matches,
        );
        let (warm, used_cache) = scan_one_cached(&module, &pattern, Some(&cached));
        assert!(used_cache);
        assert!(warm.found);
        assert_eq!(warm.match_rva, uncached.match_rva);
        assert_eq!(warm.rva, uncached.rva);

        let synth = warm
            .pattern_synth
            .as_deref()
            .expect("cache-path hit emits local synth");
        assert!(
            synth.split_ascii_whitespace().any(|tok| tok.contains('?')),
            "cache-path synth must wildcard the planted CALL rel32: {synth}"
        );
        let hits = find_ida(module.text(), synth).expect("shipped finder parses cache synth");
        assert!(
            hits.contains(&PLANTED_SITE_A),
            "cache synth must match the cached RVA, got {hits:?}"
        );
    }

    #[test]
    fn cached_rva_is_accepted_when_prologue_is_not_unique_in_text() {
        let mut image = vec![0xCCu8; 192];
        let mut seq = [0x90u8; 48];
        seq[0] = 0x48;
        seq[1] = 0x83;
        seq[2] = 0xEC;
        seq[3] = 0x28;
        seq[4] = 0xE8;
        seq[5] = 0x11;
        seq[6] = 0x22;
        seq[7] = 0x33;
        seq[8] = 0x44;
        for (i, byte) in seq.iter_mut().enumerate().skip(9) {
            *byte = 0xA0 + (i as u8 % 13);
        }
        image[16..64].copy_from_slice(&seq);
        image[96..144].copy_from_slice(&seq);
        let module = client_text_module(image);
        let pattern = raw_client_pattern("DuplicatedPrologue", "48 83 EC 28");
        let uncached = scan_pattern(&module, &pattern);
        assert!(uncached.found);
        assert_eq!(uncached.match_rva, Some(16));
        assert!(uncached.matches >= 2);

        let cached = cached_hit(&pattern, 16, uncached.matches);
        let (warm, used_cache) = scan_one_cached(&module, &pattern, Some(&cached));
        assert!(used_cache, "duplicate prologue must not reject a still-valid cached RVA");
        assert_eq!(warm.match_rva, Some(16));
        let synth = warm
            .pattern_synth
            .as_deref()
            .expect("cache-path synth does not need a unique prologue");
        assert!(
            synth.split_ascii_whitespace().any(|tok| tok.contains('?')),
            "duplicated prologue still wildcards the planted CALL: {synth}"
        );
        let hits = find_ida(module.text(), synth).expect("shipped finder parses cache synth");
        assert!(hits.contains(&16), "cache synth must still match site A: {hits:?}");
        assert!(
            hits.len() >= 2,
            "local cache synth must not uniqueness-walk; duplicated prologue should match twice: {hits:?}"
        );
        let cache_tokens = synth.split_ascii_whitespace().count();
        assert_eq!(
            cache_tokens, 16,
            "cache synth is the local 16-byte window, not a uniqueness fallback: {synth}"
        );
    }

    #[test]
    fn drifted_cached_needle_misses_and_rescans() {
        let pattern = raw_client_pattern("PlantedPrologue", PLANTED_NEEDLE);
        let previous = PatternCache {
            hits: vec![cached_hit(&pattern, PLANTED_SITE_A as u64, 2)],
        };
        let index = PatternCacheIndex::from_cache(Some(&previous));
        assert!(
            index
                .get(pattern.module, pattern.name, "48 83 EC 28 E9")
                .is_none(),
            "a drifted needle string must not reuse the previous-run RVA"
        );

        let mut drifted = planted_unique_prologue_image();
        drifted[PLANTED_SITE_A] = 0x00;
        let module = client_text_module(drifted);
        let stale = cached_hit(&pattern, PLANTED_SITE_A as u64, 1);
        let (hit, used_cache) = scan_one_cached(&module, &pattern, Some(&stale));
        assert!(!used_cache);
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(PLANTED_SITE_B as u64));
    }

    #[test]
    fn scan_pattern_records_every_text_match() {
        let mut image = vec![0u8; 32];
        image[2..5].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        image[12..15].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 32,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "Example",
            module: "client.dll",
            needle: "AA BB CC",
            resolve: ResolveKind::None,
            extra_off: 0,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.matches, 2);
        assert_eq!(hit.match_rva, Some(2));
    }

    #[test]
    fn scan_pattern_prefers_a_resolvable_match() {
        let mut image = vec![0u8; 32];
        // First E8 target points before the image and must be rejected.
        image[2..7].copy_from_slice(&[0xE8, 0xFF, 0xFE, 0xFF, 0xFF]);
        // Second E8 target resolves to RVA 17, inside .text.
        image[12..17].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 32,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "CallTarget",
            module: "client.dll",
            needle: "E8 ? ? ? ?",
            resolve: ResolveKind::Rel32 { rel_off: 1 },
            extra_off: 0,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.matches, 2);
        assert_eq!(hit.match_rva, Some(12));
        assert_eq!(hit.rva, Some(17));
    }

    #[test]
    fn scan_pattern_falls_back_to_rdata_after_invalid_text_hit() {
        let mut image = vec![0u8; 64];
        // Invalid text candidate: target resolves outside the image.
        image[2..7].copy_from_slice(&[0xE8, 0xFF, 0xFE, 0xFF, 0xFF]);
        // Valid candidate lives in the rdata window.
        image[34..39].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 16,
            rdata_rva: 32,
            rdata_size: 16,
        };
        let pattern = Pattern {
            name: "RdataFallback",
            module: "client.dll",
            needle: "E8 ? ? ? ?",
            resolve: ResolveKind::Rel32 { rel_off: 1 },
            extra_off: 0,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(34));
        assert_eq!(hit.rva, Some(39));
    }

    #[test]
    fn raw_patterns_apply_extra_offset_to_rva_and_va() {
        let mut image = vec![0u8; 32];
        image[10..13].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 32,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "FunctionBodyAnchor",
            module: "client.dll",
            needle: "AA BB CC",
            resolve: ResolveKind::None,
            extra_off: -4,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.match_rva, Some(10));
        assert_eq!(hit.rva, Some(6));
        assert_eq!(hit.va, Some(module.base + 6));
    }

    #[test]
    fn raw_patterns_reject_extra_offset_outside_image() {
        let mut image = vec![0u8; 8];
        image[2..5].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 8,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "InvalidBodyAnchor",
            module: "client.dll",
            needle: "AA BB CC",
            resolve: ResolveKind::None,
            extra_off: -8,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(!hit.found);
        assert!(hit.error.as_deref().unwrap_or_default().contains("outside"));
    }

    #[test]
    fn raw_patterns_and_cached_hits_reject_targets_past_image_end() {
        let mut image = vec![0u8; 8];
        image[2..5].copy_from_slice(&[0xAA, 0xBB, 0xCC]);
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: image.into(),
            text_rva: 0,
            text_size: 8,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "PastImageEnd",
            module: "client.dll",
            needle: "AA BB CC",
            resolve: ResolveKind::None,
            extra_off: 8,
            prototype: "",
        };
        let cached = CachedPatternHit {
            name: pattern.name.to_string(),
            module: pattern.module.to_string(),
            pattern: pattern.needle.to_string(),
            found: true,
            match_rva: Some(2),
            matches: 1,
        };

        let hit = scan_pattern(&module, &pattern);
        assert!(!hit.found);
        assert!(hit.error.as_deref().unwrap_or_default().contains("outside"));
        assert!(validate_cached_hit(&module, &pattern, &cached).is_none());
    }

    #[test]
    fn pattern_results_normalize_external_module_case() {
        let module = ModuleCache {
            name: "CLIENT.DLL".into(),
            base: 0x0001_8000_0000,
            image: vec![0xAA, 0xBB, 0xCC].into(),
            text_rva: 0,
            text_size: 3,
            rdata_rva: 0,
            rdata_size: 0,
        };
        let pattern = Pattern {
            name: "CaseInsensitiveModule",
            module: "CLIENT.DLL",
            needle: "AA BB CC",
            resolve: ResolveKind::None,
            extra_off: 0,
            prototype: "",
        };
        let hit = scan_pattern(&module, &pattern);
        assert!(hit.found);
        assert_eq!(hit.module.as_ref(), "client.dll");
    }

    #[test]
    fn malformed_section_bounds_do_not_panic() {
        let module = ModuleCache {
            name: "client.dll".into(),
            base: 0x0001_8000_0000,
            image: vec![0u8; 8].into(),
            text_rva: 0x1000,
            text_size: u32::MAX,
            rdata_rva: 0x2000,
            rdata_size: u32::MAX,
        };
        assert!(module.text().is_empty());
        assert!(module.rdata().is_none());
    }

    #[test]
    fn display_name_borrows_offset_and_netvar_symbols() {
        let dw = "dwEntityList";
        let out = display_name(dw);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), dw.as_ptr()));
        assert_eq!(display_name("CCSPlayer_RunCommand_Context").as_ref(), "RunCommand_Context");
        assert_eq!(display_name("client.dll::CreateMove").as_ref(), "CreateMove");
    }

    #[test]
    fn builtin_pattern_interns_static_needle() {
        let pattern = Pattern {
            name: "dwEntityList",
            module: "client.dll",
            needle: "48 8B 0D ? ? ? ? 48 85 C9 74 04 8B 01",
            resolve: ResolveKind::RipRel { rel_off: 3 },
            extra_off: 0,
            prototype: "",
        };
        let needle = pattern.needle_cow();
        assert!(matches!(needle, Cow::Borrowed(_)));
        assert!(std::ptr::eq(needle.as_ref().as_ptr(), pattern.needle.as_ptr()));
        let name = pattern.display_name_cow();
        assert!(matches!(name, Cow::Borrowed(_)));
        assert!(std::ptr::eq(name.as_ref().as_ptr(), pattern.name.as_ptr()));
    }

    #[test]
    fn canonical_module_name_borrows_lowercase() {
        let module = "client.dll";
        let out = canonical_module_name(module);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), module.as_ptr()));
        assert_eq!(canonical_module_name("CLIENT.DLL").as_ref(), "client.dll");
        assert_eq!(canonical_module_name("  engine2.dll").as_ref(), "engine2.dll");
    }

    #[test]
    fn intern_cached_module_shares_canonical_arc() {
        let name: Arc<str> = Arc::from("client.dll");
        let interned = intern_cached_module(&name);
        assert!(Arc::ptr_eq(&name, &interned));
        let upper: Arc<str> = Arc::from("CLIENT.DLL");
        let lowered = intern_cached_module(&upper);
        assert_eq!(lowered.as_ref(), "client.dll");
        assert!(!Arc::ptr_eq(&upper, &lowered));
    }

    #[test]
    fn cache_index_matches_case_insensitive_name_and_exact_pattern() {
        let cache = PatternCache {
            hits: vec![CachedPatternHit {
                name: "dwEntityList".into(),
                module: "CLIENT.DLL".into(),
                pattern: "48 8B 0D".into(),
                found: true,
                match_rva: Some(0x10),
                matches: 1,
            }],
        };
        assert_eq!(
            cache_lookup_key("CLIENT.DLL", "DwEntityList"),
            "client.dll\0dwentitylist"
        );
        let index = PatternCacheIndex::from_cache(Some(&cache));
        assert!(index.get("client.dll", "DWENTITYLIST", "48 8B 0D").is_some());
        assert!(
            index.get("client.dll", "dwEntityList", "DE AD").is_none(),
            "a drifted needle must miss the cache and rescan"
        );
        assert!(index.get("engine2.dll", "dwEntityList", "48 8B 0D").is_none());
        assert!(PatternCacheIndex::from_cache(None)
            .get("client.dll", "dwEntityList", "48 8B 0D")
            .is_none());
    }
}
