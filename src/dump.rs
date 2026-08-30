//! Analyze a CS2 process and emit the a2x-compatible dump plus the C++ include-tree.

use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use log::info;
use memflow::prelude::v1::*;

use crate::analysis;
use crate::output::{self, ManifestExtra, Output};
use crate::patterns;
use crate::ui;

/// Signatures to scan. The default dump keeps the static 504-pattern DB by
/// reference; `--pattern-file` is the only path that materializes `PatternSpec`.
#[derive(Clone, Copy)]
pub enum PatternSet<'a> {
    Builtins(&'a [patterns::Pattern]),
    Specs(&'a [patterns::PatternSpec]),
}

impl PatternSet<'_> {
    pub fn len(self) -> usize {
        match self {
            Self::Builtins(sigs) => sigs.len(),
            Self::Specs(sigs) => sigs.len(),
        }
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

pub struct Config<'a> {
    pub output: &'a Path,
    pub file_types: &'a [String],
    pub patterns: PatternSet<'a>,
    pub pattern_cache: Option<&'a patterns::PatternCache>,
    pub external_pattern_count: usize,
    pub loadlib_schema_va: Option<u64>,
    pub used_load_lib: bool,
    pub backend: String,
    pub shade_bindings: Vec<String>,
    pub guess_structs: bool,
    /// Parsed `game/csgo/steam.inf` when dumping via LoadLibrary.
    pub steam_inf: Option<crate::loadlib::SteamInf>,
}

/// Languages the dump writes. CLI and `validate_file_types` share this so a
/// new format cannot be accepted in one place and omitted in the other.
pub const FILE_TYPES: &[&str] = &["cs", "hpp", "json", "rs", "zig"];

pub fn validate_file_types(file_types: &[String]) -> Result<()> {
    let invalid: Vec<&str> = file_types
        .iter()
        .map(String::as_str)
        .filter(|kind| !FILE_TYPES.contains(kind))
        .collect();
    if !invalid.is_empty() {
        anyhow::bail!(
            "unsupported file type(s): {}; supported types: {}",
            invalid.join(", "),
            FILE_TYPES.join(", ")
        );
    }

    let mut seen = std::collections::BTreeSet::new();
    let duplicates: Vec<&str> = file_types
        .iter()
        .map(String::as_str)
        .filter(|kind| !seen.insert(*kind))
        .collect();
    if !duplicates.is_empty() {
        anyhow::bail!("duplicate output file type(s): {}", duplicates.join(", "));
    }
    Ok(())
}

struct AnalyzedDump {
    result: analysis::AnalysisResult,
    pattern_report: Option<patterns::PatternReport>,
    anchors: LiveAnchors,
    build_number: Option<u32>,
    dynamic_offsets_added: usize,
    removed_invalid_offsets: usize,
}

pub fn run<P: Process + MemoryView>(process: &mut P, cfg: &Config<'_>) -> Result<()> {
    let now = Instant::now();
    fs::create_dir_all(cfg.output)
        .with_context(|| format!("failed to create output directory {}", cfg.output.display()))?;
    let _images = analysis::module_data::ImageSession::begin();
    let modules = analysis::module_data::cached_module_list(process)?;

    ui::kv("Backend", &cfg.backend);
    ui::kv("Output", cfg.output.display());
    ui::kv("Offsets", "enabled");
    ui::kv("Patterns", "enabled");

    let mut analyzed = analyze_process(process, cfg, &modules)?;
    write_dump(process, cfg, &mut analyzed)?;
    print_summary(cfg, &analyzed, now.elapsed());
    Ok(())
}

/// Process-bound analysis: schemas, offsets, patterns, live recoveries.
/// Does not write consumer artifacts besides the pattern cache files needed
/// by later include-tree emission.
fn analyze_process<P: Process + MemoryView>(
    process: &mut P,
    cfg: &Config<'_>,
    modules: &analysis::module_data::ModuleList,
) -> Result<AnalyzedDump> {
    ui::section("Offsets, interfaces, buttons, schemas");
    ui::sound(ui::Cue::Step);
    let mut result = analysis::analyze_all(process)?;
    let mut build_number = read_build_number(process, &result.offsets);
    let mut dynamic_offsets_added = 0usize;

    ui::section("Patterns");
    let pattern_report = scan_patterns(
        process,
        cfg,
        &mut result,
        &mut build_number,
        &mut dynamic_offsets_added,
    )?;

    recover_schema_and_buttons(
        process,
        cfg.loadlib_schema_va,
        pattern_report.as_ref(),
        &mut result,
    );
    let anchors = resolve_live_anchors(process, pattern_report.as_ref());
    recover_live_offsets(
        process,
        &mut result,
        &mut dynamic_offsets_added,
        anchors.entity_system,
    );
    let removed_invalid_offsets = sanitize_offset_map(&mut result.offsets, modules);
    if removed_invalid_offsets > 0 {
        log::warn!(
            "discarded {} canonical offset(s) outside their module image",
            removed_invalid_offsets
        );
    }
    Ok(AnalyzedDump {
        result,
        pattern_report,
        anchors,
        build_number,
        dynamic_offsets_added,
        removed_invalid_offsets,
    })
}

/// Writes every consumer artifact. Process-touching walks run first so file
/// emitters never share `&mut process` with rayon. Manifest is written even
/// when a later stage failed, then the first error is returned.
fn write_dump<P: Process + MemoryView>(
    process: &mut P,
    cfg: &Config<'_>,
    analyzed: &mut AnalyzedDump,
) -> Result<()> {
    if let Some(report) = analyzed.pattern_report.as_ref() {
        analysis::recover_names(&mut analyzed.result.vtables, &report.hits);
    }
    let netvars = output::netvars::extract(&analyzed.result.schemas);
    let fingerprints = module_fingerprints(process);

    let vtables_result = write_vtables(
        cfg.output,
        &analyzed.result,
        analyzed.pattern_report.as_ref(),
        process,
        analyzed.build_number,
    );
    if let Err(err) = &vtables_result {
        log::warn!("failed to write vtable outputs: {err}");
    }

    let runtime_outputs_result = write_runtime_reports(
        process,
        cfg.output,
        &analyzed.result,
        &analyzed.anchors,
        analyzed.build_number,
    );
    if let Err(err) = &runtime_outputs_result {
        log::warn!("failed to write runtime reports: {err}");
    }

    let output = Output::new(
        cfg.file_types,
        4,
        cfg.output,
        &analyzed.result,
        analyzed.build_number,
    )?;
    let missing_schema_modules =
        analysis::schema_flags::missing_schema_modules(&analyzed.result.schemas);

    // Merged offsets must use the sanitized, live-recovered map and land on
    // disk before include-tree copies `offsets_merged.hpp`.
    let merged_offsets_result = match analyzed.pattern_report.as_ref() {
        Some(report) => write_merged_offset_artifacts(cfg, report, &analyzed.result),
        None => Ok(()),
    };
    if let Err(err) = &merged_offsets_result {
        log::warn!("failed to write merged offsets: {err}");
    }

    let previous_interfaces = fs::read_to_string(cfg.output.join("interfaces.json")).ok();
    let ((dump_all_result, primary_extras_result), diffs_result) = rayon::join(
        || {
            rayon::join(
                || output.dump_all(),
                || {
                    write_primary_extras(
                        cfg,
                        &analyzed.result,
                        analyzed.pattern_report.as_ref(),
                        analyzed.build_number,
                    )
                },
            )
        },
        || {
            write_diffs_and_indexes(
                cfg.output,
                &analyzed.result,
                &netvars,
                analyzed.build_number,
                previous_interfaces.as_deref(),
            )
        },
    );
    if let Err(err) = &dump_all_result {
        log::warn!("failed to write dump-all outputs: {err}");
    }
    if let Err(err) = &primary_extras_result {
        log::warn!("failed to write primary extras: {err}");
    }
    if let Err(err) = &diffs_result {
        log::warn!("failed to write indexes or netvars: {err}");
    }

    output.dump_manifest(&ManifestExtra {
        backend: &cfg.backend,
        load_lib: cfg.used_load_lib,
        shade_bindings: &cfg.shade_bindings,
        module_fingerprints: fingerprints,
        missing_schema_modules,
        pattern_summary: analyzed.pattern_report.as_ref().map(|report| {
            serde_json::json!({
                "found": report.found,
                "total": report.total,
                "modules": report.modules.len(),
                "external_overrides": cfg.external_pattern_count,
                "dynamic_offsets_added": analyzed.dynamic_offsets_added,
                "canonical_offsets_removed": analyzed.removed_invalid_offsets,
                "cache_hits": report.cache_hits,
                "cache_misses": report.cache_misses,
            })
        }),
        steam_inf: cfg
            .steam_inf
            .as_ref()
            .and_then(|inf| serde_json::to_value(inf).ok()),
    })?;
    vtables_result?;
    runtime_outputs_result?;
    dump_all_result?;
    primary_extras_result?;
    diffs_result?;
    merged_offsets_result?;
    Ok(())
}

fn write_runtime_reports<P: Process + MemoryView>(
    process: &mut P,
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    anchors: &LiveAnchors,
    build_number: Option<u32>,
) -> Result<()> {
    write_runtime_walks(process, out_dir, result, anchors, build_number)?;
    write_protobufs(process, out_dir, build_number)
}

fn print_summary(cfg: &Config<'_>, analyzed: &AnalyzedDump, elapsed: std::time::Duration) {
    info!("analysis completed in {elapsed:.2?}");
    ui::section("Summary");
    ui::kv("Output dir", cfg.output.display());
    if let Some(bn) = analyzed.build_number {
        ui::kv("Build number", bn);
    }
    if let Some(inf) = cfg.steam_inf.as_ref() {
        if let Some(patch) = inf.patch_version.as_deref() {
            ui::kv("PatchVersion", patch);
        }
        if let Some(client) = inf.client_version {
            ui::kv("ClientVersion", client);
        }
    }
    if let Some(report) = analyzed.pattern_report.as_ref() {
        ui::kv(
            "Patterns",
            format_args!("{}/{}", report.found, report.total),
        );
    }
    ui::sound(ui::Cue::Success);
    ui::step("All stages completed.");
}

fn scan_patterns<P: Process + MemoryView>(
    process: &mut P,
    cfg: &Config<'_>,
    result: &mut analysis::AnalysisResult,
    build_number: &mut Option<u32>,
    dynamic_offsets_added: &mut usize,
) -> Result<Option<patterns::PatternReport>> {
    let options = patterns::ScanOptions { auto_repair: true };
    let scanned = match cfg.patterns {
        PatternSet::Builtins(sigs) => {
            patterns::scan_all_with_options(process, sigs, cfg.pattern_cache, options)
        }
        PatternSet::Specs(sigs) => {
            patterns::scan_all_with_options(process, sigs, cfg.pattern_cache, options)
        }
    };
    match scanned {
        Ok(report) => {
            let added = overlay_dynamic_offsets(&mut result.offsets, &report);
            *dynamic_offsets_added += added;
            if build_number.is_none() {
                *build_number = dynamic_build_number(process, &report);
            }
            if added > 0 {
                info!(
                    "added {} dynamically resolved offset(s) missing from canonical scanner",
                    added
                );
            }
            write_pattern_artifacts(cfg, &report)?;
            info!(
                "found {}/{} patterns across {} modules",
                report.found,
                report.total,
                report.modules.len()
            );
            Ok(Some(report))
        }
        Err(err) => {
            log::error!("pattern scan failed: {err}");
            Err(err)
        }
    }
}

fn write_pattern_artifacts(cfg: &Config<'_>, report: &patterns::PatternReport) -> Result<()> {
    let previous = fs::read_to_string(cfg.output.join("patterns.json")).ok();
    let patterns_json_ok = write_serialized(
        &cfg.output.join("patterns.json"),
        serde_json::to_string_pretty(report),
    );
    if let Some(previous) = previous {
        match output::pattern_diff::render_json(&previous, report) {
            Ok(diff) => {
                write_logged(&cfg.output.join("patterns.diff.json"), diff);
            }
            Err(err) => log::warn!("failed to compare pattern reports: {err}"),
        }
    }

    let repair_path = cfg.output.join("patterns.repair.json");
    let patch_path = cfg.output.join("patterns.repair.patch.json");
    let mut failed: Vec<String> = Vec::new();
    if !patterns_json_ok {
        failed.push("patterns.json".into());
    }

    if report.repairs.is_empty() {
        let _ = fs::remove_file(&repair_path);
        let _ = fs::remove_file(&patch_path);
    } else {
        if !write_serialized(&repair_path, serde_json::to_string_pretty(&report.repairs)) {
            failed.push("patterns.repair.json".into());
        } else {
            info!(
                "wrote patterns.repair.json ({} suggestion(s))",
                report.repairs.len()
            );
        }
        match patterns::repair::render_pattern_file(&report.repairs) {
            Some(patch) => {
                if write_logged(&patch_path, patch) {
                    info!(
                        "wrote patterns.repair.patch.json; re-run with --pattern-file {} to apply it",
                        patch_path.display()
                    );
                } else {
                    failed.push("patterns.repair.patch.json".into());
                }
            }
            None => {
                let _ = fs::remove_file(&patch_path);
            }
        }
    }

    let (hpp, md) = rayon::join(
        || patterns::writers::render_hpp(&report.hits),
        || patterns::writers::render_md(&report.hits),
    );

    for file_type in cfg.file_types {
        let rendered = match file_type.as_str() {
            "cs" => Some(patterns::writers::render_cs(&report.hits)),
            "rs" => Some(patterns::writers::render_rs(&report.hits)),
            "zig" => Some(patterns::writers::render_zig(&report.hits)),
            _ => None,
        };
        if let Some(body) = rendered {
            let mut path = cfg.output.join("patterns");
            path.set_extension(file_type);
            if !write_logged(&path, body) {
                failed.push(format!("patterns.{file_type}"));
            }
        }
    }
    if !write_logged(&cfg.output.join("patterns.md"), md) {
        failed.push("patterns.md".into());
    }

    if !write_logged(&cfg.output.join("patterns.hpp"), hpp) {
        failed.push("patterns.hpp".into());
    }

    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "failed to write required pattern artifacts: {}",
            failed.join(", ")
        )
    }
}

fn write_merged_offset_artifacts(
    cfg: &Config<'_>,
    report: &patterns::PatternReport,
    result: &analysis::AnalysisResult,
) -> Result<()> {
    let (merged_hpp, merged_json) = rayon::join(
        || {
            patterns::offsets_writer::render_offsets_hpp(
                &report.hits,
                &result.offsets,
                &result.interfaces,
            )
        },
        || {
            patterns::offsets_writer::render_offsets_json(
                &report.hits,
                &result.offsets,
                &result.interfaces,
            )
        },
    );
    let merged_hpp_ok = write_logged(&cfg.output.join("offsets_merged.hpp"), merged_hpp);
    let merged_json_ok = write_serialized(&cfg.output.join("offsets_merged.json"), merged_json);
    let failed = [
        ("offsets_merged.hpp", merged_hpp_ok),
        ("offsets_merged.json", merged_json_ok),
    ]
    .into_iter()
    .filter_map(|(path, ok)| (!ok).then_some(path))
    .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "failed to write required pattern artifacts: {}",
            failed.join(", ")
        )
    }
}

fn recover_schema_and_buttons<P: Process + MemoryView>(
    process: &mut P,
    loadlib_schema_va: Option<u64>,
    pattern_report: Option<&patterns::PatternReport>,
    result: &mut analysis::AnalysisResult,
) {
    let schema_candidates = [
        loadlib_schema_va,
        pattern_report.and_then(|report| resolved_pattern_va(report, "pSchemaSystem")),
    ];
    for schema_system_va in schema_candidates.into_iter().flatten() {
        match analysis::schemas_from_system_va(process, schema_system_va) {
            Ok(schemas) if !schemas.is_empty() => {
                let module_count = schemas.len();
                result.schemas = schemas;
                info!("using dynamically resolved pSchemaSystem ({module_count} modules)");
                break;
            }
            Ok(_) => log::warn!(
                "dynamic pSchemaSystem produced no schema scopes; retaining legacy result"
            ),
            Err(err) => log::warn!("dynamic pSchemaSystem failed; retaining legacy result: {err}"),
        }
    }

    if let Some(button_global_va) = pattern_report
        .and_then(|report| resolved_pattern_va(report, "pButtonList"))
        .or_else(|| {
            anchor_from_scan(
                "button list",
                analysis::find_button_list(process, "client.dll"),
            )
        })
    {
        match analysis::buttons_from_global(process, button_global_va) {
            Ok(buttons) if !buttons.is_empty() => {
                result.buttons = buttons;
                info!(
                    "using dynamically resolved button registry ({} buttons)",
                    result.buttons.len()
                );
            }
            Ok(_) => log::warn!("dynamic button registry was empty; retaining legacy buttons"),
            Err(err) => {
                log::warn!("dynamic button registry failed; retaining legacy buttons: {err}")
            }
        }
    }
}

struct LiveAnchors {
    entity_system: Option<u64>,
    cvar_registry: Option<u64>,
    event_manager: Option<u64>,
}

fn resolve_live_anchors<P: Process + MemoryView>(
    process: &mut P,
    pattern_report: Option<&patterns::PatternReport>,
) -> LiveAnchors {
    LiveAnchors {
        entity_system: pattern_va(pattern_report, "pEntitySystem").or_else(|| {
            anchor_from_scan(
                "entity system",
                analysis::entity_anchor::find_in_module(process, "client.dll"),
            )
        }),
        cvar_registry: pattern_va(pattern_report, "pCvarRegistry").or_else(|| {
            anchor_from_scan(
                "convar registry",
                analysis::convars::find_registry(process, "tier0.dll"),
            )
        }),
        event_manager: pattern_va(pattern_report, "pGameEventManager").or_else(|| {
            anchor_from_scan(
                "game event manager",
                analysis::gameevents::find_manager(process, "client.dll"),
            )
        }),
    }
}

fn recover_live_offsets<P: Process + MemoryView>(
    process: &mut P,
    result: &mut analysis::AnalysisResult,
    dynamic_offsets_added: &mut usize,
    entity_system_global: Option<u64>,
) {
    let recovered = analysis::dyn_offsets::recover(process, &result.schemas, entity_system_global);
    let mut added = 0usize;
    for item in recovered {
        if insert_missing_offset(
            &mut result.offsets,
            &item.module,
            item.symbol.clone(),
            item.rva,
        ) {
            info!(
                "recovered {} from live objects at {}+{:#X}",
                item.symbol, item.module, item.rva
            );
            added += 1;
        }
    }
    *dynamic_offsets_added += added;
}

fn write_diffs_and_indexes(
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    netvars: &[output::netvars::NetVar<'_>],
    build_number: Option<u32>,
    previous_interfaces: Option<&str>,
) -> Result<()> {
    if let Some(previous) = previous_interfaces {
        match output::interface_diff::render_json(previous, &result.interfaces) {
            Ok(diff) => {
                write_logged(&out_dir.join("interfaces.diff.json"), diff);
            }
            Err(err) => log::warn!("failed to compare interfaces: {err}"),
        }
    }

    let previous_schema_index = fs::read_to_string(out_dir.join("schema_index.json")).ok();
    let index = output::schema_index::render_json(&result.schemas)
        .map_err(|err| anyhow::anyhow!("failed to serialize schema_index.json: {err}"))?;
    write_required(&out_dir.join("schema_index.json"), &index)?;
    info!("wrote schema_index.json ({} modules)", result.schemas.len());
    if let Some(previous) = previous_schema_index {
        match output::schema_diff::render_json(&previous, &index) {
            Ok(diff) => {
                write_logged(&out_dir.join("schema_index.diff.json"), diff);
            }
            Err(err) => log::warn!("failed to compare schema indexes: {err}"),
        }
    }

    if netvars.is_empty() {
        return Ok(());
    }
    let dir = out_dir.join("netvars");
    fs::create_dir_all(&dir)?;
    let (json, hpp) = rayon::join(
        || output::netvars::render_json(netvars),
        || output::netvars::render_hpp(netvars, build_number),
    );
    write_serialized_required(&dir.join("netvars.json"), json)?;
    write_required(&dir.join("netvars.hpp"), hpp)?;
    info!("wrote netvar reports ({} fields)", netvars.len());
    Ok(())
}

fn iface_classes_from_vtables<'a>(
    result: &'a analysis::AnalysisResult,
) -> Vec<output::interface_classes::IfaceClass<'a>> {
    result
        .vtables
        .iter()
        .flat_map(|(module, ifaces)| {
            ifaces.iter().map(move |(iface_name, info)| {
                let methods = info
                    .methods
                    .iter()
                    .enumerate()
                    .map(|(index, method)| output::interface_classes::Method {
                        index,
                        name: method.name.as_deref(),
                    })
                    .collect();
                output::interface_classes::IfaceClass {
                    module: module.as_str(),
                    iface_name: iface_name.as_str(),
                    instance_rva: result
                        .interfaces
                        .iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(module))
                        .and_then(|(_, items)| {
                            items
                                .iter()
                                .find(|(name, _)| name.eq_ignore_ascii_case(iface_name))
                                .map(|(_, rva)| *rva)
                        }),
                    rtti_class: info.rtti_class.as_deref().map(std::borrow::Cow::Borrowed),
                    methods,
                    manual: false,
                }
            })
        })
        .collect()
}

fn write_vtables<'a, P: Process + MemoryView>(
    out_dir: &Path,
    result: &'a analysis::AnalysisResult,
    pattern_report: Option<&'a patterns::PatternReport>,
    process: &mut P,
    build_number: Option<u32>,
) -> Result<()> {
    let mut typed_classes: Vec<output::interface_classes::IfaceClass<'a>> = Vec::new();
    if !result.vtables.is_empty() {
        let count: usize = result.vtables.values().map(|m| m.len()).sum();
        let (json, (hpp, cs)) = rayon::join(
            || output::vtables::render_json(&result.vtables),
            || {
                rayon::join(
                    || output::vtables::render_hpp(&result.vtables, build_number),
                    || output::vtables::render_cs(&result.vtables, build_number),
                )
            },
        );
        let (write_results, collected) = rayon::join(
            || {
                let json_result = write_serialized_required(&out_dir.join("vtables.json"), json);
                let (hpp_result, cs_result) = rayon::join(
                    || write_required(&out_dir.join("vtables.hpp"), hpp),
                    || write_required(&out_dir.join("vtables.cs"), cs),
                );
                (json_result, hpp_result, cs_result)
            },
            || iface_classes_from_vtables(result),
        );
        write_results.0?;
        write_results.1?;
        write_results.2?;
        info!("wrote vtables.json ({count} interfaces)");
        typed_classes = collected;
    }
    if let Some(report) = pattern_report {
        typed_classes.extend(analysis::manual_iface::discover(process, report));
    }
    if !typed_classes.is_empty() {
        let dir = out_dir.join("interfaces");
        fs::create_dir_all(&dir)?;
        write_required(
            &dir.join("interfaces.hpp"),
            output::interface_classes::render_hpp(&result.interfaces, &typed_classes, build_number),
        )?;
        info!(
            "wrote interfaces/interfaces.hpp ({} classes)",
            typed_classes.len()
        );
    }
    Ok(())
}

fn write_runtime_walks<P: Process + MemoryView>(
    process: &mut P,
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    anchors: &LiveAnchors,
    build_number: Option<u32>,
) -> Result<()> {
    if let Some(global_va) = anchors.cvar_registry {
        match analysis::convars::walk(process, global_va) {
            Ok(dump) => {
                let dir = out_dir.join("convars");
                fs::create_dir_all(&dir)?;
                let (json, hpp) = rayon::join(
                    || output::convars::render_json(&dump, build_number),
                    || output::convars::render_hpp(&dump, build_number),
                );
                write_serialized_required(&dir.join("convars.json"), json)?;
                write_required(&dir.join("convars.hpp"), hpp)?;
                info!(
                    "wrote convars report ({} convars, {} commands)",
                    dump.convars.len(),
                    dump.commands.len()
                );
            }
            Err(err) => log::warn!("convar walk failed: {err}"),
        }
    }
    write_events_and_world(process, out_dir, result, anchors, build_number)
}

fn write_events_and_world<P: Process + MemoryView>(
    process: &mut P,
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    anchors: &LiveAnchors,
    build_number: Option<u32>,
) -> Result<()> {
    if let Some(global_va) = anchors.event_manager {
        match analysis::gameevents::walk(process, global_va) {
            Ok(events) => {
                let dir = out_dir.join("gameevents");
                fs::create_dir_all(&dir)?;
                write_serialized_required(
                    &dir.join("gameevents.json"),
                    output::gameevents::render_json(&events, build_number),
                )?;
                info!("wrote gameevents.json ({} events)", events.len());
            }
            Err(err) => log::warn!("gameevent walk failed: {err}"),
        }
    }
    write_world_snapshots(process, out_dir, result, anchors, build_number)
}

fn write_world_snapshots<P: Process + MemoryView>(
    process: &mut P,
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    anchors: &LiveAnchors,
    build_number: Option<u32>,
) -> Result<()> {
    let Some(global_va) = anchors.entity_system else {
        return Ok(());
    };
    match analysis::entities::walk(process, global_va, &result.schemas) {
        Ok(entities) => {
            let dir = out_dir.join("entities");
            fs::create_dir_all(&dir)?;
            write_serialized_required(
                &dir.join("entities.json"),
                output::entities::render_json(&entities, build_number),
            )?;
            info!("wrote entities.json ({} entities)", entities.len());
        }
        Err(err) => log::warn!("entity walk failed: {err}"),
    }
    write_weapon_snapshot(process, out_dir, result, global_va, build_number)
}

fn write_weapon_snapshot<P: MemoryView>(
    process: &mut P,
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    entity_system_va: u64,
    build_number: Option<u32>,
) -> Result<()> {
    match analysis::weapons::walk(process, entity_system_va, &result.schemas) {
        Ok(weapons) => {
            let dir = out_dir.join("weapons");
            fs::create_dir_all(&dir)?;
            write_serialized_required(
                &dir.join("weapons.json"),
                output::weapons::render_json(&weapons, build_number),
            )?;
            info!("wrote weapons.json ({} weapons)", weapons.len());
        }
        Err(err) => log::warn!("weapon walk failed: {err}"),
    }
    Ok(())
}

fn write_primary_extras(
    cfg: &Config<'_>,
    result: &analysis::AnalysisResult,
    pattern_report: Option<&patterns::PatternReport>,
    build_number: Option<u32>,
) -> Result<()> {
    let (flat_result, include_tree_result) = rayon::join(
        || -> Result<()> {
            write_required(
                &cfg.output.join("entity_system.hpp"),
                output::entity_system::render_hpp(build_number),
            )?;
            if cfg.guess_structs {
                write_required(
                    &cfg.output.join("structs.hpp"),
                    output::guessed_structs::render_hpp(&result.schemas, build_number),
                )?;
                ui::ok("guessed structs.hpp emitted");
            }
            Ok(())
        },
        || write_include_tree(cfg.output, result, pattern_report, build_number),
    );
    flat_result?;
    include_tree_result
}

fn write_include_tree(
    out_dir: &Path,
    result: &analysis::AnalysisResult,
    pattern_report: Option<&patterns::PatternReport>,
    build_number: Option<u32>,
) -> Result<()> {
    let csgo_input_rva = output::include_tree::live_csgo_input_rva(
        &result.offsets,
        pattern_report.and_then(|report| resolved_pattern_rva(report, "pCSGOInput")),
    );
    ui::section("Include tree");
    match output::include_tree::dump(out_dir, result, build_number, csgo_input_rva) {
        Ok(count) => {
            ui::ok(format_args!(
                "include-tree SDK emitted ({} schema modules)",
                count
            ));
            Ok(())
        }
        Err(err) => {
            ui::warn(format_args!("include tree failed: {err}"));
            match output::include_tree::write_empty_cs2_if_missing(out_dir, build_number) {
                Ok(()) => Err(err),
                Err(write_err) => anyhow::bail!(
                    "include tree failed: {err}; cs2.hpp fallback failed: {write_err}"
                ),
            }
        }
    }
}

fn write_protobufs<P: Process + MemoryView>(
    process: &mut P,
    out_dir: &Path,
    build_number: Option<u32>,
) -> Result<()> {
    match analysis::protobufs(process) {
        Ok(messages) if !messages.is_empty() => {
            let dir = out_dir.join("protobufs");
            fs::create_dir_all(&dir)?;
            let (json_result, hpp_result) = rayon::join(
                || {
                    write_serialized_required(
                        &dir.join("protobufs.json"),
                        output::protobufs::render_json(&messages),
                    )
                },
                || {
                    write_required(
                        &dir.join("protobufs.hpp"),
                        output::protobufs::render_hpp(&messages, build_number),
                    )
                },
            );
            json_result?;
            hpp_result?;
            let count: usize = messages.values().map(|items| items.len()).sum();
            info!("wrote protobuf reports ({count} messages)");
        }
        Ok(_) => info!("protobuf reflection tables not found"),
        Err(err) => log::warn!("protobuf scan failed: {err}"),
    }
    Ok(())
}

fn write_serialized_required(
    path: &Path,
    rendered: Result<String, impl std::fmt::Display>,
) -> Result<()> {
    let body =
        rendered.map_err(|err| anyhow::anyhow!("failed to serialize {}: {err}", path.display()))?;
    write_required(path, body)
}
fn write_required(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    crate::output::write_staged(path, contents)
        .map_err(|err| anyhow::anyhow!("failed to write {}: {err}", path.display()))
}

fn write_serialized(path: &Path, rendered: Result<String, impl std::fmt::Display>) -> bool {
    match rendered {
        Ok(body) => write_logged(path, body),
        Err(err) => {
            log::warn!("failed to serialize {}: {err}", path.display());
            false
        }
    }
}

fn write_logged(path: &Path, contents: impl AsRef<[u8]>) -> bool {
    match crate::output::write_staged(path, contents) {
        Ok(()) => true,
        Err(err) => {
            log::warn!("failed to write {}: {err}", path.display());
            false
        }
    }
}

fn pattern_va(report: Option<&patterns::PatternReport>, name: &str) -> Option<u64> {
    report.and_then(|report| resolved_pattern_va(report, name))
}

fn resolved_pattern_va(report: &patterns::PatternReport, name: &str) -> Option<u64> {
    report
        .hits
        .iter()
        .find(|hit| hit.found && hit.name.eq_ignore_ascii_case(name))
        .and_then(|hit| hit.va)
}

fn resolved_pattern_rva(report: &patterns::PatternReport, name: &str) -> Option<u64> {
    report
        .hits
        .iter()
        .find(|hit| hit.found && hit.name.eq_ignore_ascii_case(name))
        .and_then(|hit| hit.rva)
}

fn anchor_from_scan(name: &str, found: Option<u64>) -> Option<u64> {
    match found {
        Some(va) => info!("{name} recovered by data scan at {va:#X}"),
        None => log::debug!("{name} not found by pattern or data scan"),
    }
    found
}

fn insert_missing_offset(
    offsets: &mut analysis::OffsetMap,
    module: &str,
    symbol: String,
    rva: u32,
) -> bool {
    let existing_module = offsets
        .keys()
        .find(|key| key.eq_ignore_ascii_case(module))
        .cloned();
    if let Some(key) = existing_module {
        // The key was cloned from this map, but keep the merge path total in
        // case the map implementation changes or a caller mutates it between
        // the lookup and insertion.
        let Some(module_offsets) = offsets.get_mut(&key) else {
            return false;
        };
        if module_offsets
            .keys()
            .any(|present| present.eq_ignore_ascii_case(&symbol))
        {
            return false;
        }
        module_offsets.insert(symbol, rva);
        return true;
    }
    offsets
        .entry(module.to_string())
        .or_default()
        .insert(symbol, rva);
    true
}

fn overlay_dynamic_offsets(
    offsets: &mut analysis::OffsetMap,
    report: &patterns::PatternReport,
) -> usize {
    let mut added = 0usize;
    for hit in &report.hits {
        let Some(rva) = hit.rva.and_then(|value| u32::try_from(value).ok()) else {
            continue;
        };
        if !hit.found || !is_offset_symbol(&hit.name) {
            continue;
        }
        if insert_missing_offset(offsets, hit.module.as_ref(), hit.name.to_string(), rva) {
            added += 1;
        }
    }
    added
}

fn is_offset_symbol(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some('d' | 'D'), Some('w' | 'W'), Some(c)) if c.is_ascii_alphabetic()
    )
}

fn sanitize_offset_map<N: AsRef<str>>(
    offsets: &mut analysis::OffsetMap,
    modules: &[(N, u64, u64)],
) -> usize {
    let mut removed = 0usize;
    for (module, values) in offsets.iter_mut() {
        let Some((_, _, size)) = modules
            .iter()
            .find(|(name, _, _)| name.as_ref().eq_ignore_ascii_case(module))
        else {
            continue;
        };
        let before = values.len();
        values.retain(|_, rva| (*rva as u64) < *size);
        removed += before.saturating_sub(values.len());
    }
    removed
}

/// Engine `dwBuildNumber` is a small Source 2 compile stamp (typically 5 digits).
/// LoadLibrary images leave the global uninitialized (`0` / `u32::MAX`); Steam's
/// `ClientVersion` is a different, larger number and must not be substituted.
fn plausible_engine_build(value: u32) -> Option<u32> {
    (1000..=1_000_000).contains(&value).then_some(value)
}

/// First `(module, rva)` whose symbol matches `name` ignoring ASCII case.
fn named_offset_rva<'a>(offsets: &'a analysis::OffsetMap, name: &str) -> Option<(&'a str, u64)> {
    offsets.iter().find_map(|(module, map)| {
        map.iter()
            .find(|(symbol, _)| symbol.eq_ignore_ascii_case(name))
            .map(|(_, rva)| (module.as_str(), u64::from(*rva)))
    })
}

fn u32_at_module_rva<P: Process + MemoryView>(
    process: &mut P,
    module: &str,
    rva: u64,
) -> Option<u32> {
    let info = process.module_by_name(module).ok()?;
    let address = info.base.to_umem().checked_add(rva).map(Address::from)?;
    process.read::<u32>(address).data_part().ok()
}

fn read_build_number<P: Process + MemoryView>(
    process: &mut P,
    offsets: &analysis::OffsetMap,
) -> Option<u32> {
    let (module, rva) = named_offset_rva(offsets, "dwBuildNumber")?;
    u32_at_module_rva(process, module, rva).and_then(plausible_engine_build)
}

fn dynamic_build_number<P: Process + MemoryView>(
    process: &mut P,
    report: &patterns::PatternReport,
) -> Option<u32> {
    report
        .hits
        .iter()
        .filter(|hit| hit.found && hit.name.eq_ignore_ascii_case("dwBuildNumber"))
        .find_map(|hit| {
            u32_at_module_rva(process, hit.module.as_ref(), hit.rva?)
                .and_then(plausible_engine_build)
        })
}

fn hex16_lower(value: u64) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for shift in (0..16).rev() {
        out.push(HEX[((value >> (shift * 4)) & 0xF) as usize] as char);
    }
    out
}

fn fnv1a64_head_tail(head: &[u8], tail: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in head.iter().chain(tail.iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn module_fingerprints<P: Process + MemoryView>(process: &mut P) -> serde_json::Value {
    let mut modules = serde_json::Map::new();
    let Ok(list) = analysis::module_data::cached_module_list(process) else {
        return serde_json::Value::Object(modules);
    };
    for (name, base, size) in list.iter() {
        let Ok(size) = usize::try_from(*size) else {
            continue;
        };
        if name.is_empty() || size == 0 {
            continue;
        }
        let sample_len = size.min(4096);
        let hash = if let Some((_, image)) = analysis::module_data::cached_live(name) {
            let head_len = sample_len.min(image.len());
            let head = &image[..head_len];
            let tail: &[u8] = if image.len() > sample_len {
                &image[image.len() - sample_len..]
            } else {
                &[]
            };
            fnv1a64_head_tail(head, tail)
        } else {
            let Some(head) = process
                .read_raw(Address::from(*base), sample_len)
                .data_part()
                .ok()
            else {
                continue;
            };
            let tail = if size > sample_len {
                let Some(tail_base) = base.checked_add((size - sample_len) as u64) else {
                    continue;
                };
                process
                    .read_raw(Address::from(tail_base), sample_len)
                    .data_part()
                    .ok()
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            fnv1a64_head_tail(&head, &tail)
        };
        modules.insert(
            name.to_string(),
            serde_json::json!({
                "size": size,
                "sample_bytes": sample_len,
                "fnv1a64_head_tail": hex16_lower(hash),
            }),
        );
    }
    serde_json::Value::Object(modules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a64_head_tail_is_stable_and_covers_both_ends() {
        let head = [0x41u8; 8];
        let tail = [0x42u8; 8];
        assert_eq!(
            fnv1a64_head_tail(&head, &tail),
            fnv1a64_head_tail(&head, &tail)
        );
        assert_ne!(
            fnv1a64_head_tail(&head, &tail),
            fnv1a64_head_tail(&head, &[])
        );
        assert_ne!(
            fnv1a64_head_tail(&head, &tail),
            fnv1a64_head_tail(&tail, &head)
        );
    }

    #[test]
    fn hex16_lower_matches_zero_padded_hex() {
        assert_eq!(hex16_lower(0), "0000000000000000");
        assert_eq!(hex16_lower(0x1), "0000000000000001");
        assert_eq!(hex16_lower(0xdead_beef), "00000000deadbeef");
    }

    #[test]
    fn write_pattern_artifacts_emits_hpp_and_merged_offsets_from_inserted_hit() {
        let symbol = "dwTestPawn";
        let rva: u32 = 0x4A8;
        let report = patterns::PatternReport {
            total: 1,
            found: 1,
            modules: vec!["client.dll".into()],
            hits: vec![patterns::PatternHit {
                name: symbol.into(),
                module: "client.dll".into(),
                resolve: "raw",
                pattern: "48 8B 05".into(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(rva as u64),
                match_va: Some(rva as u64),
                rva: Some(rva as u64),
                va: Some(rva as u64),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };
        let result = analysis::AnalysisResult {
            buttons: Default::default(),
            interfaces: Default::default(),
            offsets: analysis::OffsetMap::from([(
                "client.dll".to_string(),
                std::collections::BTreeMap::from([(symbol.to_string(), rva)]),
            )]),
            schemas: Default::default(),
            vtables: Default::default(),
        };
        let out_dir = std::env::temp_dir().join(format!(
            "cs2-dumper-pattern-artifacts-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir).expect("temp output dir");
        let file_types = ["hpp".to_string(), "json".to_string()];
        let cfg = Config {
            output: &out_dir,
            file_types: &file_types,
            patterns: PatternSet::Specs(&[]),
            pattern_cache: None,
            external_pattern_count: 0,
            loadlib_schema_va: None,
            used_load_lib: false,
            backend: "test".into(),
            shade_bindings: Vec::new(),
            guess_structs: false,
            steam_inf: None,
        };
        write_pattern_artifacts(&cfg, &report).expect("shipped pattern-artifact writer");
        write_merged_offset_artifacts(&cfg, &report, &result)
            .expect("shipped merged-offset writer");

        let patterns_hpp = fs::read_to_string(out_dir.join("patterns.hpp")).expect("patterns.hpp");
        assert!(
            patterns_hpp.contains(symbol),
            "patterns.hpp missing {symbol}: {patterns_hpp}"
        );

        let merged =
            fs::read_to_string(out_dir.join("offsets_merged.hpp")).expect("offsets_merged.hpp");
        let cleaned = symbol.trim_start_matches("dw");
        assert!(
            merged.contains(cleaned),
            "offsets_merged.hpp missing {cleaned}: {merged}"
        );
        let rva_text = format!("{:#X}", rva);
        assert!(
            merged.contains(&rva_text),
            "offsets_merged.hpp missing {rva_text}: {merged}"
        );
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn write_pattern_artifacts_propagates_required_write_failures() {
        let out_dir = std::env::temp_dir().join(format!(
            "cs2-dumper-pattern-artifacts-fail-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(out_dir.join("patterns.json")).expect("occupy required output path");
        let file_types = Vec::new();
        let cfg = Config {
            output: &out_dir,
            file_types: &file_types,
            patterns: PatternSet::Specs(&[]),
            pattern_cache: None,
            external_pattern_count: 0,
            loadlib_schema_va: None,
            used_load_lib: false,
            backend: "test".into(),
            shade_bindings: Vec::new(),
            guess_structs: false,
            steam_inf: None,
        };

        let err = write_pattern_artifacts(&cfg, &patterns::PatternReport::default())
            .expect_err("required artifact write failure must be returned");
        assert!(
            err.to_string().contains("patterns.json"),
            "failure must name the missing artifact: {err}"
        );
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn write_pattern_artifacts_propagates_markdown_write_failures() {
        let out_dir =
            std::env::temp_dir().join(format!("cs2-dumper-pattern-md-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir).expect("temp output dir");
        fs::create_dir(out_dir.join("patterns.md")).expect("occupy markdown output path");
        let file_types = Vec::new();
        let cfg = Config {
            output: &out_dir,
            file_types: &file_types,
            patterns: PatternSet::Specs(&[]),
            pattern_cache: None,
            external_pattern_count: 0,
            loadlib_schema_va: None,
            used_load_lib: false,
            backend: "test".into(),
            shade_bindings: Vec::new(),
            guess_structs: false,
            steam_inf: None,
        };
        let err = write_pattern_artifacts(&cfg, &patterns::PatternReport::default())
            .expect_err("markdown write failure must be returned");
        assert!(
            err.to_string().contains("patterns.md"),
            "failure must name the markdown artifact: {err}"
        );
        let _ = fs::remove_dir_all(&out_dir);
    }
    #[test]
    fn write_pattern_artifacts_propagates_requested_language_write_failures() {
        let out_dir = std::env::temp_dir().join(format!(
            "cs2-dumper-pattern-lang-fail-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir).expect("temp output dir");
        fs::create_dir(out_dir.join("patterns.cs")).expect("occupy language output path");
        let file_types = vec!["cs".to_string(), "hpp".to_string()];
        let cfg = Config {
            output: &out_dir,
            file_types: &file_types,
            patterns: PatternSet::Specs(&[]),
            pattern_cache: None,
            external_pattern_count: 0,
            loadlib_schema_va: None,
            used_load_lib: false,
            backend: "test".into(),
            shade_bindings: Vec::new(),
            guess_structs: false,
            steam_inf: None,
        };
        let err = write_pattern_artifacts(&cfg, &patterns::PatternReport::default())
            .expect_err("requested language write failure must be returned");
        assert!(
            err.to_string().contains("patterns.cs"),
            "failure must name the language artifact: {err}"
        );
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn write_diffs_and_indexes_propagates_current_artifact_failures() {
        let result = analysis::AnalysisResult {
            buttons: Default::default(),
            interfaces: Default::default(),
            offsets: Default::default(),
            schemas: Default::default(),
            vtables: Default::default(),
        };
        let netvar = output::netvars::NetVar {
            class: "C_Test",
            field: "m_value",
            offset: 0x10,
            type_name: "int32",
        };
        for case in ["schema-index", "netvars"] {
            let out_dir = std::env::temp_dir().join(format!(
                "cs2-dumper-{case}-write-failure-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&out_dir);
            fs::create_dir_all(&out_dir).expect("temp output dir");
            let netvars = if case == "schema-index" {
                fs::create_dir(out_dir.join("schema_index.json"))
                    .expect("occupy schema-index path");
                &[][..]
            } else {
                fs::write(out_dir.join("netvars"), b"occupied")
                    .expect("occupy netvars directory path");
                std::slice::from_ref(&netvar)
            };
            write_diffs_and_indexes(&out_dir, &result, netvars, None, None)
                .expect_err("current artifact write failure must propagate");
            let _ = fs::remove_dir_all(&out_dir);
        }
    }

    #[test]
    fn overlay_and_live_rvas_outside_the_module_image_are_discarded() {
        let mut offsets = analysis::OffsetMap::from([(
            "client.dll".to_string(),
            std::collections::BTreeMap::from([("dwLocalPlayerPawn".to_string(), 0x10u32)]),
        )]);
        let report = patterns::PatternReport {
            total: 1,
            found: 1,
            modules: vec!["client.dll".into()],
            hits: vec![patterns::PatternHit {
                name: "dwGlowManager".into(),
                module: "client.dll".into(),
                resolve: "riprel",
                pattern: "48 8B 05".into(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(0x5000),
                match_va: Some(0x5000),
                rva: Some(0x5000),
                va: Some(0x5000),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };
        let added = overlay_dynamic_offsets(&mut offsets, &report);
        assert_eq!(added, 1);
        let removed = sanitize_offset_map(&mut offsets, &[("client.dll", 0u64, 0x1000u64)]);
        assert_eq!(removed, 1);
        assert_eq!(
            offsets
                .get("client.dll")
                .and_then(|m| m.get("dwLocalPlayerPawn"))
                .copied(),
            Some(0x10)
        );
        assert!(
            !offsets
                .get("client.dll")
                .is_some_and(|m| m.contains_key("dwGlowManager")),
            "RVA 0x5000 is past a 0x1000 image"
        );
    }

    #[test]
    fn write_serialized_does_not_emit_empty_json_on_error() {
        let path = std::env::temp_dir().join(format!("cs2-dumper-ser-fail-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let rendered: Result<String, &str> = Err("boom");
        assert!(!write_serialized(&path, rendered));
        assert!(
            !path.exists(),
            "serialize failure must not write a fake empty object"
        );
    }

    #[test]
    fn rejects_uninitialized_engine_build_sentinels() {
        assert_eq!(plausible_engine_build(0), None);
        assert_eq!(plausible_engine_build(1), None);
        assert_eq!(plausible_engine_build(u32::MAX), None);
        assert_eq!(plausible_engine_build(2000885), None);
        assert_eq!(plausible_engine_build(14152), Some(14152));
    }

    #[test]
    fn named_offset_rva_matches_build_number_case_insensitively() {
        let offsets = analysis::OffsetMap::from([(
            "engine2.dll".to_string(),
            std::collections::BTreeMap::from([("DWBUILDNUMBER".to_string(), 0xABCCu32)]),
        )]);
        assert_eq!(
            named_offset_rva(&offsets, "dwBuildNumber"),
            Some(("engine2.dll", 0xABCC))
        );
        assert_eq!(named_offset_rva(&offsets, "dwLocalPlayerPawn"), None);
    }

    #[test]
    fn write_required_names_the_path_when_the_write_fails() {
        let dir =
            std::env::temp_dir().join(format!("cs2-dumper-write-required-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("blocked.json");
        fs::create_dir(&path).expect("occupy output path as a directory");
        let err = write_required(&path, b"{}").expect_err("write into a directory must fail");
        assert!(
            err.to_string().contains("blocked.json"),
            "failure must name the path: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_unknown_output_file_types_before_attach() {
        let shipped: Vec<String> = FILE_TYPES.iter().map(|kind| (*kind).to_string()).collect();
        assert!(
            validate_file_types(&shipped).is_ok(),
            "CLI default types must be exactly the dump's supported set"
        );
        for kind in FILE_TYPES {
            assert!(
                validate_file_types(&[(*kind).to_string()]).is_ok(),
                "shipped type {kind} must validate"
            );
        }
        let error = validate_file_types(&["hpp".into(), "lua".into()])
            .expect_err("unknown output type must be rejected");
        assert!(error.to_string().contains("lua"));
        assert!(error.to_string().contains("cs"));

        let duplicate = validate_file_types(&["json".into(), "json".into()])
            .expect_err("duplicate output types must be rejected");
        assert!(duplicate.to_string().contains("duplicate"));
        assert!(duplicate.to_string().contains("json"));
    }

    #[test]
    fn dynamic_offsets_fill_only_missing_symbols() {
        let mut offsets = analysis::OffsetMap::from([(
            "client.dll".to_string(),
            std::collections::BTreeMap::from([("dwExisting".to_string(), 0x111)]),
        )]);
        let report = patterns::PatternReport {
            hits: vec![
                patterns::PatternHit {
                    name: "dwExisting".into(),
                    module: "client.dll".into(),
                    resolve: "raw",
                    pattern: "AA".into(),
                    prototype: None,
                    bytes: None,
                    pattern_synth: None,
                    repaired_from: None,
                    found: true,
                    match_rva: Some(1),
                    match_va: Some(1),
                    rva: Some(0x222),
                    va: Some(0x222),
                    matches: 1,
                    confidence: 1.0,
                    error: None,
                },
                patterns::PatternHit {
                    name: "dwAdded".into(),
                    module: "client.dll".into(),
                    resolve: "raw",
                    pattern: "BB".into(),
                    prototype: None,
                    bytes: None,
                    pattern_synth: None,
                    repaired_from: None,
                    found: true,
                    match_rva: Some(2),
                    match_va: Some(2),
                    rva: Some(0x333),
                    va: Some(0x333),
                    matches: 1,
                    confidence: 1.0,
                    error: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(overlay_dynamic_offsets(&mut offsets, &report), 1);
        assert_eq!(offsets["client.dll"]["dwExisting"], 0x111);
        assert_eq!(offsets["client.dll"]["dwAdded"], 0x333);
    }

    #[test]
    fn overlay_accepts_dw_prefix_regardless_of_ascii_case() {
        assert!(is_offset_symbol("dwEntityList"));
        assert!(is_offset_symbol("DwEntityList"));
        assert!(is_offset_symbol("DWENTITYLIST"));
        assert!(!is_offset_symbol("pEntityList"));
        assert!(!is_offset_symbol("dw"));
        let mut offsets = analysis::OffsetMap::new();
        let report = patterns::PatternReport {
            hits: vec![patterns::PatternHit {
                name: "DwEntityList".into(),
                module: "client.dll".into(),
                resolve: "raw",
                pattern: "AA".into(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(1),
                match_va: Some(1),
                rva: Some(0xABC),
                va: Some(0xABC),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };
        assert_eq!(overlay_dynamic_offsets(&mut offsets, &report), 1);
        assert_eq!(offsets["client.dll"]["DwEntityList"], 0xABC);
    }

    #[test]
    fn resolved_pattern_rva_does_not_use_the_absolute_va() {
        let report = patterns::PatternReport {
            hits: vec![patterns::PatternHit {
                name: "pCSGOInput".into(),
                module: "client.dll".into(),
                resolve: "riprel",
                pattern: "48 8B 0D".into(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(0x111),
                match_va: Some(0x7FF6_0000_0111),
                rva: Some(0x222),
                va: Some(0x7FF6_0000_0222),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };
        assert_eq!(resolved_pattern_rva(&report, "pCSGOInput"), Some(0x222));
        assert_eq!(
            resolved_pattern_va(&report, "pCSGOInput"),
            Some(0x7FF6_0000_0222)
        );
        assert_eq!(
            output::include_tree::live_csgo_input_rva(&analysis::OffsetMap::new(), Some(0x222)),
            Some(0x222)
        );
        assert_eq!(
            output::include_tree::live_csgo_input_rva(
                &analysis::OffsetMap::new(),
                Some(0x7FF6_0000_0222)
            ),
            None,
            "a 64-bit module VA must not be truncated into an RVA"
        );
    }

    #[test]
    fn overlay_fills_existing_module_when_hit_module_case_differs() {
        let mut offsets = analysis::OffsetMap::from([(
            "CLIENT.DLL".to_string(),
            std::collections::BTreeMap::from([("dwExisting".to_string(), 0x111)]),
        )]);
        let report = patterns::PatternReport {
            hits: vec![
                patterns::PatternHit {
                    name: "dwExisting".into(),
                    module: "client.dll".into(),
                    resolve: "raw",
                    pattern: "AA".into(),
                    prototype: None,
                    bytes: None,
                    pattern_synth: None,
                    repaired_from: None,
                    found: true,
                    match_rva: Some(1),
                    match_va: Some(1),
                    rva: Some(0x222),
                    va: Some(0x222),
                    matches: 1,
                    confidence: 1.0,
                    error: None,
                },
                patterns::PatternHit {
                    name: "dwAdded".into(),
                    module: "client.dll".into(),
                    resolve: "raw",
                    pattern: "BB".into(),
                    prototype: None,
                    bytes: None,
                    pattern_synth: None,
                    repaired_from: None,
                    found: true,
                    match_rva: Some(2),
                    match_va: Some(2),
                    rva: Some(0x333),
                    va: Some(0x333),
                    matches: 1,
                    confidence: 1.0,
                    error: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(overlay_dynamic_offsets(&mut offsets, &report), 1);
        assert_eq!(offsets.len(), 1, "mixed-case module must not fork the map");
        assert_eq!(offsets["CLIENT.DLL"]["dwExisting"], 0x111);
        assert_eq!(offsets["CLIENT.DLL"]["dwAdded"], 0x333);
        assert!(!offsets.contains_key("client.dll"));
    }

    #[test]
    fn offset_symbol_filter_excludes_non_offsets() {
        assert!(is_offset_symbol("dwEntityList"));
        assert!(!is_offset_symbol("pEntitySystem"));
        assert!(!is_offset_symbol("dw_lowercase"));
    }

    #[test]
    fn sanitizes_only_out_of_image_offsets() {
        let mut offsets = analysis::OffsetMap::from([(
            "client.dll".to_string(),
            std::collections::BTreeMap::from([
                ("dwValid".to_string(), 0x100),
                ("dwInvalid".to_string(), 0x1000),
            ]),
        )]);
        let sizes = [("client.dll", 0u64, 0x800u64)];
        assert_eq!(sanitize_offset_map(&mut offsets, &sizes), 1);
        assert!(offsets["client.dll"].contains_key("dwValid"));
        assert!(!offsets["client.dll"].contains_key("dwInvalid"));
    }

    #[test]
    fn sanitizes_offsets_when_module_name_case_differs() {
        let mut offsets = analysis::OffsetMap::from([(
            "CLIENT.DLL".to_string(),
            std::collections::BTreeMap::from([
                ("dwValid".to_string(), 0x100),
                ("dwInvalid".to_string(), 0x1000),
            ]),
        )]);
        let sizes = [("client.dll", 0u64, 0x800u64)];
        assert_eq!(sanitize_offset_map(&mut offsets, &sizes), 1);
        assert!(offsets["CLIENT.DLL"].contains_key("dwValid"));
        assert!(!offsets["CLIENT.DLL"].contains_key("dwInvalid"));
    }

    #[test]
    fn resolves_external_pattern_anchor_case_insensitively() {
        let report = patterns::PatternReport {
            hits: vec![patterns::PatternHit {
                name: "pentitysystem".into(),
                module: "client.dll".into(),
                resolve: "riprel",
                pattern: "48 8B ?".into(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(0x100),
                match_va: Some(0x0001_8000_0100),
                rva: Some(0x100),
                va: Some(0x0001_8000_0100),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };
        assert_eq!(
            resolved_pattern_va(&report, "pEntitySystem"),
            Some(0x0001_8000_0100)
        );
    }

    #[test]
    fn default_pattern_set_keeps_static_builtins() {
        let builtins = crate::patterns::database::CS2_PATTERNS;
        let set = PatternSet::Builtins(builtins);
        assert_eq!(set.len(), builtins.len());
        assert!(!set.is_empty());
    }

    #[test]
    fn print_summary_is_the_final_dump_stage_and_needs_no_process() {
        crate::ui::init(true);
        let analyzed = AnalyzedDump {
            result: analysis::AnalysisResult {
                buttons: Default::default(),
                interfaces: Default::default(),
                offsets: Default::default(),
                schemas: Default::default(),
                vtables: Default::default(),
            },
            pattern_report: None,
            anchors: LiveAnchors {
                entity_system: None,
                cvar_registry: None,
                event_manager: None,
            },
            build_number: Some(14152),
            dynamic_offsets_added: 0,
            removed_invalid_offsets: 0,
        };
        let file_types = ["json".to_string()];
        let output = std::env::temp_dir();
        let cfg = Config {
            output: &output,
            file_types: &file_types,
            patterns: PatternSet::Specs(&[]),
            pattern_cache: None,
            external_pattern_count: 0,
            loadlib_schema_va: None,
            used_load_lib: false,
            backend: "test".into(),
            shade_bindings: Vec::new(),
            guess_structs: false,
            steam_inf: None,
        };
        print_summary(&cfg, &analyzed, std::time::Duration::from_millis(1));
    }
}
