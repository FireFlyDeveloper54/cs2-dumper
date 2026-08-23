#![allow(dead_code)]

use std::fs::{self, File};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use clap::{ArgAction, Parser};

use log::{LevelFilter, info};

use memflow::prelude::v1::*;

use simplelog::*;

use output::Output;

mod analysis;
mod loadlib;
mod memory;
mod output;
mod patterns;
mod source2;
mod ui;

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "CS2 dumper — attaches to cs2.exe, or LoadLibrary-dumps from the Steam install if the game is not running"
)]
struct Args {
    /// Memory backend. Default: native attach.
    /// `syscall` — NtReadVirtualMemory stub (live cs2.exe, Windows).
    /// `shade` — inject payload into live cs2.exe, call InstallSchemaBindings, then dump.
    /// memflow plugins: `pcileech`, `kvm`, `winio`.
    #[arg(short, long)]
    connector: Option<String>,

    #[arg(short = 'a', long, hide = true)]
    connector_args: Option<String>,

    /// Output directory.
    #[arg(short, long, default_value = "output")]
    output: PathBuf,

    /// Increase logging verbosity.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[arg(long, hide = true, value_name = "FILE")]
    pattern_file: Option<PathBuf>,

    /// Emit packed C++ structs that guess unknown type sizes from field gaps.
    /// Offsets are padded explicitly; unknown sizeof values can still be wrong.
    #[arg(long)]
    guess_structs: bool,
}

fn validate_file_types(file_types: &[String]) -> Result<()> {
    const SUPPORTED: &[&str] = &["cs", "hpp", "json", "rs", "zig"];
    let invalid: Vec<&str> = file_types
        .iter()
        .map(String::as_str)
        .filter(|kind| !SUPPORTED.contains(kind))
        .collect();
    if invalid.is_empty() {
        Ok(())
    } else {
        bail!(
            "unsupported file type(s): {}; supported types: {}",
            invalid.join(", "),
            SUPPORTED.join(", ")
        )
    }
}

fn resolved_pattern_va(report: &patterns::PatternReport, name: &str) -> Option<u64> {
    report
        .hits
        .iter()
        .find(|hit| hit.found && hit.name.eq_ignore_ascii_case(name))
        .and_then(|hit| hit.va)
}

/// Report which route resolved an anchor a signature failed to find, and pass
/// the result through. A pattern names the *code* that touches a global, so a
/// recompile can invalidate it; the data scans recognise the object instead, and
/// the log line says so because the two routes have very different failure
/// modes when a section later looks wrong.
fn anchor_from_scan(name: &str, found: Option<u64>) -> Option<u64> {
    match found {
        Some(va) => info!("{name} recovered by data scan at {va:#X}"),
        None => log::debug!("{name} not found by pattern or data scan"),
    }
    found
}

/// Add dynamically resolved offset symbols to the legacy map without
/// overwriting canonical scanner results. This keeps existing output stable
/// while allowing an external/bundled signature to repair a missing symbol
/// after a game update.
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
        let module = offsets.entry(hit.module.clone()).or_default();
        if module.contains_key(&hit.name) {
            continue;
        }
        module.insert(hit.name.clone(), rva);
        added += 1;
    }
    added
}

fn is_offset_symbol(name: &str) -> bool {
    let mut chars = name.chars();
    matches!((chars.next(), chars.next()), (Some('d'), Some('w')))
        && chars.next().is_some_and(|c| c.is_ascii_uppercase())
}

fn sanitize_offset_map(
    offsets: &mut analysis::OffsetMap,
    module_sizes: &std::collections::BTreeMap<String, u64>,
) -> usize {
    let mut removed = 0usize;
    for (module, values) in offsets.iter_mut() {
        let Some(&size) = module_sizes.get(module) else {
            continue;
        };
        let before = values.len();
        values.retain(|_, rva| (*rva as u64) < size);
        removed += before.saturating_sub(values.len());
    }
    removed
}

fn dynamic_build_number<P: Process + MemoryView>(
    process: &mut P,
    report: &patterns::PatternReport,
) -> Option<u32> {
    report
        .hits
        .iter()
        .filter(|hit| hit.found && hit.name.eq_ignore_ascii_case("dwBuildNumber"))
        .filter_map(|hit| {
            let rva = hit.rva?;
            let module = process.module_by_name(&hit.module).ok()?;
            process.read::<u32>(module.base + rva).data_part().ok()
        })
        .find(|build| (1000..=1_000_000).contains(build))
}
fn module_fingerprints<P: Process + MemoryView>(process: &mut P) -> serde_json::Value {
    let mut modules = serde_json::Map::new();
    let Ok(list) = process.module_list() else {
        return serde_json::Value::Object(modules);
    };
    for module in list {
        let name = module.name.to_string().to_ascii_lowercase();
        let size = module.size as usize;
        if name.is_empty() || size == 0 {
            continue;
        }
        let sample_len = size.min(4096);
        let head = process.read_raw(module.base, sample_len).data_part().ok();
        let tail = if size > sample_len {
            process
                .read_raw(module.base + (size - sample_len), sample_len)
                .data_part()
                .ok()
        } else {
            None
        };
        let Some(head) = head else { continue };
        let mut hash = 0xcbf29ce484222325u64;
        for byte in head.iter().chain(tail.as_deref().unwrap_or(&[]).iter()) {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        modules.insert(
            name,
            serde_json::json!({
                "size": size,
                "sample_bytes": sample_len,
                "fnv1a64_head_tail": format!("{:016x}", hash),
            }),
        );
    }
    serde_json::Value::Object(modules)
}
const FILE_TYPES: [&str; 5] = ["cs", "hpp", "json", "rs", "zig"];

fn main() -> Result<()> {
    let args = Args::parse();
    let file_types: Vec<String> = FILE_TYPES.iter().map(|s| (*s).to_string()).collect();
    ui::init(false);
    ui::banner();
    ui::sound(ui::Cue::Start);
    validate_file_types(&file_types)?;

    let level_filter = match args.verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![TermLogger::new(
        level_filter,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )];

    loggers.push(WriteLogger::new(
        LevelFilter::Info,
        Config::default(),
        File::create("cs2-dumper.log")?,
    ));

    CombinedLogger::init(loggers)?;

    // Pattern updates are data, not offsets: users can replace a stale
    // signature after a game update while every RVA/VA is still resolved from
    // the currently running CS2 process.
    let external = match args.pattern_file.as_deref() {
        Some(path) => patterns::load_pattern_file(path)?,
        None => Vec::new(),
    };
    let external_pattern_count = external.len();
    let pattern_specs =
        patterns::merged_patterns(patterns::database::CS2_PATTERNS, external);
    let pattern_cache_path = {
        let path = args.output.join("patterns.json");
        path.is_file().then_some(path)
    };
    let pattern_cache = pattern_cache_path.as_deref().and_then(|path| {
        match fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str::<patterns::PatternCache>(&raw).ok())
        {
            Some(cache) => Some(cache),
            None => {
                log::warn!("unable to load pattern cache {}", path.display());
                None
            }
        }
    });
    if external_pattern_count > 0 {
        info!(
            "loaded {} external pattern override(s); scanning {} total signatures",
            external_pattern_count,
            pattern_specs.len()
        );
    }

    if memory::syscall::is_syscall_connector(args.connector.as_deref()) {
        #[cfg(not(windows))]
        {
            bail!("-c syscall is Windows-only");
        }
        #[cfg(windows)]
        {
            ui::section("Target");
            ui::kv("Backend", "syscall");
            let mut process = memory::syscall::attach("cs2.exe")?;
            ui::ok(&format!(
                "cs2.exe via NtReadVirtualMemory (pid {})",
                process.info().pid
            ));
            return run_dump(
                &mut process,
                &args,
                &file_types,
                &pattern_specs,
                pattern_cache.as_ref(),
                external_pattern_count,
                None,
                false,
                "syscall",
                &[],
            );
        }
    }

    let mut shade_bindings: Vec<String> = Vec::new();
    if memory::shade::is_shade_connector(args.connector.as_deref()) {
        #[cfg(not(windows))]
        {
            bail!("-c shade is Windows-only");
        }
        #[cfg(windows)]
        {
            ui::section("Target");
            ui::kv("Backend", "shade");
            let report = memory::shade::inject_schema_bindings()?;
            ui::ok(&format!(
                "injected InstallSchemaBindings ({} modules, SchemaSystem {:#X})",
                report.bindings.len(),
                report.schema_system
            ));
            for name in &report.bindings {
                log::info!("shade registered {name}");
            }
            for (name, err) in &report.failed {
                ui::warn(&format!("{name}: {err}"));
            }
            shade_bindings = report.bindings;
        }
    }

    let conn_args = args
        .connector_args
        .as_deref()
        .map(ConnectorArgs::from_str)
        .transpose()
        .map_err(|err| anyhow::anyhow!("unable to parse connector arguments: {err}"))?
        .unwrap_or_default();

    let shade_mode = memory::shade::is_shade_connector(args.connector.as_deref());
    let mut os = match args.connector.as_deref() {
        Some(_) if shade_mode => {
            #[cfg(windows)]
            {
                memflow_native::create_os(&OsArgs::default(), LibArc::default())?
            }
            #[cfg(not(windows))]
            {
                bail!("-c shade is Windows-only")
            }
        }
        Some(conn) => {
            let mut inventory = Inventory::scan();

            inventory
                .builder()
                .connector(conn)
                .args(conn_args)
                .os("win32")
                .build()?
        }
        None => {
            #[cfg(windows)]
            {
                memflow_native::create_os(&OsArgs::default(), LibArc::default())?
            }
            #[cfg(not(windows))]
            {
                bail!("no connector specified; pass --connector on this platform")
            }
        }
    };

    ui::section("Target");
    let live_pid = os
        .process_by_name("cs2.exe")
        .ok()
        .map(|process| process.info().pid);
    if !shade_mode && live_pid.is_none() {
        ui::warn("cs2.exe not running — searching Steam install");
        let game_dir = loadlib::find_install()?;
        ui::ok(&format!("install {}", game_dir.display()));
        ui::section("LoadLibrary");
        ui::sound(ui::Cue::Step);
        let report = loadlib::load(&game_dir)?;
        ui::ok(&format!(
            "loaded {} modules, {} schema bindings",
            report.loaded.len(),
            report.bindings.len()
        ));
        for (name, err) in &report.failed {
            ui::warn(&format!("{name}: {err}"));
        }
        #[cfg(not(windows))]
        {
            bail!("LoadLibrary dump is Windows-only");
        }
        #[cfg(windows)]
        {
            // Do not ask memflow to find this exe by name: CS2 DLLs just
            // loaded into us can make process_by_name fail ("process not
            // found") which looks like a crash if the window closes.
            let mut process = memory::local::attach_self()?;
            ui::ok(&format!("self pid {}", process.info().pid));
            return run_dump(
                &mut process,
                &args,
                &file_types,
                &pattern_specs,
                pattern_cache.as_ref(),
                external_pattern_count,
                report.schema_system,
                true,
                "loadlib",
                &[],
            );
        }
    }
    let mut process = if shade_mode {
        os.process_by_name("cs2.exe")
            .context("cs2.exe disappeared after shade inject")?
    } else {
        let pid = live_pid.context("cs2.exe disappeared after detection")?;
        ui::ok(&format!("cs2.exe running (pid {pid})"));
        os.process_by_name("cs2.exe")
            .context("cs2.exe disappeared after detection")?
    };

    let backend = if shade_mode {
        "shade"
    } else {
        args.connector.as_deref().unwrap_or("native")
    };
    run_dump(
        &mut process,
        &args,
        &file_types,
        &pattern_specs,
        pattern_cache.as_ref(),
        external_pattern_count,
        None,
        false,
        backend,
        &shade_bindings,
    )
}

fn run_dump<P: Process + MemoryView>(
    process: &mut P,
    args: &Args,
    file_types: &[String],
    pattern_specs: &[patterns::PatternSpec],
    pattern_cache: Option<&patterns::PatternCache>,
    external_pattern_count: usize,
    loadlib_schema_va: Option<u64>,
    used_load_lib: bool,
    backend: &str,
    shade_bindings: &[String],
) -> Result<()> {
    let now = Instant::now();

    ui::kv("Backend", backend);
    ui::kv("Output", &args.output.display().to_string());
    ui::kv("Offsets", "enabled");
    ui::kv("Patterns", "enabled");

    ui::section("Offsets, interfaces, buttons, schemas");
    ui::sound(ui::Cue::Step);
    let mut result = analysis::analyze_all(process)?;
    let module_sizes = process
        .module_list()
        .map(|modules| {
            modules
                .into_iter()
                .map(|module| {
                    (
                        module.name.to_string().to_ascii_lowercase(),
                        module.size as u64,
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let removed_invalid_offsets = sanitize_offset_map(&mut result.offsets, &module_sizes);
    if removed_invalid_offsets > 0 {
        log::warn!(
            "discarded {} canonical offset(s) outside their module image",
            removed_invalid_offsets
        );
    }
    let module_fingerprints = module_fingerprints(process);
    let mut build_number = result.offsets.iter().find_map(|(module_name, offsets)| {
        let module = process.module_by_name(module_name).ok()?;
        let offset = offsets.iter().find(|(name, _)| *name == "dwBuildNumber")?.1;
        process.read::<u32>(module.base + offset).data_part().ok()
    });
    let mut dynamic_offsets_added = 0usize;

    let mut pattern_report: Option<patterns::PatternReport> = None;

    ui::section("Patterns");
    match patterns::scan_all_with_options(
        process,
        pattern_specs,
        pattern_cache,
        patterns::ScanOptions {
            auto_repair: true,
        },
    ) {
            Ok(report) => {
                let added_offsets = overlay_dynamic_offsets(&mut result.offsets, &report);
                dynamic_offsets_added = added_offsets;
                if build_number.is_none() {
                    build_number = dynamic_build_number(process, &report);
                }
                if added_offsets > 0 {
                    info!(
                        "added {} dynamically resolved offset(s) missing from canonical scanner",
                        added_offsets
                    );
                }
                let previous_patterns = fs::read_to_string(args.output.join("patterns.json")).ok();
                fs::create_dir_all(&args.output)?;
                fs::write(
                    args.output.join("patterns.json"),
                    serde_json::to_string_pretty(&report)?,
                )?;
                if let Some(previous) = previous_patterns {
                    match output::pattern_diff::render_json(&previous, &report) {
                        Ok(diff) => fs::write(args.output.join("patterns.diff.json"), diff)?,
                        Err(err) => log::warn!("failed to compare pattern reports: {}", err),
                    }
                }
                let repair_path = args.output.join("patterns.repair.json");
                let patch_path = args.output.join("patterns.repair.patch.json");
                if report.repairs.is_empty() {
                    // A healthy database must not leave a stale repair report
                    // behind from an earlier, broken run.
                    let _ = fs::remove_file(&repair_path);
                    let _ = fs::remove_file(&patch_path);
                } else {
                    match serde_json::to_string_pretty(&report.repairs) {
                        Ok(json) => {
                            if let Err(err) = fs::write(&repair_path, json) {
                                log::warn!("failed to write pattern repair report: {}", err);
                            } else {
                                info!(
                                    "wrote patterns.repair.json ({} suggestion(s))",
                                    report.repairs.len()
                                );
                            }
                        }
                        Err(err) => log::warn!("failed to render pattern repair report: {}", err),
                    }
                    match patterns::repair::render_pattern_file(&report.repairs) {
                        Some(patch) => {
                            if let Err(err) = fs::write(&patch_path, patch) {
                                log::warn!("failed to write pattern repair patch: {}", err);
                            } else {
                                info!(
                                    "wrote patterns.repair.patch.json; re-run with --pattern-file {} to apply it",
                                    patch_path.display()
                                );
                            }
                        }
                        None => {
                            let _ = fs::remove_file(&patch_path);
                        }
                    }
                }
                fs::write(
                    args.output.join("patterns.hpp"),
                    patterns::writers::render_hpp(&report.hits),
                )?;
                fs::write(
                    args.output.join("patterns.md"),
                    patterns::writers::render_md(&report.hits),
                )?;
                for file_type in file_types {
                    let rendered = match file_type.as_str() {
                        "cs" => Some(patterns::writers::render_cs(&report.hits)),
                        "rs" => Some(patterns::writers::render_rs(&report.hits)),
                        "zig" => Some(patterns::writers::render_zig(&report.hits)),
                        _ => None,
                    };
                    if let Some(rendered) = rendered {
                        fs::write(
                            args.output.join(format!("patterns.{}", file_type)),
                            rendered,
                        )?;
                    }
                }
                fs::write(
                    args.output.join("offsets_merged.hpp"),
                    patterns::offsets_writer::render_offsets_hpp(
                        &report.hits,
                        &result.offsets,
                        &result.interfaces,
                    ),
                )?;
                fs::write(
                    args.output.join("offsets_merged.json"),
                    patterns::offsets_writer::render_offsets_json(
                        &report.hits,
                        &result.offsets,
                        &result.interfaces,
                    ),
                )?;
                info!(
                    "found {}/{} patterns across {} modules",
                    report.found,
                    report.total,
                    report.modules.len()
                );
                pattern_report = Some(report);
            }
            Err(err) => log::error!("pattern scan failed: {err}"),
        }

    if let Some(schema_system_va) = pattern_report
        .as_ref()
        .and_then(|report| resolved_pattern_va(report, "pSchemaSystem"))
        .or(loadlib_schema_va)
    {
        match analysis::schemas_from_system_va(process, schema_system_va) {
            Ok(schemas) if !schemas.is_empty() => {
                let module_count = schemas.len();
                result.schemas = schemas;
                info!(
                    "using dynamically resolved pSchemaSystem ({} modules)",
                    module_count
                );
            }
            Ok(_) => log::warn!(
                "dynamic pSchemaSystem produced no schema scopes; retaining legacy result"
            ),
            Err(err) => log::warn!(
                "dynamic pSchemaSystem failed; retaining legacy result: {}",
                err
            ),
        }
    }
    if let Some(button_global_va) = pattern_report
        .as_ref()
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
            Err(err) => log::warn!(
                "dynamic button registry failed; retaining legacy buttons: {}",
                err
            ),
        }
    }
    let netvars = output::netvars::extract(&result.schemas);
    let previous_interfaces = fs::read_to_string(args.output.join("interfaces.json")).ok();
    if let Some(previous) = previous_interfaces {
        match output::interface_diff::render_json(&previous, &result.interfaces) {
            Ok(diff) => {
                if let Err(err) = fs::write(args.output.join("interfaces.diff.json"), diff) {
                    log::warn!("failed to write interface diff: {}", err);
                } else {
                    info!("wrote interfaces.diff.json");
                }
            }
            Err(err) => log::warn!("failed to compare interfaces: {}", err),
        }
    }
    let previous_schema_index = fs::read_to_string(args.output.join("schema_index.json")).ok();
    if let Err(err) = fs::create_dir_all(&args.output).and_then(|_| {
        fs::write(
            args.output.join("schema_index.json"),
            output::schema_index::render_json(&result.schemas),
        )
    }) {
        log::warn!("failed to write schema_index.json: {}", err);
    } else {
        info!("wrote schema_index.json ({} modules)", result.schemas.len());
        if let Some(previous) = previous_schema_index {
            let current = output::schema_index::render_json(&result.schemas);
            match output::schema_diff::render_json(&previous, &current) {
                Ok(diff) => {
                    if let Err(err) = fs::write(args.output.join("schema_index.diff.json"), diff) {
                        log::warn!("failed to write schema diff: {}", err);
                    } else {
                        info!("wrote schema_index.diff.json");
                    }
                }
                Err(err) => log::warn!("failed to compare schema indexes: {}", err),
            }
        }
    }

    if !netvars.is_empty() {
        let dir = args.output.join("netvars");
        if let Err(err) = fs::create_dir_all(&dir)
            .and_then(|_| {
                fs::write(
                    dir.join("netvars.json"),
                    output::netvars::render_json(&netvars),
                )
            })
            .and_then(|_| {
                fs::write(
                    dir.join("netvars.hpp"),
                    output::netvars::render_hpp(&netvars, build_number),
                )
            })
        {
            log::warn!("failed to write netvar reports: {}", err);
        } else {
            info!("wrote netvar reports ({} fields)", netvars.len());
        }
    }

    // These signatures describe the *code* that touches a global, so a recompile
    // can invalidate them. The objects they point at are recognisable on their
    // own, so fall back to describing those: the entity, weapon, convar and
    // game-event reports then survive an update instead of disappearing until
    // the patterns have been re-authored by hand.
    let pattern_va = |name: &str| {
        pattern_report
            .as_ref()
            .and_then(|report| resolved_pattern_va(report, name))
    };
    let entity_system_global = pattern_va("pEntitySystem").or_else(|| {
        anchor_from_scan(
            "entity system",
            analysis::entity_anchor::find_in_module(process, "client.dll"),
        )
    });
    let cvar_registry_global = pattern_va("pCvarRegistry").or_else(|| {
        anchor_from_scan(
            "convar registry",
            analysis::convars::find_registry(process, "tier0.dll"),
        )
    });
    let event_manager_global = pattern_va("pGameEventManager").or_else(|| {
        anchor_from_scan(
            "game event manager",
            analysis::gameevents::find_manager(process, "client.dll"),
        )
    });

    // Offset symbols whose globals point at objects with nothing describable
    // about them — game rules, the local player — are recovered from the live
    // world instead: the entity list names the object, the schema dump locates
    // it, and the global is whatever slot in `client.dll` holds it. The view
    // matrix needs none of that — its numbers identify it in the image — so the
    // recovery runs even when no entity system was found. Canonical scanner
    // results keep their names, so this only fills what a stale signature left
    // empty.
    let recovered =
        analysis::dyn_offsets::recover(process, &result.schemas, entity_system_global);
    let mut added = 0usize;
    for item in &recovered {
        let module = result.offsets.entry(item.module.clone()).or_default();
        if module.contains_key(&item.symbol) {
            continue;
        }
        module.insert(item.symbol.clone(), item.rva);
        added += 1;
        info!(
            "recovered {} from live objects at {}+{:#X}",
            item.symbol, item.module, item.rva
        );
    }
    dynamic_offsets_added += added;

    // Vtables come from the interface walk in analyze_all. Pattern hits
    // only recover slot names; a failed signature pass must not drop the
    // headers.
    if let Some(report) = pattern_report.as_ref() {
        analysis::recover_names(&mut result.vtables, &report.hits);
    }
    if !result.vtables.is_empty() {
        let count: usize = result.vtables.values().map(|m| m.len()).sum();
        if let Err(err) = fs::write(
            args.output.join("vtables.json"),
            output::vtables::render_json(&result.vtables)?,
        ) {
            log::warn!("failed to write vtables.json: {}", err);
        } else {
            info!("wrote vtables.json ({} interfaces)", count);
        }
        if let Err(err) = fs::write(
            args.output.join("vtables.hpp"),
            output::vtables::render_hpp(&result.vtables, build_number),
        ) {
            log::warn!("failed to write vtables.hpp: {}", err);
        } else {
            info!("wrote vtables.hpp ({} interfaces)", count);
        }
        if let Err(err) = fs::write(
            args.output.join("vtables.cs"),
            output::vtables::render_cs(&result.vtables, build_number),
        ) {
            log::warn!("failed to write vtables.cs: {}", err);
        }
    }

    // Typed interface wrappers are an additive SDK-style view of the
    // vtable data. The legacy root interfaces.hpp remains untouched.
    let interface_rvas = &result.interfaces;
    let mut typed_classes: Vec<output::interface_classes::IfaceClass> = result
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
                        name: method.name.clone(),
                    })
                    .collect();
                output::interface_classes::IfaceClass {
                    module: module.clone(),
                    iface_name: iface_name.clone(),
                    instance_rva: interface_rvas
                        .get(module)
                        .and_then(|items| items.get(iface_name))
                        .copied()
                        .map(|value| value as u64),
                    rtti_class: info.rtti_class.clone(),
                    methods,
                    manual: false,
                }
            })
        })
        .collect();
    if let Some(report) = pattern_report.as_ref() {
        typed_classes.extend(analysis::manual_iface::discover(process, report));
    }
    if !typed_classes.is_empty() {
        let dir = args.output.join("interfaces");
        if let Err(err) = fs::create_dir_all(&dir).and_then(|_| {
            fs::write(
                dir.join("interfaces.hpp"),
                output::interface_classes::render_hpp(
                    &result.interfaces,
                    &typed_classes,
                    build_number,
                ),
            )
        }) {
            log::warn!("failed to write typed interface header: {}", err);
        } else {
            info!(
                "wrote interfaces/interfaces.hpp ({} classes)",
                typed_classes.len()
            );
        }
    }

    // The walks below are anchored on globals that a data scan can supply, so
    // they are deliberately outside the pattern-report block: a dump run with
    // `--skip-patterns`, or one whose signatures have gone stale, still gets
    // them.
    if let Some(global_va) = cvar_registry_global {
        match analysis::convars::walk(process, global_va) {
            Ok(dump) => {
                let dir = args.output.join("convars");
                if let Err(err) = fs::create_dir_all(&dir)
                    .and_then(|_| {
                        fs::write(
                            dir.join("convars.json"),
                            output::convars::render_json(&dump, build_number),
                        )
                    })
                    .and_then(|_| {
                        fs::write(
                            dir.join("convars.hpp"),
                            output::convars::render_hpp(&dump, build_number),
                        )
                    })
                {
                    log::warn!("failed to write convar report: {}", err);
                } else {
                    info!(
                        "wrote convars report ({} convars, {} commands)",
                        dump.convars.len(),
                        dump.commands.len()
                    );
                }
            }
            Err(err) => log::warn!("convar walk failed: {}", err),
        }
    }

    if let Some(global_va) = event_manager_global {
        match analysis::gameevents::walk(process, global_va) {
            Ok(events) => {
                let dir = args.output.join("gameevents");
                if let Err(err) = fs::create_dir_all(&dir).and_then(|_| {
                    fs::write(
                        dir.join("gameevents.json"),
                        output::gameevents::render_json(&events, build_number),
                    )
                }) {
                    log::warn!("failed to write gameevent report: {}", err);
                } else {
                    info!("wrote gameevents.json ({} events)", events.len());
                }
            }
            Err(err) => log::warn!("gameevent walk failed: {}", err),
        }
    }

    if let Some(global_va) = entity_system_global {
        match analysis::entities::walk(process, global_va, &result.schemas) {
            Ok(entities) => {
                let dir = args.output.join("entities");
                if let Err(err) = fs::create_dir_all(&dir).and_then(|_| {
                    fs::write(
                        dir.join("entities.json"),
                        output::entities::render_json(&entities, build_number),
                    )
                }) {
                    log::warn!("failed to write entity report: {}", err);
                } else {
                    info!("wrote entities.json ({} entities)", entities.len());
                }
            }
            Err(err) => log::warn!("entity walk failed: {}", err),
        }
    }

    if let Some(global_va) = entity_system_global {
        match analysis::weapons::walk(process, global_va, &result.schemas) {
            Ok(weapons) => {
                let dir = args.output.join("weapons");
                if let Err(err) = fs::create_dir_all(&dir).and_then(|_| {
                    fs::write(
                        dir.join("weapons.json"),
                        output::weapons::render_json(&weapons, build_number),
                    )
                }) {
                    log::warn!("failed to write weapon report: {}", err);
                } else {
                    info!("wrote weapons.json ({} weapons)", weapons.len());
                }
            }
            Err(err) => log::warn!("weapon walk failed: {}", err),
        }
    }
    let _ = fs::write(
        args.output.join("entity_system.hpp"),
        output::entity_system::render_hpp(build_number),
    );
    let output = Output::new(
        file_types,
        4,
        &args.output,
        &result,
        build_number,
    )?;

    output.dump_all(process)?;

    if args.guess_structs {
        match fs::write(
            args.output.join("structs.hpp"),
            output::guessed_structs::render_hpp(&result.schemas, build_number),
        ) {
            Ok(()) => {
                ui::ok("guessed structs.hpp emitted");
                info!("wrote structs.hpp (--guess-structs)");
            }
            Err(err) => log::warn!("failed to write structs.hpp: {err}"),
        }
    }

    let csgo_input_rva = output::include_tree::live_csgo_input_rva(
        &result.offsets,
        pattern_report
            .as_ref()
            .and_then(|report| resolved_pattern_va(report, "pCSGOInput")),
    );
    ui::section("Include tree");
    match output::include_tree::dump(&args.output, &result, build_number, csgo_input_rva) {
        Ok(stems) => {
            ui::ok(&format!(
                "include-tree SDK emitted ({} schema modules)",
                stems.len()
            ));
            info!("wrote include-tree SDK ({} schema modules)", stems.len());
        }
        Err(err) => {
            ui::warn(&format!("include tree failed: {err}"));
            log::warn!("failed to write include-tree SDK: {err}");
            let _ = fs::write(
                args.output.join("cs2.hpp"),
                output::amalgamation::render_hpp(&[], build_number),
            );
        }
    }

    // Protobuf reflection is intentionally the final pass: it reads several
    // complete module images and can reduce the effectiveness of later reads.
    match analysis::protobufs(process) {
        Ok(messages) if !messages.is_empty() => {
            let dir = args.output.join("protobufs");
            if let Err(err) = fs::create_dir_all(&dir)
                .and_then(|_| {
                    fs::write(
                        dir.join("protobufs.json"),
                        output::protobufs::render_json(&messages),
                    )
                })
                .and_then(|_| {
                    fs::write(
                        dir.join("protobufs.hpp"),
                        output::protobufs::render_hpp(&messages, build_number),
                    )
                })
            {
                log::warn!("failed to write protobuf reports: {}", err);
            } else {
                let count: usize = messages.values().map(|items| items.len()).sum();
                info!("wrote protobuf reports ({} messages)", count);
            }
        }
        Ok(_) => info!("protobuf reflection tables not found"),
        Err(err) => log::warn!("protobuf scan failed: {}", err),
    }

    output.dump_manifest()?;
    if let Ok(manifest_path) = args.output.join("manifest.json").canonicalize() {
        if let Ok(raw) = fs::read_to_string(&manifest_path) {
            if let Ok(mut manifest) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(object) = manifest.as_object_mut() {
                    object.insert("build_number".to_string(), build_number.into());
                    object.insert("backend".to_string(), backend.into());
                    object.insert("load_lib".to_string(), used_load_lib.into());
                    object.insert(
                        "shade_bindings".to_string(),
                        serde_json::Value::Array(
                            shade_bindings
                                .iter()
                                .map(|name| serde_json::Value::String(name.clone()))
                                .collect(),
                        ),
                    );
                    object.insert(
                        "module_fingerprints".to_string(),
                        module_fingerprints.clone(),
                    );
                    object.insert(
                        "modules_list".to_string(),
                        serde_json::Value::Array(
                            result
                                .schemas
                                .keys()
                                .map(|name| serde_json::Value::String(name.clone()))
                                .collect(),
                        ),
                    );
                    object.insert(
                        "missing_schema_modules".to_string(),
                        serde_json::Value::Array(
                            analysis::schema_flags::missing_schema_modules(&result.schemas)
                                .into_iter()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                    if let Some(report) = pattern_report.as_ref() {
                        object.insert(
                            "pattern_summary".to_string(),
                            serde_json::json!({
                                "found": report.found,
                                "total": report.total,
                                "modules": report.modules.len(),
                                "external_overrides": external_pattern_count,
                                "dynamic_offsets_added": dynamic_offsets_added,
                                "canonical_offsets_removed": removed_invalid_offsets,
                                "cache_hits": report.cache_hits,
                                "cache_misses": report.cache_misses,
                            }),
                        );
                    }
                    if let Ok(content) = serde_json::to_string_pretty(&manifest) {
                        if let Err(err) = fs::write(&manifest_path, content) {
                            log::warn!("failed to enrich manifest: {}", err);
                        }
                    }
                }
            }
        }
    }
    info!("analysis completed in {:.2?}", now.elapsed());
    ui::section("Summary");
    ui::kv("Output dir", &args.output.display().to_string());
    if let Some(bn) = build_number {
        ui::kv("Build number", &bn.to_string());
    }
    if let Some(report) = pattern_report.as_ref() {
        ui::kv("Patterns", &format!("{}/{}", report.found, report.total));
    }
    ui::sound(ui::Cue::Success);
    ui::step("All stages completed.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_output_file_types_before_attach() {
        assert!(validate_file_types(&["hpp".into(), "json".into()]).is_ok());
        let error = validate_file_types(&["hpp".into(), "lua".into()])
            .expect_err("unknown output type must be rejected");
        assert!(error.to_string().contains("lua"));
    }

    #[test]
    fn syscall_connector_is_not_a_memflow_plugin_name() {
        assert!(memory::syscall::is_syscall_connector(Some("syscall")));
        assert!(!memory::syscall::is_syscall_connector(Some("pcileech")));
    }

    #[test]
    fn shade_connector_is_not_a_memflow_plugin_name() {
        assert!(memory::shade::is_shade_connector(Some("shade")));
        assert!(!memory::shade::is_shade_connector(Some("syscall")));
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
        let sizes = std::collections::BTreeMap::from([("client.dll".to_string(), 0x800)]);
        assert_eq!(sanitize_offset_map(&mut offsets, &sizes), 1);
        assert!(offsets["client.dll"].contains_key("dwValid"));
        assert!(!offsets["client.dll"].contains_key("dwInvalid"));
    }

    #[test]
    fn resolves_external_pattern_anchor_case_insensitively() {
        let report = patterns::PatternReport {
            hits: vec![patterns::PatternHit {
                name: "pentitysystem".to_string(),
                module: "client.dll".to_string(),
                resolve: "riprel",
                pattern: "48 8B ?".to_string(),
                prototype: None,
                bytes: None,
                pattern_synth: None,
                repaired_from: None,
                found: true,
                match_rva: Some(0x100),
                match_va: Some(0x1800_0010_0),
                rva: Some(0x100),
                va: Some(0x1800_0010_0),
                matches: 1,
                confidence: 1.0,
                error: None,
            }],
            ..Default::default()
        };

        assert_eq!(
            resolved_pattern_va(&report, "pEntitySystem"),
            Some(0x1800_0010_0)
        );
    }
}
