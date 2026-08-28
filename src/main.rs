use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use log::{LevelFilter, info};
use memflow::prelude::v1::*;
use simplelog::*;

use cs2_dumper::dump;
use cs2_dumper::loadlib;
use cs2_dumper::memory;
use cs2_dumper::patterns;
use cs2_dumper::ui;

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

    /// Disable the Windows Beep() progress cues.
    #[arg(long)]
    no_sound: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let file_types: Vec<String> = dump::FILE_TYPES.iter().map(|s| (*s).to_string()).collect();
    fs::create_dir_all(&args.output).with_context(|| {
        format!("failed to create output directory {}", args.output.display())
    })?;
    ui::init(args.no_sound);
    ui::banner();
    ui::sound(ui::Cue::Start);
    dump::validate_file_types(&file_types)?;
    init_logging(args.verbose, &dump_log_path(&args.output))?;

    let external = match args.pattern_file.as_deref() {
        Some(path) => patterns::load_pattern_file(path)?,
        None => Vec::new(),
    };
    let external_pattern_count = external.len();
    let merged_specs = if external.is_empty() {
        None
    } else {
        Some(patterns::merged_patterns(
            patterns::database::CS2_PATTERNS,
            external,
        ))
    };
    let patterns = match merged_specs.as_deref() {
        Some(specs) => dump::PatternSet::Specs(specs),
        None => dump::PatternSet::Builtins(patterns::database::CS2_PATTERNS),
    };
    let pattern_cache = load_pattern_cache(&args.output);
    if external_pattern_count > 0 {
        info!(
            "loaded {} external pattern override(s); scanning {} total signatures",
            external_pattern_count,
            patterns.len()
        );
    }

    let dump_cfg = |backend: &str,
                    loadlib_schema_va: Option<u64>,
                    used_load_lib: bool,
                    shade_bindings: &[String]| dump::Config {
        output: &args.output,
        file_types: &file_types,
        patterns,
        pattern_cache: pattern_cache.as_ref(),
        external_pattern_count,
        loadlib_schema_va,
        used_load_lib,
        backend: backend.to_string(),
        shade_bindings: shade_bindings.to_vec(),
        guess_structs: args.guess_structs,
        steam_inf: None,
    };

    if memory::syscall::is_syscall_connector(args.connector.as_deref()) {
        #[cfg(not(windows))]
        {
            anyhow::bail!("-c syscall is Windows-only");
        }
        #[cfg(windows)]
        {
            ui::section("Target");
            ui::kv("Backend", "syscall");
            let mut process = memory::syscall::attach("cs2.exe")?;
            ui::ok(format_args!(
                "cs2.exe via NtReadVirtualMemory (pid {})",
                process.info().pid
            ));
            return dump_or_fail(&mut process, &dump_cfg("syscall", None, false, &[]));
        }
    }

    let mut shade_bindings: Vec<String> = Vec::new();
    let shade_mode = memory::shade::is_shade_connector(args.connector.as_deref());
    if shade_mode {
        #[cfg(not(windows))]
        {
            anyhow::bail!("-c shade is Windows-only");
        }
        #[cfg(windows)]
        {
            ui::section("Target");
            ui::kv("Backend", "shade");
            let report = memory::shade::inject_schema_bindings()?;
            ui::ok(format_args!(
                "injected InstallSchemaBindings ({} modules, SchemaSystem {:#X})",
                report.bindings.len(),
                report.schema_system
            ));
            for name in &report.bindings {
                log::info!("shade registered {name}");
            }
            for (name, err) in &report.failed {
                ui::warn(format_args!("{name}: {err}"));
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

    let mut os = match args.connector.as_deref() {
        Some(_) if shade_mode => {
            #[cfg(windows)]
            {
                memflow_native::create_os(&OsArgs::default(), LibArc::default())?
            }
            #[cfg(not(windows))]
            {
                anyhow::bail!("-c shade is Windows-only")
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
                anyhow::bail!("no connector specified; pass --connector on this platform")
            }
        }
    };

    ui::section("Target");
    let live_pid = os
        .process_by_name("cs2.exe")
        .ok()
        .map(|process| process.info().pid);
    if !shade_mode && live_pid.is_none() {
        if let Some(connector) = args.connector.as_deref() {
            anyhow::bail!(
                "cs2.exe not found on connector `{connector}`; LoadLibrary fallback is native-only"
            );
        }
        ui::warn("cs2.exe not running — searching Steam install");
        let game_dir = loadlib::find_install()?;
        ui::ok(format_args!("install {}", game_dir.display()));
        ui::section("LoadLibrary");
        ui::sound(ui::Cue::Step);
        let report = loadlib::load(&game_dir)?;
        ui::ok(format_args!(
            "loaded {} modules, {} schema bindings",
            report.loaded.len(),
            report.bindings.len()
        ));
        for (name, err) in &report.failed {
            ui::warn(format_args!("{name}: {err}"));
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("LoadLibrary dump is Windows-only");
        }
        #[cfg(windows)]
        {
            let mut process = memory::local::attach_self()?;
            ui::ok(format_args!("self pid {}", process.info().pid));
            let mut cfg = dump_cfg("loadlib", report.schema_system, true, &[]);
            cfg.steam_inf = report.steam_inf;
            return dump_or_fail(&mut process, &cfg);
        }
    }

    let mut process = if shade_mode {
        os.process_by_name("cs2.exe")
            .context("cs2.exe disappeared after shade inject")?
    } else {
        let pid = live_pid.context("cs2.exe disappeared after detection")?;
        ui::ok(format_args!("cs2.exe running (pid {pid})"));
        os.process_by_name("cs2.exe")
            .context("cs2.exe disappeared after detection")?
    };
    let backend = if shade_mode {
        "shade"
    } else {
        args.connector.as_deref().unwrap_or("native")
    };
    dump_or_fail(
        &mut process,
        &dump_cfg(backend, None, false, &shade_bindings),
    )
}

fn dump_or_fail<P: Process + MemoryView>(
    process: &mut P,
    cfg: &dump::Config<'_>,
) -> Result<()> {
    match dump::run(process, cfg) {
        Ok(()) => Ok(()),
        Err(err) => {
            ui::sound(ui::Cue::Failure);
            ui::err(format_args!("{err:#}"));
            Err(err)
        }
    }
}

fn dump_log_path(output: &Path) -> PathBuf {
    output.join("cs2-dumper.log")
}

/// Open the dump log. A create failure is reported on stderr and returns
/// `None` so attach / analysis still runs.
fn log_file_or_warn(log_path: &Path) -> Option<File> {
    match File::create(log_path) {
        Ok(file) => Some(file),
        Err(err) => {
            eprintln!(
                "unable to write log file {}: {err}",
                log_path.display()
            );
            None
        }
    }
}

fn terminal_log_level(verbose: u8) -> LevelFilter {
    match verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

fn init_logging(verbose: u8, log_path: &Path) -> Result<()> {
    let level_filter = terminal_log_level(verbose);
    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![TermLogger::new(
        level_filter,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )];
    if let Some(file) = log_file_or_warn(log_path) {
        loggers.push(WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            file,
        ));
    }
    CombinedLogger::init(loggers)?;
    Ok(())
}

fn load_pattern_cache(output: &std::path::Path) -> Option<patterns::PatternCache> {
    let path = output.join("patterns.json");
    if !path.is_file() {
        return None;
    }
    match fs::read_to_string(&path).ok().and_then(|raw| serde_json::from_str(&raw).ok()) {
        Some(cache) => Some(cache),
        None => {
            log::warn!("unable to load pattern cache {}", path.display());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_log_path_is_inside_the_output_directory() {
        let output = Path::new(r"C:\dumps\cs2");
        let log = dump_log_path(output);
        assert_eq!(log.parent(), Some(output));
        assert_eq!(
            log.file_name().and_then(|name| name.to_str()),
            Some("cs2-dumper.log")
        );
    }

    #[test]
    fn log_file_or_warn_returns_none_when_the_path_is_a_directory() {
        let dir = std::env::temp_dir().join(format!(
            "cs2-dumper-log-dir-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp log dir");
        assert!(
            log_file_or_warn(&dir).is_none(),
            "creating a log file on a directory must not abort the dump"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_terminal_log_level_keeps_warnings_visible() {
        assert_eq!(terminal_log_level(0), LevelFilter::Warn);
        assert_eq!(terminal_log_level(1), LevelFilter::Info);
        assert_eq!(terminal_log_level(2), LevelFilter::Debug);
    }
}
