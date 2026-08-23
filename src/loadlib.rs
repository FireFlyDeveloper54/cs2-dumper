//! Load CS2 modules into this process and register schema bindings.
//!
//! Windows-only port of `cs2-schema-dumper-no-process`: `LoadLibrary` the
//! schema DLLs, resolve `SchemaSystem_001`, then call each module's
//! `InstallSchemaBindings` export. The rest of the dumper then attaches to
//! *this* process and walks schema/offsets as usual.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

#[derive(Debug, Default)]
pub struct LoadLibReport {
    pub loaded: Vec<String>,
    pub bindings: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub schema_system: Option<u64>,
}

/// Relative paths loaded before schema registration.
const DEPS: &[&str] = &[
    "game\\bin\\win64\\tier0.dll",
    "game\\bin\\win64\\vstdlib.dll",
    "game\\bin\\win64\\steam_api64.dll",
    "game\\bin\\win64\\steamnetworkingsockets.dll",
];

/// Modules whose `InstallSchemaBindings` export fills CSchemaSystem.
const SCHEMA_MODULES: &[&str] = &[
    "game\\bin\\win64\\schemasystem.dll",
    "game\\bin\\win64\\animationsystem.dll",
    "game\\bin\\win64\\engine2.dll",
    "game\\bin\\win64\\filesystem_stdio.dll",
    "game\\bin\\win64\\inputsystem.dll",
    "game\\bin\\win64\\imemanager.dll",
    "game\\bin\\win64\\localize.dll",
    "game\\bin\\win64\\materialsystem2.dll",
    "game\\bin\\win64\\meshsystem.dll",
    "game\\bin\\win64\\navsystem.dll",
    "game\\bin\\win64\\networksystem.dll",
    "game\\bin\\win64\\panorama.dll",
    "game\\bin\\win64\\panorama_text_pango.dll",
    "game\\bin\\win64\\panoramauiclient.dll",
    "game\\bin\\win64\\particles.dll",
    "game\\bin\\win64\\pulse_system.dll",
    "game\\bin\\win64\\rendersystemdx11.dll",
    "game\\bin\\win64\\resourcesystem.dll",
    "game\\bin\\win64\\scenefilecache.dll",
    "game\\bin\\win64\\scenesystem.dll",
    "game\\bin\\win64\\soundsystem.dll",
    "game\\bin\\win64\\steamaudio.dll",
    "game\\bin\\win64\\v8system.dll",
    "game\\bin\\win64\\vconcomm.dll",
    "game\\bin\\win64\\vphysics2.dll",
    "game\\bin\\win64\\vscript.dll",
    "game\\bin\\win64\\worldrenderer.dll",
    "game\\csgo\\bin\\win64\\client.dll",
    "game\\csgo\\bin\\win64\\server.dll",
    "game\\csgo\\bin\\win64\\host.dll",
    "game\\csgo\\bin\\win64\\matchmaking.dll",
];

pub fn current_process_name() -> Result<String> {
    let exe = std::env::current_exe().context("failed to resolve current executable")?;
    exe.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .context("current executable has no file name")
}

/// True when `dir` looks like a CS2 install root (`game\bin\win64\...`).
pub fn is_cs2_install(dir: &Path) -> bool {
    resolve_game_file(dir, "game\\bin\\win64\\schemasystem.dll").is_file()
        || resolve_game_file(dir, "game\\bin\\win64\\cs2.exe").is_file()
}

fn folder_name_lower(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_counter_strike_folder(dir: &Path) -> bool {
    folder_name_lower(dir).contains("counter-strike")
}

/// Prefer an official CS2 folder name over a leftover CS:GO-era name.
fn install_rank(dir: &Path) -> u8 {
    let name = folder_name_lower(dir);
    if name == "counter-strike 2" {
        0
    } else if name.contains("counter-strike 2") {
        1
    } else if name.contains("global offensive") {
        2
    } else if name.contains("counter-strike") {
        3
    } else {
        4
    }
}

fn steamapps_common(steam_root: &Path) -> Option<PathBuf> {
    let common = steam_root.join("steamapps").join("common");
    common.is_dir().then_some(common)
}

fn parse_libraryfolders(text: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else { break };
        let token = &rest[..end];
        rest = &rest[end + 1..];
        if token.len() < 2 {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if !(lower.contains(":\\") || lower.contains("steam")) {
            continue;
        }
        if lower.contains(".vdf") || lower.contains(".dll") {
            continue;
        }
        paths.push(PathBuf::from(token.replace("\\\\", "\\")));
    }
    paths
}

fn steam_roots_from_vdf(steam_root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![steam_root.to_path_buf()];
    for rel in ["steamapps/libraryfolders.vdf", "config/libraryfolders.vdf"] {
        let Ok(text) = std::fs::read_to_string(steam_root.join(rel)) else {
            continue;
        };
        for path in parse_libraryfolders(&text) {
            if path.is_dir() {
                roots.push(path);
            }
        }
    }
    roots
}

#[cfg(windows)]
fn steam_roots_from_registry() -> Vec<PathBuf> {
    windows_reg::steam_install_paths()
}

#[cfg(not(windows))]
fn steam_roots_from_registry() -> Vec<PathBuf> {
    Vec::new()
}

fn env_steam_roots() -> Vec<PathBuf> {
    ["STEAM", "STEAM_PATH", "STEAMROOT", "STEAM_ROOT"]
        .iter()
        .filter_map(|key| std::env::var_os(key).map(PathBuf::from))
        .filter(|path| path.is_dir())
        .collect()
}

fn well_known_steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in ["ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"] {
        if let Some(base) = std::env::var_os(key).map(PathBuf::from) {
            roots.push(base.join("Steam"));
        }
    }
    if let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    {
        roots.push(home.join(".steam").join("steam"));
        roots.push(home.join(".steam").join("root"));
        roots.push(home.join(".local").join("share").join("Steam"));
        roots.push(home.join("Steam"));
    }
    roots
}

fn drive_letters() -> Vec<PathBuf> {
    // Skip A:/B: — those can hang on empty floppy/optical drives.
    (b'C'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
        .filter(|drive| drive.is_dir())
        .collect()
}

/// Steam / SteamLibrary at the drive root, plus one extra directory level
/// (`D:\games\Steam`, `E:\application\steam`, …) without baking in a machine
/// path.
fn discover_steam_roots_on_drives() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for drive in drive_letters() {
        for name in ["Steam", "SteamLibrary", "Program Files (x86)\\Steam", "Program Files\\Steam"]
        {
            roots.push(drive.join(name));
        }
        let Ok(top) = std::fs::read_dir(&drive) else {
            continue;
        };
        for entry in top.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if steamapps_common(&path).is_some() {
                roots.push(path.clone());
            }
            let Ok(children) = std::fs::read_dir(&path) else {
                continue;
            };
            for child in children.flatten() {
                let nested = child.path();
                if nested.is_dir() && steamapps_common(&nested).is_some() {
                    roots.push(nested);
                }
            }
        }
    }
    roots
}

fn all_steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    roots.extend(steam_roots_from_registry());
    roots.extend(env_steam_roots());
    roots.extend(well_known_steam_roots());
    roots.extend(discover_steam_roots_on_drives());
    roots.retain(|path| path.is_dir());
    roots
}

fn cs2_candidates_in_common(common: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(common) else {
        return Vec::new();
    };
    let installs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && is_cs2_install(path))
        .collect();
    let named: Vec<PathBuf> = installs
        .iter()
        .filter(|path| is_counter_strike_folder(path))
        .cloned()
        .collect();
    if named.is_empty() {
        installs
    } else {
        named
    }
}

/// Locate the CS2 install root. Uses the Steam registry, `libraryfolders.vdf`,
/// and a shallow scan of local drives for `steamapps/common/Counter-Strike*`.
pub fn find_install() -> Result<PathBuf> {
    let mut seen_steam = std::collections::BTreeSet::new();
    let mut candidates = Vec::new();

    for steam in all_steam_roots() {
        if !seen_steam.insert(steam.clone()) {
            continue;
        }
        for library in steam_roots_from_vdf(&steam) {
            let Some(common) = steamapps_common(&library) else {
                continue;
            };
            candidates.extend(cs2_candidates_in_common(&common));
        }
    }

    candidates.sort_by(|a, b| {
        install_rank(a)
            .cmp(&install_rank(b))
            .then_with(|| a.cmp(b))
    });
    candidates.dedup();
    if let Some(found) = candidates.into_iter().next() {
        return Ok(found);
    }

    bail!(
        "cs2.exe is not running and no CS2 install was found. Searched Steam (registry, libraryfolders.vdf) and drive roots for steamapps/common/Counter-Strike*"
    )
}

#[cfg(windows)]
mod windows_reg {
    use std::path::PathBuf;

    unsafe extern "system" {
        fn RegGetValueW(
            hkey: isize,
            sub_key: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut u8,
            data_size: *mut u32,
        ) -> i32;
    }

    const HKEY_CURRENT_USER: isize = 0x8000_0001u32 as isize;
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_sz(root: isize, sub: &str, value: &str) -> Option<PathBuf> {
        let sub_w = wide(sub);
        let val_w = wide(value);
        let mut buf = vec![0u16; 512];
        let mut size = (buf.len() * 2) as u32;
        let status = unsafe {
            RegGetValueW(
                root,
                sub_w.as_ptr(),
                val_w.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut u8,
                &mut size,
            )
        };
        if status != 0 {
            return None;
        }
        let chars = (size as usize / 2).saturating_sub(1);
        let text = String::from_utf16_lossy(&buf[..chars.min(buf.len())]);
        let path = PathBuf::from(text.trim_end_matches('\0'));
        path.is_dir().then_some(path)
    }

    pub fn steam_install_paths() -> Vec<PathBuf> {
        let mut out = Vec::new();
        for (root, key, value) in [
            (HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath"),
            (
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Valve\Steam",
                "InstallPath",
            ),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath"),
        ] {
            if let Some(path) = read_sz(root, key, value) {
                out.push(path);
            }
        }
        out
    }
}

pub fn load(game_dir: &Path) -> Result<LoadLibReport> {
    #[cfg(windows)]
    {
        windows::load(game_dir)
    }
    #[cfg(not(windows))]
    {
        let _ = game_dir;
        bail!("LoadLibrary dump is only supported on Windows")
    }
}

fn resolve_game_file(game_dir: &Path, relative: &str) -> PathBuf {
    let mut path = game_dir.to_path_buf();
    for part in relative.split(['\\', '/']) {
        if !part.is_empty() {
            path.push(part);
        }
    }
    path
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::windows::ffi::OsStrExt;

    use log::{info, warn};

    const LOAD_LIBRARY_SEARCH_DEFAULT_DIRS: u32 = 0x0000_1000;
    const LOAD_LIBRARY_SEARCH_USER_DIRS: u32 = 0x0000_0400;
    const SCHEMA_BINDINGS_OK: u64 = 0x0000_0000_C000_0001;

    type CreateInterfaceFn = unsafe extern "C" fn(*const i8, *mut i32) -> *mut core::ffi::c_void;
    type InstallSchemaBindingsFn =
        unsafe extern "C" fn(*const i8, *mut core::ffi::c_void) -> usize;

    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            module: *mut core::ffi::c_void,
            name: *const i8,
        ) -> *const core::ffi::c_void;
        fn SetDllDirectoryW(path: *const u16) -> i32;
        fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
        fn AddDllDirectory(path: *const u16) -> *mut core::ffi::c_void;
        fn GetLastError() -> u32;
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn load_library(path: &Path) -> Result<*mut core::ffi::c_void> {
        let wide = wide(path);
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            bail!("LoadLibraryW({}) failed: {err}", path.display());
        }
        Ok(handle)
    }

    fn setup_search_path(game_dir: &Path) -> Result<()> {
        let bin64 = resolve_game_file(game_dir, "game\\bin\\win64");
        let csgo64 = resolve_game_file(game_dir, "game\\csgo\\bin\\win64");
        if !bin64.is_dir() {
            bail!(
                "CS2 bin directory not found: {} (pass the game root that contains game\\bin\\win64)",
                bin64.display()
            );
        }
        let flags = LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS;
        unsafe {
            SetDefaultDllDirectories(flags);
            SetDllDirectoryW(wide(&bin64).as_ptr());
            if csgo64.is_dir() {
                AddDllDirectory(wide(&csgo64).as_ptr());
            }
            AddDllDirectory(wide(&bin64).as_ptr());
        }
        Ok(())
    }

    fn export<T>(handle: *mut core::ffi::c_void, name: &str) -> Option<T> {
        let cname = CString::new(name).ok()?;
        let ptr = unsafe { GetProcAddress(handle, cname.as_ptr()) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy(&ptr) })
        }
    }

    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }

    pub fn load(game_dir: &Path) -> Result<LoadLibReport> {
        // Game DllMain/threads abort this process on some patches. Keep going
        // without the Windows crash dialog so a failed bind is a log line.
        const SEM_FAILCRITICALERRORS: u32 = 0x0001;
        const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
        const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;
        unsafe {
            SetErrorMode(
                SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX,
            );
        }
        setup_search_path(game_dir)?;
        let mut report = LoadLibReport::default();
        let mut handles: BTreeMap<String, *mut core::ffi::c_void> = BTreeMap::new();

        for dep in DEPS {
            load_one(game_dir, dep, false, &mut handles, &mut report)?;
        }
        load_one(
            game_dir,
            "game\\bin\\win64\\schemasystem.dll",
            true,
            &mut handles,
            &mut report,
        )?;

        let schema_dll = *handles
            .get("schemasystem.dll")
            .context("schemasystem.dll was not loaded")?;
        let create: CreateInterfaceFn = export(schema_dll, "CreateInterface")
            .context("schemasystem.dll has no CreateInterface export")?;
        let name = CString::new("SchemaSystem_001")?;
        let schema_system = unsafe { create(name.as_ptr(), std::ptr::null_mut()) };
        if schema_system.is_null() {
            bail!("CreateInterface(SchemaSystem_001) returned null");
        }
        report.schema_system = Some(schema_system as u64);
        info!("SchemaSystem_001 at {:#X}", schema_system as u64);

        install_bindings("schemasystem.dll", schema_system, &handles, &mut report);
        for module in SCHEMA_MODULES {
            load_one(game_dir, module, false, &mut handles, &mut report)?;
            if let Some(name) = module.rsplit(['\\', '/']).next() {
                install_bindings(&name.to_ascii_lowercase(), schema_system, &handles, &mut report);
            }
        }

        if report.bindings.is_empty() {
            bail!("no InstallSchemaBindings calls succeeded");
        }
        Ok(report)
    }

    fn load_one(
        game_dir: &Path,
        relative: &str,
        required: bool,
        handles: &mut BTreeMap<String, *mut core::ffi::c_void>,
        report: &mut LoadLibReport,
    ) -> Result<()> {
        let file_name = relative
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(relative)
            .to_ascii_lowercase();
        if handles.contains_key(&file_name) {
            return Ok(());
        }
        let path = resolve_game_file(game_dir, relative);
        if !path.is_file() {
            let msg = format!("file not found: {}", path.display());
            if required {
                bail!("{msg}");
            }
            report.failed.push((file_name, msg));
            return Ok(());
        }
        match load_library(&path) {
            Ok(handle) => {
                info!("LoadLibrary {}", path.display());
                report.loaded.push(file_name.clone());
                handles.insert(file_name, handle);
                Ok(())
            }
            Err(err) => {
                if required {
                    Err(err)
                } else {
                    warn!("{err}");
                    report.failed.push((file_name, err.to_string()));
                    Ok(())
                }
            }
        }
    }

    fn install_bindings(
        file_name: &str,
        schema_system: *mut core::ffi::c_void,
        handles: &BTreeMap<String, *mut core::ffi::c_void>,
        report: &mut LoadLibReport,
    ) {
        let Some(&handle) = handles.get(file_name) else {
            return;
        };
        let Some(install_fn): Option<InstallSchemaBindingsFn> =
            export(handle, "InstallSchemaBindings")
        else {
            return;
        };
        let Ok(iface) = CString::new("SchemaSystem_001") else {
            return;
        };
        let status = unsafe { install_fn(iface.as_ptr(), schema_system) } as u64;
        if status == SCHEMA_BINDINGS_OK || status == 0 {
            info!("InstallSchemaBindings({file_name}) ok ({status:#X})");
            report.bindings.push(file_name.to_string());
        } else {
            warn!("InstallSchemaBindings({file_name}) returned {status:#X}");
            report
                .failed
                .push((file_name.to_string(), format!("status {status:#X}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_game_file;
    use std::path::Path;

    #[test]
    fn detects_cs2_install_layout() {
        let root = std::env::temp_dir().join(format!(
            "cs2-dumper-install-{}",
            std::process::id()
        ));
        let dll = super::resolve_game_file(&root, "game\\bin\\win64\\schemasystem.dll");
        std::fs::create_dir_all(dll.parent().unwrap()).unwrap();
        std::fs::write(&dll, b"mz").unwrap();
        assert!(super::is_cs2_install(&root));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn parses_steam_libraryfolders_paths() {
        let vdf = r#"
"libraryfolders"
{
	"0"
	{
		"path"		"C:\\Program Files (x86)\\Steam"
	}
}
"#;
        let paths = super::parse_libraryfolders(vdf);
        assert!(
            paths
                .iter()
                .any(|p| p.to_string_lossy().contains("Program Files"))
        );
    }

    #[test]
    fn finds_local_counter_strike_install_when_present() {
        let Ok(path) = super::find_install() else {
            return;
        };
        assert!(
            super::is_cs2_install(&path),
            "discovered path is not a CS2 install: {}",
            path.display()
        );
        assert!(
            super::is_counter_strike_folder(&path),
            "discovered path is not a Counter-Strike folder: {}",
            path.display()
        );
    }

    #[test]
    fn ranks_counter_strike_folder_names() {
        assert!(super::is_counter_strike_folder(Path::new(
            "steamapps/common/Counter-Strike Global Offensive"
        )));
        assert!(super::is_counter_strike_folder(Path::new(
            r"E:\SteamLibrary\steamapps\common\Counter-Strike 2"
        )));
        assert!(!super::is_counter_strike_folder(Path::new(
            "steamapps/common/CS2D"
        )));
        assert!(
            super::install_rank(Path::new("Counter-Strike 2"))
                < super::install_rank(Path::new("Counter-Strike Global Offensive"))
        );
    }

    #[test]
    fn joins_cs2_relative_module_paths() {
        let path = resolve_game_file(
            Path::new("D:/Steam/steamapps/common/Counter-Strike Global Offensive"),
            "game\\csgo\\bin\\win64\\client.dll",
        );
        let text = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        assert!(text.ends_with("game/csgo/bin/win64/client.dll"));
    }
}
