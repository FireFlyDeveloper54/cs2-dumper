use std::fmt::{self, Write};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rayon::prelude::*;

use chrono::{DateTime, Utc};

use serde_json::json;

use formatter::Formatter;

use crate::analysis::*;
#[cfg(windows)]
pub(crate) fn write_staged(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("output"),
        std::process::id()
    ));
    if let Err(err) = fs::write(&tmp, contents.as_ref()) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "failed to write temporary {}: {err}",
            tmp.display()
        ));
    }
    let result = {
        use std::os::windows::ffi::OsStrExt;
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let source: Vec<u16> = tmp
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let ok = unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 0x1 | 0x8) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "failed to replace {}: {err}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) mod amalgamation;
mod buttons;
pub(crate) mod convars;
pub(crate) mod cpp_types;
pub(crate) mod engine_structs;
pub(crate) mod entities;
pub(crate) mod entity_system;
mod formatter;
pub(crate) mod gameevents;
pub(crate) mod guessed_structs;
pub mod ident;
pub(crate) use ident::slugify;
pub(crate) mod include_tree;
pub(crate) mod interface_classes;
pub(crate) mod interface_diff;
mod interfaces;
pub(crate) mod netvars;
mod offsets;
pub(crate) mod pattern_diff;
pub(crate) mod protobufs;
pub(crate) mod schema_diff;
pub(crate) mod schema_index;
mod schemas;
mod sdk;
pub(crate) mod sdk_classes;
pub(crate) mod verified;
pub(crate) mod vtables;
pub(crate) mod weapons;

enum Item<'a> {
    Buttons(&'a ButtonMap),
    Interfaces(&'a InterfaceMap),
    Offsets(&'a OffsetMap),
    SchemaModule(schemas::SchemaModule<'a>),
}

impl<'a> Item<'a> {
    fn write(&self, fmt: &mut Formatter<'a>, file_type: &str) -> fmt::Result {
        match file_type {
            "cs" => self.write_cs(fmt),
            "hpp" => self.write_hpp(fmt),
            "json" => self.write_json(fmt),
            "rs" => self.write_rs(fmt),
            "zig" => self.write_zig(fmt),
            _ => Err(fmt::Error),
        }
    }
}

trait CodeWriter {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result;
}

impl<'a> CodeWriter for Item<'a> {
    fn write_cs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_cs(fmt),
            Item::Interfaces(ifaces) => ifaces.write_cs(fmt),
            Item::Offsets(offsets) => offsets.write_cs(fmt),
            Item::SchemaModule(module) => module.write_cs(fmt),
        }
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_hpp(fmt),
            Item::Interfaces(ifaces) => ifaces.write_hpp(fmt),
            Item::Offsets(offsets) => offsets.write_hpp(fmt),
            Item::SchemaModule(module) => module.write_hpp(fmt),
        }
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_json(fmt),
            Item::Interfaces(ifaces) => ifaces.write_json(fmt),
            Item::Offsets(offsets) => offsets.write_json(fmt),
            Item::SchemaModule(module) => module.write_json(fmt),
        }
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_rs(fmt),
            Item::Interfaces(ifaces) => ifaces.write_rs(fmt),
            Item::Offsets(offsets) => offsets.write_rs(fmt),
            Item::SchemaModule(module) => module.write_rs(fmt),
        }
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_zig(fmt),
            Item::Interfaces(ifaces) => ifaces.write_zig(fmt),
            Item::Offsets(offsets) => offsets.write_zig(fmt),
            Item::SchemaModule(module) => module.write_zig(fmt),
        }
    }
}

pub(crate) struct ManifestExtra<'a> {
    pub backend: &'a str,
    pub load_lib: bool,
    pub shade_bindings: &'a [String],
    pub module_fingerprints: serde_json::Value,
    pub missing_schema_modules: Vec<String>,
    pub pattern_summary: Option<serde_json::Value>,
    pub steam_inf: Option<serde_json::Value>,
}

pub(crate) struct Output<'a> {
    file_types: &'a [String],
    indent_size: usize,
    out_dir: &'a Path,
    result: &'a AnalysisResult,
    build_number: Option<u32>,
    timestamp: DateTime<Utc>,
}

impl<'a> Output<'a> {
    pub fn new(
        file_types: &'a [String],
        indent_size: usize,
        out_dir: &'a Path,
        result: &'a AnalysisResult,
        build_number: Option<u32>,
    ) -> Result<Self> {
        fs::create_dir_all(out_dir)?;

        Ok(Self {
            file_types,
            indent_size,
            out_dir,
            result,
            build_number,
            timestamp: Utc::now(),
        })
    }

    pub fn dump_all(&self) -> Result<()> {
        let items = [
            ("buttons", Item::Buttons(&self.result.buttons)),
            ("interfaces", Item::Interfaces(&self.result.interfaces)),
            ("offsets", Item::Offsets(&self.result.offsets)),
        ];

        let mut first_err = items
            .par_iter()
            .filter_map(|(file_name, item)| {
                self.dump_item(file_name, item).err().map(|err| {
                    log::warn!("dump-all write failed: {err}");
                    err
                })
            })
            .reduce_with(|first, _| first);

        let ((schema_res, sdk_res), info_res) = rayon::join(
            || {
                rayon::join(
                    || self.dump_schemas(),
                    || sdk::dump_sdk(self.out_dir, &self.result.schemas, self.build_number),
                )
            },
            || self.dump_info(),
        );
        if let Err(err) = schema_res {
            log::warn!("dump-all write failed: {err}");
            if first_err.is_none() {
                first_err = Some(err);
            }
        }
        if let Err(err) = sdk_res {
            log::warn!("failed to write sdk/: {err}");
            if first_err.is_none() {
                first_err = Some(err.into());
            }
        }
        if let Err(err) = info_res {
            log::warn!("dump-all write failed: {err}");
            if first_err.is_none() {
                first_err = Some(err);
            }
        }

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub fn dump_manifest(&self, extra: &ManifestExtra<'_>) -> Result<()> {
        let class_count: usize = self
            .result
            .schemas
            .values()
            .map(|(classes, _)| classes.len())
            .sum();
        let enum_count: usize = self
            .result
            .schemas
            .values()
            .map(|(_, enums)| enums.len())
            .sum();

        let exists = |relative: &str| self.out_dir.join(relative).exists();
        let mut outputs = serde_json::Map::new();
        let output_flags = [
            ("buttons", exists("buttons.hpp") || exists("buttons.json")),
            ("offsets", exists("offsets.hpp")),
            (
                "interfaces",
                exists("interfaces.hpp") || exists("interfaces/interfaces.hpp"),
            ),
            ("schemas", exists("client_dll.hpp")),
            ("sdk", exists("sdk/sdk.hpp")),
            ("sdk_modules", exists("sdk/modules.hpp")),
            ("sdk_class_headers", exists("sdk/classes")),
            ("schema_index", exists("schema_index.json")),
            ("schema_index_diff", exists("schema_index.diff.json")),
            ("interface_diff", exists("interfaces.diff.json")),
            ("patterns", exists("patterns.json")),
            ("pattern_headers", exists("patterns.hpp")),
            ("pattern_markdown", exists("patterns.md")),
            (
                "pattern_language_outputs",
                exists("patterns.cs") || exists("patterns.rs") || exists("patterns.zig"),
            ),
            ("pattern_diff", exists("patterns.diff.json")),
            ("pattern_repair", exists("patterns.repair.json")),
            ("pattern_repair_patch", exists("patterns.repair.patch.json")),
            ("netvars", exists("netvars/netvars.json")),
            ("convars", exists("convars/convars.json")),
            ("gameevents", exists("gameevents/gameevents.json")),
            ("vtables", exists("vtables.json")),
            ("vtable_headers", exists("vtables.hpp")),
            ("typed_interfaces", exists("interfaces/interfaces.hpp")),
            ("protobufs", exists("protobufs/protobufs.json")),
            ("entity_snapshot", exists("entities/entities.json")),
            ("weapon_vdata", exists("weapons/weapons.json")),
            ("include_tree", exists("macros.hpp") && exists("cs2.hpp")),
            ("schema_headers", exists("schemas")),
            ("engine_structs", exists("engine/engine_structs.json")),
            ("verified_features", exists("verified_features.json")),
            ("impl_entity_system", exists("impl/entity_system.hpp")),
            ("schema_inventory", exists("schemas/info.txt")),
            ("guessed_structs", exists("structs.hpp")),
        ];
        for (key, present) in output_flags {
            outputs.insert(key.to_string(), json!(present));
        }

        let content = serde_json::to_string_pretty(&json!({
            "generated_at": self.timestamp.to_rfc3339(),
            "build_number": self.build_number,
            "backend": extra.backend,
            "load_lib": extra.load_lib,
            "shade_bindings": extra.shade_bindings,
            "steam_inf": extra.steam_inf,
            "module_fingerprints": extra.module_fingerprints,
            "modules_list": self.result.schemas.keys().collect::<Vec<_>>(),
            "missing_schema_modules": extra.missing_schema_modules,
            "pattern_summary": extra.pattern_summary,
            "modules": self.result.schemas.len(),
            "classes": class_count,
            "enums": enum_count,
            "outputs": outputs,
        }))?;

        let path = self.out_dir.join("manifest.json");
        write_staged(&path, content)?;
        Ok(())
    }
    fn dump_info(&self) -> Result<()> {
        let file_path = self.out_dir.join("info.json");

        let build_number = self.build_number;

        let content = serde_json::to_string_pretty(&json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "build_number": build_number,
        }))?;

        fs::write(&file_path, &content)
            .with_context(|| format!("failed to write {}", file_path.display()))?;

        Ok(())
    }

    fn write_item_file(&self, file_name: &str, item: &Item, file_type: &str) -> Result<()> {
        let mut out = String::with_capacity(match item {
            Item::SchemaModule(module) => (module.classes.len().saturating_mul(384)
                + module.enums.len().saturating_mul(128))
            .max(8192),
            _ => 4096,
        });
        let mut fmt = Formatter::new(&mut out, self.indent_size);

        if file_type != "json" {
            self.write_banner(&mut fmt)?;
        }

        item.write(&mut fmt, file_type)?;
        let mut path = self.out_dir.join(file_name);
        path.set_extension(file_type);
        write_staged(&path, out)?;
        Ok(())
    }

    fn dump_item(&self, file_name: &str, item: &Item) -> Result<()> {
        let first_err = self
            .file_types
            .par_iter()
            .filter_map(|file_type| {
                self.write_item_file(file_name, item, file_type)
                    .err()
                    .map(|err| {
                        log::warn!("failed to write {file_name}.{file_type}: {err}");
                        err
                    })
            })
            .reduce_with(|first, _| first);

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn dump_schemas(&self) -> Result<()> {
        // Schema scope names come from the target process. Distinct names can
        // sanitize to the same path (for example foo.dll and foo_dll), and
        // Windows treats case-only differences as the same file. Allocate the
        // stems before entering rayon so every module gets a deterministic,
        // collision-free output path.
        let mut used_stems = std::collections::BTreeSet::new();
        let modules: Vec<_> = self
            .result
            .schemas
            .iter()
            .map(|(module_name, (classes, enums))| {
                (
                    ident::unique_slug(module_name, &mut used_stems),
                    module_name,
                    classes,
                    enums,
                )
            })
            .collect();

        let first_err = modules
            .into_par_iter()
            .filter_map(|(file_name, module_name, classes, enums)| {
                self.dump_item(
                    &file_name,
                    &Item::SchemaModule(schemas::SchemaModule {
                        module_name,
                        classes,
                        enums,
                    }),
                )
                .err()
                .map(|err| {
                    log::warn!("failed to write schema module {module_name}: {err}");
                    err
                })
            })
            .reduce_with(|first, _| first);

        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
    fn write_banner(&self, fmt: &mut Formatter<'_>) -> Result<()> {
        writeln!(fmt, "// Generated using https://github.com/a2x/cs2-dumper")?;
        writeln!(fmt, "// {}\n", self.timestamp)?;

        Ok(())
    }
}

#[inline]
pub(crate) fn zig_ident(input: &str) -> std::borrow::Cow<'_, str> {
    if input.is_empty() {
        return std::borrow::Cow::Borrowed("anonymous");
    }
    if is_zig_identifier(input) && !is_zig_keyword(input) {
        std::borrow::Cow::Borrowed(input)
    } else {
        let escaped = input.replace('\\', "\\\\").replace('"', "\\\"");
        std::borrow::Cow::Owned(format!("@\"{}\"", escaped))
    }
}

/// Preserve generated line-comment structure when schema text is malformed.
pub(crate) fn comment_text(input: &str) -> std::borrow::Cow<'_, str> {
    if !input.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(input);
    }
    std::borrow::Cow::Owned(
        input
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect(),
    )
}

#[inline]
fn is_zig_identifier(input: &str) -> bool {
    let mut chars = input.chars();

    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }

    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[inline]
fn is_zig_keyword(input: &str) -> bool {
    matches!(
        input,
        "addrspace"
            | "align"
            | "allowzero"
            | "and"
            | "anyframe"
            | "anytype"
            | "asm"
            | "async"
            | "await"
            | "break"
            | "callconv"
            | "catch"
            | "comptime"
            | "const"
            | "continue"
            | "defer"
            | "else"
            | "enum"
            | "errdefer"
            | "error"
            | "export"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "inline"
            | "linksection"
            | "noalias"
            | "noinline"
            | "nosuspend"
            | "null"
            | "opaque"
            | "or"
            | "orelse"
            | "packed"
            | "pub"
            | "resume"
            | "return"
            | "struct"
            | "suspend"
            | "switch"
            | "test"
            | "threadlocal"
            | "true"
            | "try"
            | "union"
            | "unreachable"
            | "usingnamespace"
            | "var"
            | "volatile"
            | "while"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{AnalysisResult, Class, ClassField, SchemaMap};

    #[test]
    fn dump_all_writes_slugified_schema_file_from_borrowed_module() {
        let health_offset: i32 = 0x4A8;
        let class_name = "C_TestPawn";
        let field_name = "m_iHealth";
        let module = "client.dll";

        let schemas = SchemaMap::from([(
            module.to_string(),
            (
                vec![Class {
                    name: class_name.to_string(),
                    module_name: module.into(),
                    parent_name: None,
                    size: 0x500,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: field_name.to_string(),
                        type_name: "int32".to_string(),
                        offset: health_offset,
                        metadata: Vec::new(),
                    }],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )]);

        let result = AnalysisResult {
            buttons: Default::default(),
            interfaces: Default::default(),
            offsets: Default::default(),
            schemas,
            vtables: Default::default(),
        };

        let out_dir =
            std::env::temp_dir().join(format!("cs2-dumper-schema-borrow-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);
        let file_types = ["cs", "hpp", "json", "rs", "zig"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let output =
            Output::new(&file_types, 4, &out_dir, &result, Some(12345)).expect("create output dir");
        output.dump_all().expect("shipped dump_all path");

        let hpp = fs::read_to_string(out_dir.join("client_dll.hpp")).expect("client_dll.hpp");
        assert!(
            hpp.contains(class_name),
            "missing class {class_name} in {hpp}"
        );
        assert!(
            hpp.contains(field_name),
            "missing field {field_name} in {hpp}"
        );
        let offset_text = format!("{:#X}", health_offset);
        assert!(
            hpp.contains(&offset_text),
            "missing offset {offset_text} in {hpp}"
        );

        let json_raw =
            fs::read_to_string(out_dir.join("client_dll.json")).expect("client_dll.json");
        let json: serde_json::Value =
            serde_json::from_str(&json_raw).expect("client_dll.json must parse");
        assert_eq!(
            json[module]["classes"][class_name]["fields"][field_name], health_offset,
            "json missing {class_name}.{field_name}={health_offset}: {json_raw}"
        );

        assert!(
            out_dir.join("sdk").join("sdk.hpp").is_file(),
            "default dump_all must still emit sdk/sdk.hpp"
        );

        output
            .dump_manifest(&ManifestExtra {
                backend: "loadlib",
                load_lib: true,
                shade_bindings: &[],
                module_fingerprints: json!({}),
                missing_schema_modules: Vec::new(),
                pattern_summary: None,
                steam_inf: Some(json!({
                    "patch_version": "1.41.7.6",
                    "client_version": 2000885,
                })),
            })
            .expect("dump_manifest");
        let manifest_raw =
            fs::read_to_string(out_dir.join("manifest.json")).expect("manifest.json");
        let manifest: serde_json::Value =
            serde_json::from_str(&manifest_raw).expect("manifest.json must parse");
        assert_eq!(manifest["backend"], "loadlib");
        assert_eq!(manifest["steam_inf"]["patch_version"], "1.41.7.6");
        assert_eq!(manifest["steam_inf"]["client_version"], 2000885);

        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn dump_all_unknown_file_type_still_emits_sdk_and_returns_error() {
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "C_TestPawn".to_string(),
                    module_name: "client.dll".into(),
                    parent_name: None,
                    size: 0x500,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: "m_iHealth".to_string(),
                        type_name: "int32".to_string(),
                        offset: 0x4A8,
                        metadata: Vec::new(),
                    }],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )]);
        let result = AnalysisResult {
            buttons: Default::default(),
            interfaces: Default::default(),
            offsets: Default::default(),
            schemas,
            vtables: Default::default(),
        };
        let out_dir =
            std::env::temp_dir().join(format!("cs2-dumper-unknown-type-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);
        let file_types = vec!["json".to_string(), "lua".to_string()];
        let output =
            Output::new(&file_types, 4, &out_dir, &result, Some(12345)).expect("create output dir");
        output
            .dump_all()
            .expect_err("unknown file type must be a write error, not a panic");
        assert!(
            out_dir.join("sdk").join("sdk.hpp").is_file(),
            "sdk/ must still be written when a language writer fails"
        );
        assert!(
            out_dir.join("client_dll.json").is_file(),
            "a failed language must not skip the others"
        );
        assert!(
            !out_dir.join("client_dll.lua").is_file(),
            "unknown language must not emit a file"
        );
        assert!(
            out_dir.join("info.json").is_file(),
            "info.json is independent of file_types"
        );
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn dump_all_propagates_sdk_write_failures() {
        let out_dir = std::env::temp_dir().join(format!(
            "cs2-dumper-sdk-write-failure-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&out_dir);
        fs::create_dir_all(&out_dir).expect("create output dir");
        // A file where the SDK directory must be created makes only the SDK
        // writer fail; the ordinary root-level writers remain usable.
        fs::write(out_dir.join("sdk"), b"occupied").expect("occupy sdk path");

        let result = AnalysisResult {
            buttons: Default::default(),
            interfaces: Default::default(),
            offsets: Default::default(),
            schemas: Default::default(),
            vtables: Default::default(),
        };
        let file_types = vec!["json".to_string()];
        let output =
            Output::new(&file_types, 4, &out_dir, &result, None).expect("create output writer");

        let error = output
            .dump_all()
            .expect_err("SDK filesystem failures must reach the caller");
        assert!(!error.to_string().is_empty());
        let _ = fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn schema_languages_escape_keyword_identifiers() {
        let schemas = SchemaMap::from([(
            "class.dll".to_string(),
            (
                vec![Class {
                    name: "class".to_string(),
                    module_name: "class.dll".into(),
                    parent_name: None,
                    size: 0x10,
                    alignment: 4,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: "class".to_string(),
                        type_name: "int32\nINJECTED".to_string(),
                        offset: 0,
                        metadata: Vec::new(),
                    }],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                vec![Enum {
                    name: "enum".to_string(),
                    alignment: 4,
                    size: 4,
                    members: vec![EnumMember {
                        name: "operator".to_string(),
                        value: 0,
                    }],
                    flags: Vec::new(),
                }],
            ),
        )]);

        for kind in ["hpp", "cs", "rs"] {
            let mut body = String::new();
            let mut fmt = Formatter::new(&mut body, 4);
            match kind {
                "hpp" => schemas.write_hpp(&mut fmt),
                "cs" => schemas.write_cs(&mut fmt),
                "rs" => schemas.write_rs(&mut fmt),
                _ => unreachable!(),
            }
            .expect("schema writer");
            assert!(
                !body.contains("\nINJECTED"),
                "{kind} allowed comment text to escape its line: {body}"
            );
            if kind == "rs" {
                assert!(body.contains("class: usize") || body.contains("operator ="));
            } else {
                assert!(
                    body.contains("_class"),
                    "{kind} did not escape class: {body}"
                );
                assert!(
                    body.contains("_operator"),
                    "{kind} did not escape enum member: {body}"
                );
            }
        }
    }

    #[test]
    fn schema_languages_disambiguate_sanitized_identifier_collisions() {
        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "foo_bar".to_string(),
                    module_name: "client.dll".into(),
                    parent_name: None,
                    size: 0x10,
                    alignment: 4,
                    metadata: Vec::new(),
                    fields: vec![
                        ClassField {
                            name: "x-y".to_string(),
                            type_name: "int32".to_string(),
                            offset: 0,
                            metadata: Vec::new(),
                        },
                        ClassField {
                            name: "x_y".to_string(),
                            type_name: "int32".to_string(),
                            offset: 4,
                            metadata: Vec::new(),
                        },
                    ],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                vec![Enum {
                    name: "foo-bar".to_string(),
                    alignment: 4,
                    size: 4,
                    members: vec![
                        EnumMember {
                            name: "value-a".to_string(),
                            value: 0,
                        },
                        EnumMember {
                            name: "value_a".to_string(),
                            value: 1,
                        },
                    ],
                    flags: Vec::new(),
                }],
            ),
        )]);

        for kind in ["hpp", "cs", "rs", "zig"] {
            let mut body = String::new();
            let mut fmt = Formatter::new(&mut body, 4);
            match kind {
                "hpp" => schemas.write_hpp(&mut fmt),
                "cs" => schemas.write_cs(&mut fmt),
                "rs" => schemas.write_rs(&mut fmt),
                "zig" => schemas.write_zig(&mut fmt),
                _ => unreachable!(),
            }
            .expect("schema writer");
            assert!(body.contains("foo_bar_2"), "{kind} type collision: {body}");
            assert!(body.contains("x_y_2"), "{kind} field collision: {body}");
            assert!(
                body.contains("value_a_2"),
                "{kind} enum-member collision: {body}"
            );
        }
    }

    #[test]
    fn zig_ident_borrows_plain_identifiers() {
        let name = "dwEntityList";
        let out = zig_ident(name);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
        assert!(zig_ident("align").as_ref().starts_with("@\""));
    }

    #[test]
    fn comment_text_keeps_untrusted_schema_text_on_one_line() {
        let input = format!(
            "C_Test{}#define injected 1{}",
            char::from(10),
            char::from(9)
        );
        assert_eq!(comment_text(&input).as_ref(), "C_Test #define injected 1 ");
        let clean = "C_TestPawn";
        assert!(matches!(comment_text(clean), std::borrow::Cow::Borrowed(_)));
    }
}
