use std::fmt::{self, Write};
use std::fs;
use std::path::Path;

use anyhow::Result;

use chrono::{DateTime, Utc};

use memflow::prelude::v1::*;

use serde_json::json;

use formatter::Formatter;

use crate::analysis::*;

pub mod amalgamation;
mod buttons;
pub mod convars;
pub mod engine_structs;
pub mod entities;
pub mod entity_system;
mod formatter;
pub mod gameevents;
pub mod guessed_structs;
pub mod ident;
pub mod include_tree;
pub mod interface_classes;
pub mod interface_diff;
mod interfaces;
pub mod netvars;
mod offsets;
pub mod pattern_diff;
pub mod protobufs;
pub mod schema_diff;
pub mod schema_index;
mod schemas;
mod sdk;
pub mod sdk_classes;
pub mod verified;
pub mod vtables;
pub mod weapons;

enum Item<'a> {
    Buttons(&'a ButtonMap),
    Interfaces(&'a InterfaceMap),
    Offsets(&'a OffsetMap),
    Schemas(&'a SchemaMap),
}

impl<'a> Item<'a> {
    fn write(&self, fmt: &mut Formatter<'a>, file_type: &str) -> fmt::Result {
        match file_type {
            "cs" => self.write_cs(fmt),
            "hpp" => self.write_hpp(fmt),
            "json" => self.write_json(fmt),
            "rs" => self.write_rs(fmt),
            "zig" => self.write_zig(fmt),
            _ => unimplemented!(),
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
            Item::Schemas(schemas) => schemas.write_cs(fmt),
        }
    }

    fn write_hpp(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_hpp(fmt),
            Item::Interfaces(ifaces) => ifaces.write_hpp(fmt),
            Item::Offsets(offsets) => offsets.write_hpp(fmt),
            Item::Schemas(schemas) => schemas.write_hpp(fmt),
        }
    }

    fn write_json(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_json(fmt),
            Item::Interfaces(ifaces) => ifaces.write_json(fmt),
            Item::Offsets(offsets) => offsets.write_json(fmt),
            Item::Schemas(schemas) => schemas.write_json(fmt),
        }
    }

    fn write_rs(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_rs(fmt),
            Item::Interfaces(ifaces) => ifaces.write_rs(fmt),
            Item::Offsets(offsets) => offsets.write_rs(fmt),
            Item::Schemas(schemas) => schemas.write_rs(fmt),
        }
    }

    fn write_zig(&self, fmt: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Item::Buttons(buttons) => buttons.write_zig(fmt),
            Item::Interfaces(ifaces) => ifaces.write_zig(fmt),
            Item::Offsets(offsets) => offsets.write_zig(fmt),
            Item::Schemas(schemas) => schemas.write_zig(fmt),
        }
    }
}

pub struct Output<'a> {
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
        fs::create_dir_all(&out_dir)?;

        Ok(Self {
            file_types,
            indent_size,
            out_dir,
            result,
            build_number,
            timestamp: Utc::now(),
        })
    }

    pub fn dump_all<P: MemoryView + Process>(&self, process: &mut P) -> Result<()> {
        let items = [
            ("buttons", Item::Buttons(&self.result.buttons)),
            ("interfaces", Item::Interfaces(&self.result.interfaces)),
            ("offsets", Item::Offsets(&self.result.offsets)),
        ];

        for (file_name, item) in &items {
            self.dump_item(file_name, item)?;
        }

        self.dump_schemas()?;
        sdk::dump_sdk(self.out_dir, &self.result.schemas, self.build_number)?;
        self.dump_info(process)?;

        Ok(())
    }

    pub fn dump_manifest(&self) -> Result<()> {
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
        let content = serde_json::to_string_pretty(&json!({
            "generated_at": self.timestamp.to_rfc3339(),
            "modules": self.result.schemas.len(),
            "classes": class_count,
            "enums": enum_count,
            "outputs": {
                "buttons": exists("buttons.hpp") || exists("buttons.json"),
                "offsets": exists("offsets.hpp"),
                "interfaces": exists("interfaces.hpp") || exists("interfaces/interfaces.hpp"),
                "schemas": exists("client_dll.hpp"),
                "sdk": exists("sdk/sdk.hpp"),
                "schema_index": exists("schema_index.json"),
                "schema_index_diff": exists("schema_index.diff.json"),
                "interface_diff": exists("interfaces.diff.json"),
                "sdk_modules": exists("sdk/modules.hpp"),
                "sdk_class_headers": exists("sdk/classes"),
                "patterns": exists("patterns.json"),
                "pattern_headers": exists("patterns.hpp"),
                "pattern_markdown": exists("patterns.md"),
                "pattern_language_outputs": exists("patterns.cs") || exists("patterns.rs") || exists("patterns.zig"),
                "pattern_diff": exists("patterns.diff.json"),
                "pattern_repair": exists("patterns.repair.json"),
                "pattern_repair_patch": exists("patterns.repair.patch.json"),
                "pattern_summary": exists("patterns.json"),
                "netvars": exists("netvars/netvars.json"),
                "convars": exists("convars/convars.json"),
                "gameevents": exists("gameevents/gameevents.json"),
                "vtables": exists("vtables.json"),
                "vtable_headers": exists("vtables.hpp"),
                "typed_interfaces": exists("interfaces/interfaces.hpp"),
                "protobufs": exists("protobufs/protobufs.json"),
                "entity_snapshot": exists("entities/entities.json"),
                "weapon_vdata": exists("weapons/weapons.json"),
                "include_tree": exists("macros.hpp") && exists("cs2.hpp"),
                "schema_headers": exists("schemas"),
                "engine_structs": exists("engine/engine_structs.json"),
                "verified_features": exists("verified_features.json"),
                "impl_entity_system": exists("impl/entity_system.hpp"),
                "schema_inventory": exists("schemas/info.txt"),
                "guessed_structs": exists("structs.hpp"),
            },
        }))?;

        fs::write(self.out_dir.join("manifest.json"), content)?;
        Ok(())
    }
    fn dump_info<P: MemoryView + Process>(&self, process: &mut P) -> Result<()> {
        let file_path = self.out_dir.join("info.json");

        let build_number = self.build_number.or_else(|| {
            self.result
                .offsets
                .iter()
                .find_map(|(module_name, offsets)| {
                    let module = process.module_by_name(module_name).ok()?;
                    let offset = offsets.iter().find(|(name, _)| *name == "dwBuildNumber")?.1;

                    process.read::<u32>(module.base + offset).data_part().ok()
                })
        });

        let content = serde_json::to_string_pretty(&json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "build_number": build_number,
        }))?;

        fs::write(&file_path, &content)?;

        Ok(())
    }

    fn dump_item(&self, file_name: &str, item: &Item) -> Result<()> {
        for file_type in self.file_types {
            let mut out = String::new();
            let mut fmt = Formatter::new(&mut out, self.indent_size);

            if file_type != "json" {
                self.write_banner(&mut fmt)?;
            }

            item.write(&mut fmt, file_type)?;

            let file_path = self.out_dir.join(format!("{}.{}", file_name, file_type));

            fs::write(&file_path, out)?;
        }

        Ok(())
    }

    fn dump_schemas(&self) -> Result<()> {
        for (module_name, (classes, enums)) in &self.result.schemas {
            let map = SchemaMap::from([(module_name.clone(), (classes.clone(), enums.clone()))]);

            self.dump_item(&slugify(&module_name), &Item::Schemas(&map))?;
        }

        Ok(())
    }

    fn write_banner(&self, fmt: &mut Formatter<'_>) -> Result<()> {
        writeln!(fmt, "// Generated using https://github.com/a2x/cs2-dumper")?;
        writeln!(fmt, "// {}\n", self.timestamp)?;

        Ok(())
    }
}

#[inline]
fn slugify(input: &str) -> String {
    input.replace(|c: char| !c.is_alphanumeric(), "_")
}

#[inline]
fn zig_ident(input: &str) -> String {
    if is_zig_identifier(input) && !is_zig_keyword(input) {
        input.to_string()
    } else {
        let escaped = input.replace('\\', "\\\\").replace('"', "\\\"");

        format!("@\"{}\"", escaped)
    }
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
