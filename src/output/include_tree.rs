//! Include-tree consumer SDK (from cs2-universal-offsets).
//!
//! Additive to the existing flat multi-language dump: writes a git-submodule
//! friendly header tree so a consumer can `#include "cs2.hpp"` after adding
//! the output directory to their include path.
//!
//! ```text
//! macros.hpp
//! schemas/<module>_dll.hpp
//! impl/entity_system.hpp
//! engine/*.h
//! verified_features.json
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;

use anyhow::Result;
use chrono::Utc;
use rayon::prelude::*;

use crate::analysis::{AnalysisResult, OffsetMap};

use super::amalgamation::{self, EDITOR_MODULES};
use super::comment_text;
use super::engine_structs;
use super::entity_system;
use super::sdk_classes;
use super::verified;

/// Editor/tool-only module stems excluded from the runtime amalgamation.
const EDITOR_MODULE_STEMS: &[&str] = EDITOR_MODULES;

pub fn dump(
    out_dir: &Path,
    result: &AnalysisResult,
    build_number: Option<u32>,
    csgo_input_rva: Option<u32>,
) -> Result<usize> {
    let schemas_dir = out_dir.join("schemas");
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(&schemas_dir)?;

    let ts = Utc::now().to_rfc3339();
    let module_data =
        sdk_classes::render_module_headers(&result.schemas, &result.buttons, build_number, &ts);

    let mut macros = sdk_classes::render_macros_header();
    let mut namespace_blocks: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut enum_underlying: BTreeMap<(&str, &str), &str> = BTreeMap::new();

    let module_ns_set: BTreeSet<&str> = module_data
        .iter()
        .map(|header| header.namespace.as_str())
        .collect();

    for header in &module_data {
        for (name, underlying) in &header.enum_defs {
            enum_underlying.insert((header.namespace.as_str(), name.as_str()), underlying);
        }
        for (owner_ns, ty) in &header.foreign_types {
            namespace_blocks
                .entry(owner_ns.as_ref())
                .or_default()
                .insert(ty.as_ref());
        }
    }

    macros.push_str(
        "\n// ============================================================================\n",
    );
    macros.push_str("// Cross-module forward declarations (auto-generated)\n");
    macros.push_str("// These provide declaration-only stubs for types referenced across\n");
    macros.push_str("// different module namespaces so headers can be included in any order.\n\n");

    for (ns, types_set) in &namespace_blocks {
        let _ = writeln!(macros, "namespace {} {{", ns);
        for ty in types_set {
            if let Some(under) = enum_underlying.get(&(*ns, *ty)) {
                let _ = writeln!(macros, "    enum class {} : {};", ty, under);
            } else {
                let _ = writeln!(macros, "    class {};", ty);
            }
        }
        macros.push_str("}\n\n");
    }

    emit_auto_forward_decls(&mut macros, &module_data, &module_ns_set);

    let module_stems: Vec<&str> = module_data
        .iter()
        .filter(|header| !header.is_empty())
        .filter_map(|header| header.file_name.strip_suffix(".hpp"))
        .collect();

    let impl_dir = out_dir.join("impl");
    fs::create_dir_all(&impl_dir)?;
    let engine_dir = out_dir.join("engine");
    fs::create_dir_all(&engine_dir)?;
    let offsets_dir = out_dir.join("offsets");
    fs::create_dir_all(&offsets_dir)?;
    let patterns_dir = out_dir.join("patterns");
    fs::create_dir_all(&patterns_dir)?;

    let ((macros_res, headers_res), (catalog_res, (umbrella_res, extras_res))) = rayon::join(
        || {
            rayon::join(
                || fs::write(out_dir.join("macros.hpp"), &macros),
                || {
                    module_data.par_iter().try_for_each(|header| {
                        if header.is_empty() {
                            Ok(())
                        } else {
                            fs::write(schemas_dir.join(&header.file_name), &header.body)
                        }
                    })
                },
            )
        },
        || {
            rayon::join(
                || write_schema_catalog(&schemas_dir, result),
                || {
                    rayon::join(
                        || {
                            write_include_tree_umbrella(
                                out_dir,
                                &offsets_dir,
                                &patterns_dir,
                                &module_stems,
                                build_number,
                            )
                        },
                        || {
                            write_include_tree_extras(
                                out_dir,
                                &impl_dir,
                                &engine_dir,
                        result,
                                build_number,
                                csgo_input_rva,
                            )
                        },
                    )
                },
            )
        },
    );
    macros_res?;
    headers_res?;
    catalog_res?;
    umbrella_res?;
    extras_res?;

    Ok(module_stems.len())
}

/// Only write an empty amalgamation when `cs2.hpp` is missing or already empty.
/// A later include-tree error must not clobber a non-empty umbrella.
pub fn write_empty_cs2_if_missing(
    out_dir: &Path,
    build_number: Option<u32>,
) -> std::io::Result<()> {
    let path = out_dir.join("cs2.hpp");
    if path.is_file() {
        match fs::metadata(&path) {
            Ok(meta) if meta.len() > 0 => return Ok(()),
            _ => {}
        }
    }
    fs::write(path, amalgamation::render_hpp(&[], build_number))
}

fn write_schema_catalog(schemas_dir: &Path, result: &AnalysisResult) -> Result<()> {
    let mut info = String::from("// Schema module inventory\n");
    let mut modules: Vec<_> = result.schemas.iter().collect();
    modules.sort_by(|a, b| a.0.cmp(b.0));
    for (module, (classes, enums)) in modules {
        let _ = writeln!(
            info,
            "// {}: {} classes, {} enums",
            comment_text(module),
            classes.len(),
            enums.len()
        );
        for class in classes {
            let _ = writeln!(
                info,
                "//   {} ({} fields)",
                comment_text(&class.name),
                class.fields.len()
            );
        }
    }
    fs::write(schemas_dir.join("info.txt"), info)?;
    write_optional_json(
        &schemas_dir.join("schemas.json"),
        sdk_classes::render_schemas_json(&result.schemas),
    )
}

fn write_include_tree_extras(
    out_dir: &Path,
    impl_dir: &Path,
    engine_dir: &Path,
    result: &AnalysisResult,
    build_number: Option<u32>,
    csgo_input_rva: Option<u32>,
) -> Result<()> {
    fs::write(
        impl_dir.join("entity_system.hpp"),
        entity_system::render_impl_hpp(&result.offsets, build_number),
    )?;
    write_optional_json(
        &engine_dir.join("engine_structs.json"),
        engine_structs::render_json(build_number, csgo_input_rva),
    )?;
    engine_structs::ENGINE_STRUCTS
        .par_iter()
        .try_for_each(|s| {
            let live = if s.name == "CCSGOInput" {
                csgo_input_rva
            } else {
                None
            };
            fs::write(
                engine_dir.join(format!("{}.h", s.name.to_ascii_lowercase())),
                engine_structs::render_header(s, build_number, live),
            )
        })?;
    write_optional_json(
        &out_dir.join("verified_features.json"),
        verified::render_json(build_number, Some(&result.schemas)),
    )
}

fn write_include_tree_umbrella(
    out_dir: &Path,
    offsets_dir: &Path,
    patterns_dir: &Path,
    module_stems: &[&str],
    build_number: Option<u32>,
) -> Result<()> {
    let (copy_res, body) = rayon::join(
        || -> Result<()> {
            let merged = out_dir.join("offsets_merged.hpp");
            let legacy = out_dir.join("offsets.hpp");
            if merged.is_file() {
                fs::copy(&merged, offsets_dir.join("offsets.hpp"))?;
            } else if legacy.is_file() {
                fs::copy(&legacy, offsets_dir.join("offsets.hpp"))?;
            }

            let patterns_hpp = out_dir.join("patterns.hpp");
            if patterns_hpp.is_file() {
                fs::copy(&patterns_hpp, patterns_dir.join("patterns.hpp"))?;
            }

            let vtables_hpp = out_dir.join("vtables.hpp");
            if vtables_hpp.is_file() {
                fs::copy(&vtables_hpp, offsets_dir.join("vtables.hpp"))?;
            }
            Ok(())
        },
        || amalgamation::render_hpp(module_stems, build_number),
    );
    copy_res?;
    fs::write(out_dir.join("cs2.hpp"), body)?;
    Ok(())
}

fn write_optional_json(path: &Path, rendered: Result<String, serde_json::Error>) -> Result<()> {
    let body = rendered?;
    fs::write(path, body)?;
    Ok(())
}

fn is_builtin_type(t: &str) -> bool {
    matches!(
        t,
        "bool"
            | "char"
            | "double"
            | "float"
            | "void"
            | "int"
            | "short"
            | "long"
            | "unsigned"
            | "signed"
            | "wchar_t"
            | "float32"
            | "fltx4"
            | "char8_t"
            | "char16_t"
            | "char32_t"
            | "size_t"
            | "std"
            | "const"
            | "volatile"
    )
}

fn collect_defined<'a>(text: &'a str, set: &mut BTreeSet<&'a str>) {
    for kw in [
        "class ",
        "struct ",
        "enum class ",
        "enum ",
        "using ",
        "typedef ",
    ] {
        let mut from = 0;
        while let Some(p) = text[from..].find(kw) {
            let mut i = from + p + kw.len();
            let b = text.as_bytes();
            while i < text.len() && (b[i] as char).is_ascii_whitespace() {
                i += 1;
            }
            let start = i;
            while i < text.len() {
                let c = b[i] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    i += 1;
                } else {
                    break;
                }
            }
            if i > start {
                set.insert(&text[start..i]);
            }
            from = from + p + kw.len();
        }
    }
}

fn emit_auto_forward_decls(
    macros: &mut String,
    module_data: &[sdk_classes::ModuleHeader],
    module_ns_set: &BTreeSet<&str>,
) {
    let is_editor = |fname: &str| EDITOR_MODULE_STEMS.iter().any(|e| fname.starts_with(e));

    let (mut plain, templated, qual) = {
        let mut parsed = BTreeSet::<&str>::new();
        collect_defined(macros, &mut parsed);
        let is_defined = |name: &str| {
            parsed.contains(name)
                || module_data.iter().any(|header| {
                    !is_editor(&header.file_name)
                        && (header.class_names.contains(name)
                            || header.enum_defs.contains_key(name))
                })
        };

        let mut plain = BTreeSet::<&str>::new();
        let mut templated = BTreeSet::<&str>::new();
        let mut qual: BTreeMap<&str, BTreeMap<&str, bool>> = BTreeMap::new();

        for header in module_data {
            if is_editor(&header.file_name) {
                continue;
            }
            for targ in &header.schema_field_types {
                extract_type_idents(
                    targ,
                    is_defined,
                    module_ns_set,
                    &mut plain,
                    &mut templated,
                    &mut qual,
                );
            }
        }
        (plain, templated, qual)
    };
    for t in templated.iter() {
        plain.remove(t);
    }

    if plain.is_empty() && templated.is_empty() && qual.is_empty() {
        return;
    }

    macros.push_str("// Auto-generated: forward declarations for types the runtime schemas\n");
    macros.push_str("// reference but that aren't defined in any included header.\n");
    for t in &templated {
        let _ = writeln!(macros, "template <class...> class {};", t);
    }
    for t in &plain {
        let _ = writeln!(macros, "class {};", t);
    }
    for (ns, names) in &qual {
        // `ns` can be more than one segment deep (`A::B` for a mention of
        // `A::B::C`), so open each one. Nested braces rather than the C++17
        // `namespace A::B` spelling, to match the standard the rest of the
        // generated headers are written against.
        let segments: Vec<&str> = ns.split("::").filter(|s| !s.is_empty()).collect();
        for segment in &segments {
            let _ = write!(macros, "namespace {} {{ ", segment);
        }
        for (name, is_t) in names {
            if *is_t {
                let _ = write!(macros, "template <class...> class {}; ", name);
            } else {
                let _ = write!(macros, "class {}; ", name);
            }
        }
        for _ in 0..segments.len() {
            macros.push_str("} ");
        }
        macros.push('\n');
    }
    macros.push('\n');
}

fn extract_type_idents<'a>(
    arg: &'a str,
    is_defined: impl Fn(&str) -> bool,
    module_ns_set: &BTreeSet<&str>,
    plain: &mut BTreeSet<&'a str>,
    templated: &mut BTreeSet<&'a str>,
    qual: &mut BTreeMap<&'a str, BTreeMap<&'a str, bool>>,
) {
    let bytes = arg.as_bytes();
    let mut i = 0;
    while i < arg.len() {
        let c = bytes[i] as char;
        if c.is_ascii_alphabetic() || c == '_' || c == ':' {
            let start = i;
            while i < arg.len() {
                let d = bytes[i] as char;
                if d.is_ascii_alphanumeric() || d == '_' || d == ':' {
                    i += 1;
                } else {
                    break;
                }
            }
            let tok = arg[start..i].trim_matches(':');
            if tok.is_empty() {
                continue;
            }
            let mut j = i;
            while j < arg.len() && (bytes[j] as char).is_ascii_whitespace() {
                j += 1;
            }
            let is_t = j < arg.len() && bytes[j] as char == '<';

            if let Some((ns, name)) = tok.rsplit_once("::") {
                // Key on the whole qualifier. Keeping only its first segment
                // declared `A::C` for a mention of `A::B::C`: the type that
                // actually needed declaring stayed undeclared, and the invented
                // name clashes with whatever `A::C` really is — a redeclaration
                // error when macros_base.hpp already has it as an enum.
                let root = ns.split("::").next().unwrap_or(ns);
                if !is_builtin_type(root) && !module_ns_set.contains(root) && !is_defined(name) {
                    let e = qual.entry(ns).or_default();
                    let v = e.entry(name).or_insert(false);
                    *v = *v || is_t;
                }
            } else if !is_builtin_type(tok) && !is_defined(tok) {
                if is_t {
                    templated.insert(tok);
                } else {
                    plain.insert(tok);
                }
            }
        } else {
            i += 1;
        }
    }
}

/// Prefer a live `dwCSGOInput` / `pCSGOInput` RVA over a baked engine-struct constant.
pub fn live_csgo_input_rva(offsets: &OffsetMap, pattern_rva: Option<u64>) -> Option<u32> {
    offsets
        .iter()
        .find(|(module, _)| module.eq_ignore_ascii_case("client.dll"))
        .and_then(|(_, module)| {
            module
                .iter()
                .find(|(symbol, _)| {
                    symbol.eq_ignore_ascii_case("dwCSGOInput")
                        || symbol.eq_ignore_ascii_case("pCSGOInput")
                })
                .map(|(_, rva)| *rva)
        })
        .or_else(|| pattern_rva.and_then(|value| u32::try_from(value).ok()))
}

#[cfg(test)]
mod tests {
    use super::{collect_defined, extract_type_idents, live_csgo_input_rva};
    use crate::analysis::{AnalysisResult, OffsetMap};
    use std::collections::{BTreeMap, BTreeSet};

    /// A multi-level qualified name used to be recorded under only the first
    /// segment, so `A::B::C` produced `namespace A { class C; }` — the type that
    /// needed declaring stayed undeclared, and `A::C` was invented out of thin
    /// air (a redeclaration error whenever `A::C` already exists as something
    /// else).
    #[test]
    fn a_multi_level_qualified_name_keeps_its_whole_qualifier() {
        let mut plain = BTreeSet::new();
        let mut templated = BTreeSet::new();
        let mut qual: BTreeMap<&str, BTreeMap<&str, bool>> = BTreeMap::new();
        let module_ns_set = BTreeSet::new();

        extract_type_idents(
            "A::B::C",
            |_| false,
            &module_ns_set,
            &mut plain,
            &mut templated,
            &mut qual,
        );

        assert!(
            qual.contains_key("A::B"),
            "the qualifier must be kept whole, got {:?}",
            qual.keys().collect::<Vec<_>>()
        );
        assert_eq!(qual["A::B"].keys().collect::<Vec<_>>(), vec![&"C"]);
        assert!(
            !qual.contains_key("A"),
            "no bare `A::C` may be invented, got {:?}",
            qual.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn prefers_canonical_dw_csgo_input() {
        let mut client = BTreeMap::new();
        client.insert("dwCSGOInput".into(), 0x111u32);
        let mut offsets = OffsetMap::new();
        offsets.insert("client.dll".into(), client);
        assert_eq!(live_csgo_input_rva(&offsets, Some(0x222)), Some(0x111));
    }

    #[test]
    fn live_csgo_input_rva_matches_module_and_symbol_case_insensitively() {
        let mut client = BTreeMap::new();
        client.insert("DWCSGOINPUT".into(), 0x111u32);
        let mut offsets = OffsetMap::new();
        offsets.insert("CLIENT.DLL".into(), client);
        assert_eq!(live_csgo_input_rva(&offsets, Some(0x222)), Some(0x111));
    }

    #[test]
    fn falls_back_to_pattern_rva() {
        assert_eq!(
            live_csgo_input_rva(&OffsetMap::new(), Some(0xABC)),
            Some(0xABC)
        );
        assert_eq!(live_csgo_input_rva(&OffsetMap::new(), None), None);
    }

    #[test]
    fn include_tree_failure_does_not_overwrite_a_nonempty_cs2_hpp() {
        let dir = std::env::temp_dir().join(format!("cs2-dumper-cs2-hpp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("cs2.hpp");
        std::fs::write(&path, "// keep me\n#include \"macros.hpp\"\n").expect("seed");
        super::write_empty_cs2_if_missing(&dir, Some(1)).expect("fallback");
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(
            body.contains("keep me"),
            "non-empty cs2.hpp must survive a failed include-tree: {body}"
        );
        std::fs::write(&path, []).expect("empty");
        super::write_empty_cs2_if_missing(&dir, Some(1)).expect("empty fallback");
        let replaced = std::fs::read_to_string(&path).expect("replaced");
        assert!(
            replaced.contains("single-include amalgamation"),
            "empty cs2.hpp may be replaced: {replaced}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_propagates_catalog_and_extra_write_failures() {
        for (case, blocked) in [
            ("catalog", "schemas/info.txt"),
            ("extras", "engine/engine_structs.json"),
        ] {
            let dir = std::env::temp_dir().join(format!(
                "cs2-dumper-include-tree-{case}-failure-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join(blocked)).expect("occupy output file path");
            let result = AnalysisResult {
                buttons: Default::default(),
                interfaces: Default::default(),
                offsets: Default::default(),
                schemas: Default::default(),
                vtables: Default::default(),
            };
            super::dump(&dir, &result, None, None)
                .expect_err("include-tree component write failure must propagate");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn collect_defined_borrows_idents_from_macros_text() {
        let text = "class Foo;\nstruct Bar;\nenum class Baz : int;";
        let mut set = BTreeSet::new();
        collect_defined(text, &mut set);
        assert!(set.contains("Foo"));
        assert!(set.contains("Bar"));
        assert!(set.contains("Baz"));
        let foo = *set.get("Foo").expect("Foo");
        assert!(std::ptr::eq(
            foo.as_ptr(),
            text.find("Foo").map(|i| &text[i..]).unwrap().as_ptr()
        ));
    }
}
