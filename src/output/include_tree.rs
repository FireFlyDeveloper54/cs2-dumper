//! Include-tree consumer SDK (from cs2-universal-offsets).
//!
//! Additive to the existing flat multi-language dump: writes a git-submodule
//! friendly header tree so a consumer can `#include "cs2.hpp"` after adding
//! the output directory to their include path.
//!
//!     macros.hpp
//!     schemas/<module>_dll.hpp
//!     impl/entity_system.hpp
//!     engine/*.h
//!     verified_features.json

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::Result;
use chrono::Utc;

use crate::analysis::{AnalysisResult, OffsetMap};

use super::amalgamation::{self, EDITOR_MODULES};
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
) -> Result<Vec<String>> {
    let schemas_dir = out_dir.join("schemas");
    fs::create_dir_all(out_dir)?;
    fs::create_dir_all(&schemas_dir)?;

    let ts = Utc::now().to_rfc3339();
    let buttons: BTreeMap<String, u64> = result
        .buttons
        .iter()
        .map(|(name, value)| (name.clone(), *value as u64))
        .collect();

    let module_data =
        sdk_classes::render_module_headers(&result.schemas, &buttons, build_number, &ts);

    let mut macros = sdk_classes::render_macros_header();
    let mut namespace_blocks: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut enum_underlying: BTreeMap<(String, String), String> = BTreeMap::new();

    let parse_mod_ns = |body: &str| -> Option<String> {
        let p = body.find("\nnamespace ")?;
        let s = p + "\nnamespace ".len();
        let b = body.as_bytes();
        let mut e = s;
        while e < body.len() {
            let c = b[e] as char;
            if c.is_whitespace() || c == '{' {
                break;
            }
            e += 1;
        }
        Some(body[s..e].to_string())
    };
    let module_ns_set: BTreeSet<String> = module_data
        .iter()
        .filter_map(|(_, body)| parse_mod_ns(body))
        .collect();

    for (_file_name, body) in &module_data {
        let mut current_ns = String::new();
        if let Some(ns_pos) = body.find("\nnamespace ") {
            let ns_start = ns_pos + "\nnamespace ".len();
            let mut ns_end = ns_start;
            while ns_end < body.len() {
                let c = body.as_bytes()[ns_end] as char;
                if c.is_whitespace() || c == '{' {
                    break;
                }
                ns_end += 1;
            }
            current_ns = body[ns_start..ns_end].to_string();
        }

        let mut scan_idx = 0usize;
        let bytes = body.as_bytes();
        while let Some(found) = body[scan_idx..].find("enum class") {
            let pos = scan_idx + found;
            let mut name_start = pos + "enum class".len();
            while name_start < bytes.len() && (bytes[name_start] as char).is_whitespace() {
                name_start += 1;
            }
            let mut name_end = name_start;
            while name_end < bytes.len() {
                let c = bytes[name_end] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    name_end += 1;
                } else {
                    break;
                }
            }
            if name_end > name_start {
                let name = body[name_start..name_end].trim().to_string();
                let rest = &body[name_end..];
                if let Some(colon_rel) = rest.find(':') {
                    if let Some(brace_rel) = rest.find('{') {
                        if brace_rel > colon_rel {
                            let underlying = rest[colon_rel + 1..brace_rel].trim().to_string();
                            enum_underlying.insert((current_ns.clone(), name), underlying);
                        }
                    }
                }
            }
            scan_idx = pos + 1;
        }

        let b2 = body.as_bytes();
        let mut search_idx = 0usize;
        while let Some(found) = body[search_idx..].find("::") {
            let ns_start = search_idx + found + 2;
            let mut ns_end = ns_start;
            while ns_end < body.len() {
                let c = b2[ns_end] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    ns_end += 1;
                } else {
                    break;
                }
            }
            let ns = &body[ns_start..ns_end];
            if ns_end > ns_start
                && ns_end + 2 <= body.len()
                && &body[ns_end..ns_end + 2] == "::"
                && module_ns_set.contains(ns)
            {
                let type_start = ns_end + 2;
                let mut type_end = type_start;
                while type_end < body.len() {
                    let c = b2[type_end] as char;
                    if c.is_ascii_alphanumeric() || c == '_' {
                        type_end += 1;
                    } else {
                        break;
                    }
                }
                if type_end > type_start {
                    let ty = &body[type_start..type_end];
                    namespace_blocks
                        .entry(ns.to_string())
                        .or_default()
                        .insert(ty.to_string());
                }
                search_idx = type_end;
            } else {
                search_idx = ns_start;
            }
        }
    }

    macros.push_str("\n// ============================================================================\n");
    macros.push_str("// Cross-module forward declarations (auto-generated)\n");
    macros.push_str("// These provide declaration-only stubs for types referenced across\n");
    macros.push_str("// different module namespaces so headers can be included in any order.\n\n");

    for (ns, types_set) in &namespace_blocks {
        macros.push_str(&format!("namespace {} {{\n", ns));
        for ty in types_set {
            if let Some(under) = enum_underlying.get(&(ns.clone(), ty.clone())) {
                macros.push_str(&format!("    enum class {} : {};\n", ty, under));
            } else {
                macros.push_str(&format!("    class {};\n", ty));
            }
        }
        macros.push_str("}\n\n");
    }

    emit_auto_forward_decls(&mut macros, &module_data, &module_ns_set);
    fs::write(out_dir.join("macros.hpp"), macros)?;

    let mut module_stems = Vec::new();
    for (file_name, body) in module_data {
        let is_empty = !body.contains("class ") && !body.contains("enum class ");
        if is_empty {
            continue;
        }
        fs::write(schemas_dir.join(&file_name), body)?;
        if let Some(stem) = file_name.strip_suffix(".hpp") {
            module_stems.push(stem.to_string());
        }
    }

    // schema-dumper-no-process: per-scope inventory for humans.
    let mut info = String::from("// Schema module inventory\n");
    let mut modules: Vec<_> = result.schemas.iter().collect();
    modules.sort_by(|a, b| a.0.cmp(b.0));
    for (module, (classes, enums)) in modules {
        info.push_str(&format!(
            "// {module}: {} classes, {} enums\n",
            classes.len(),
            enums.len()
        ));
        for class in classes {
            info.push_str(&format!(
                "//   {} ({} fields)\n",
                class.name,
                class.fields.len()
            ));
        }
    }
    fs::write(schemas_dir.join("info.txt"), info)?;

    fs::write(
        schemas_dir.join("schemas.json"),
        sdk_classes::render_schemas_json(&result.schemas),
    )?;

    let impl_dir = out_dir.join("impl");
    fs::create_dir_all(&impl_dir)?;
    fs::write(
        impl_dir.join("entity_system.hpp"),
        entity_system::render_impl_hpp(&result.offsets, build_number),
    )?;

    let engine_dir = out_dir.join("engine");
    fs::create_dir_all(&engine_dir)?;
    fs::write(
        engine_dir.join("engine_structs.json"),
        engine_structs::render_json(build_number, csgo_input_rva),
    )?;
    for s in engine_structs::ENGINE_STRUCTS {
        let live = if s.name == "CCSGOInput" {
            csgo_input_rva
        } else {
            None
        };
        fs::write(
            engine_dir.join(format!("{}.h", s.name.to_ascii_lowercase())),
            engine_structs::render_header(s, build_number, live),
        )?;
    }

    fs::write(
        out_dir.join("verified_features.json"),
        verified::render_json(build_number, Some(&result.schemas)),
    )?;

    // Prefer the merged offset header for the include tree (canonical +
    // pattern + interface RVAs). Fall back to the legacy offsets.hpp.
    let offsets_dir = out_dir.join("offsets");
    fs::create_dir_all(&offsets_dir)?;
    let merged = out_dir.join("offsets_merged.hpp");
    let legacy = out_dir.join("offsets.hpp");
    if merged.is_file() {
        fs::copy(&merged, offsets_dir.join("offsets.hpp"))?;
    } else if legacy.is_file() {
        fs::copy(&legacy, offsets_dir.join("offsets.hpp"))?;
    }

    let patterns_dir = out_dir.join("patterns");
    fs::create_dir_all(&patterns_dir)?;
    let patterns_hpp = out_dir.join("patterns.hpp");
    if patterns_hpp.is_file() {
        fs::copy(&patterns_hpp, patterns_dir.join("patterns.hpp"))?;
    }

    let vtables_hpp = out_dir.join("vtables.hpp");
    if vtables_hpp.is_file() {
        fs::copy(&vtables_hpp, offsets_dir.join("vtables.hpp"))?;
    }

    fs::write(
        out_dir.join("cs2.hpp"),
        amalgamation::render_hpp(&module_stems, build_number),
    )?;

    Ok(module_stems)
}

#[cfg(test)]
mod tests {
    use super::live_csgo_input_rva;
    use crate::analysis::OffsetMap;
    use std::collections::BTreeMap;

    #[test]
    fn prefers_canonical_dw_csgo_input() {
        let mut client = BTreeMap::new();
        client.insert("dwCSGOInput".into(), 0x111u32);
        let mut offsets = OffsetMap::new();
        offsets.insert("client.dll".into(), client);
        assert_eq!(live_csgo_input_rva(&offsets, Some(0x222)), Some(0x111));
    }

    #[test]
    fn falls_back_to_pattern_rva() {
        assert_eq!(live_csgo_input_rva(&OffsetMap::new(), Some(0xABC)), Some(0xABC));
        assert_eq!(live_csgo_input_rva(&OffsetMap::new(), None), None);
    }
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

fn collect_defined(text: &str, set: &mut BTreeSet<String>) {
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
                set.insert(text[start..i].to_string());
            }
            from = from + p + kw.len();
        }
    }
}

fn emit_auto_forward_decls(
    macros: &mut String,
    module_data: &[(String, String)],
    module_ns_set: &BTreeSet<String>,
) {
    let is_editor = |fname: &str| EDITOR_MODULE_STEMS.iter().any(|e| fname.starts_with(e));

    let mut defined = BTreeSet::<String>::new();
    collect_defined(macros, &mut defined);
    for (fname, body) in module_data {
        if is_editor(fname) {
            continue;
        }
        collect_defined(body, &mut defined);
    }

    let mut plain = BTreeSet::<String>::new();
    let mut templated = BTreeSet::<String>::new();
    let mut qual: BTreeMap<String, BTreeMap<String, bool>> = BTreeMap::new();

    for (fname, body) in module_data {
        if is_editor(fname) {
            continue;
        }
        let bytes = body.as_bytes();
        let mut from = 0;
        const TAG: &str = "SCHEMA_FIELD(";
        while let Some(p) = body[from..].find(TAG) {
            let mut i = from + p + TAG.len();
            let tstart = i;
            let mut depth = 0i32;
            while i < body.len() {
                match bytes[i] as char {
                    '<' => depth += 1,
                    '>' => depth -= 1,
                    ',' if depth <= 0 => break,
                    _ => {}
                }
                i += 1;
            }
            let targ = &body[tstart..i];
            extract_type_idents(
                targ,
                &defined,
                module_ns_set,
                &mut plain,
                &mut templated,
                &mut qual,
            );
            from = from + p + TAG.len();
        }
    }
    for t in templated.iter() {
        plain.remove(t);
    }

    if plain.is_empty() && templated.is_empty() && qual.is_empty() {
        return;
    }

    macros.push_str("// Auto-generated: forward declarations for types the runtime schemas\n");
    macros.push_str("// reference but that aren't defined in any included header.\n");
    for t in &templated {
        macros.push_str(&format!("template <class...> class {};\n", t));
    }
    for t in &plain {
        macros.push_str(&format!("class {};\n", t));
    }
    for (ns, names) in &qual {
        macros.push_str(&format!("namespace {} {{ ", ns));
        for (name, is_t) in names {
            if *is_t {
                macros.push_str(&format!("template <class...> class {}; ", name));
            } else {
                macros.push_str(&format!("class {}; ", name));
            }
        }
        macros.push_str("}\n");
    }
    macros.push('\n');
}

fn extract_type_idents(
    arg: &str,
    defined: &BTreeSet<String>,
    module_ns_set: &BTreeSet<String>,
    plain: &mut BTreeSet<String>,
    templated: &mut BTreeSet<String>,
    qual: &mut BTreeMap<String, BTreeMap<String, bool>>,
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
                let ns = ns.split("::").next().unwrap_or(ns);
                if !is_builtin_type(ns) && !module_ns_set.contains(ns) && !defined.contains(name) {
                    let e = qual.entry(ns.to_string()).or_default();
                    let v = e.entry(name.to_string()).or_insert(false);
                    *v = *v || is_t;
                }
            } else if !is_builtin_type(tok) && !defined.contains(tok) {
                if is_t {
                    templated.insert(tok.to_string());
                } else {
                    plain.insert(tok.to_string());
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
        .get("client.dll")
        .and_then(|module| {
            module
                .get("dwCSGOInput")
                .or_else(|| module.get("pCSGOInput"))
                .copied()
        })
        .or_else(|| pattern_rva.and_then(|value| u32::try_from(value).ok()))
}
