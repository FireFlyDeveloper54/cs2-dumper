//! Schema class/enum flag bits, ported from shade-dumper's CSchemaClassInfo.
//!
//! The live schema binding carries these in `m_nClassFlags` / `m_nFlags`.
//! They are decoded into stable English labels so JSON and generated headers
//! stay readable across dumps.

use crate::analysis::SchemaMap;

pub const SCHEMA_CF1_HAS_VIRTUAL_MEMBERS: u32 = 1 << 0;
pub const SCHEMA_CF1_IS_ABSTRACT: u32 = 1 << 1;
pub const SCHEMA_CF1_HAS_TRIVIAL_CONSTRUCTOR: u32 = 1 << 2;
pub const SCHEMA_CF1_HAS_TRIVIAL_DESTRUCTOR: u32 = 1 << 3;
pub const SCHEMA_CF1_LIMITED_METADATA: u32 = 1 << 4;
pub const SCHEMA_CF1_INHERITANCE_DEPTH_CALCULATED: u32 = 1 << 5;
pub const SCHEMA_CF1_MODULE_LOCAL_TYPE_SCOPE: u32 = 1 << 6;
pub const SCHEMA_CF1_GLOBAL_TYPE_SCOPE: u32 = 1 << 7;
pub const SCHEMA_CF1_CONSTRUCT_ALLOWED: u32 = 1 << 8;
pub const SCHEMA_CF1_CONSTRUCT_DISALLOWED: u32 = 1 << 9;
pub const SCHEMA_CF1_INFO_TAG_MNETWORK_ASSUME_NOT_NETWORKABLE: u32 = 1 << 10;
pub const SCHEMA_CF1_INFO_TAG_MNETWORK_NO_BASE: u32 = 1 << 11;
pub const SCHEMA_CF1_INFO_TAG_MIGNORE_TYPE_SCOPE_META_CHECKS: u32 = 1 << 12;
pub const SCHEMA_CF1_INFO_TAG_MDISABLE_DATA_DESC_VALIDATION: u32 = 1 << 13;
pub const SCHEMA_CF1_INFO_TAG_MCLASS_HAS_ENTITY_LIMITED_DATA_DESC: u32 = 1 << 14;
pub const SCHEMA_CF1_INFO_TAG_MCLASS_HAS_CUSTOM_ALIGNED_NEW_DELETE: u32 = 1 << 15;
pub const SCHEMA_CF1_UNK016: u32 = 1 << 16;
pub const SCHEMA_CF1_INFO_TAG_MCONSTRUCTIBLE_CLASS_BASE: u32 = 1 << 17;
pub const SCHEMA_CF1_INFO_TAG_MHAS_KV3_TRANSFER_POLYMORPHIC_CLASSNAME: u32 = 1 << 18;

pub const SCHEMA_EF_IS_REGISTERED: u8 = 1 << 0;
pub const SCHEMA_EF_MODULE_LOCAL_TYPE_SCOPE: u8 = 1 << 1;
pub const SCHEMA_EF_GLOBAL_TYPE_SCOPE: u8 = 1 << 2;

const CLASS_FLAG_LABELS: &[(u32, &str)] = &[
    (SCHEMA_CF1_HAS_VIRTUAL_MEMBERS, "Has VTable"),
    (SCHEMA_CF1_IS_ABSTRACT, "Is Abstract"),
    (SCHEMA_CF1_HAS_TRIVIAL_CONSTRUCTOR, "Has Trivial Constructor"),
    (SCHEMA_CF1_HAS_TRIVIAL_DESTRUCTOR, "Has Trivial Destructor"),
    (SCHEMA_CF1_LIMITED_METADATA, "Limited Metadata"),
    (
        SCHEMA_CF1_INHERITANCE_DEPTH_CALCULATED,
        "Inheritance Depth Calculated",
    ),
    (SCHEMA_CF1_MODULE_LOCAL_TYPE_SCOPE, "Local Type Scope"),
    (SCHEMA_CF1_GLOBAL_TYPE_SCOPE, "Global Type Scope"),
    (SCHEMA_CF1_CONSTRUCT_ALLOWED, "Construct Allowed"),
    (SCHEMA_CF1_CONSTRUCT_DISALLOWED, "Construct Disallowed"),
    (
        SCHEMA_CF1_INFO_TAG_MNETWORK_ASSUME_NOT_NETWORKABLE,
        "MNetworkAssumeNotNetworkable",
    ),
    (SCHEMA_CF1_INFO_TAG_MNETWORK_NO_BASE, "MNetworkNoBase"),
    (
        SCHEMA_CF1_INFO_TAG_MIGNORE_TYPE_SCOPE_META_CHECKS,
        "MIgnoreTypeScopeMetaChecks",
    ),
    (
        SCHEMA_CF1_INFO_TAG_MDISABLE_DATA_DESC_VALIDATION,
        "MDisableDataDescValidation",
    ),
    (
        SCHEMA_CF1_INFO_TAG_MCLASS_HAS_ENTITY_LIMITED_DATA_DESC,
        "MClassHasEntityLimitedDataDesc",
    ),
    (
        SCHEMA_CF1_INFO_TAG_MCLASS_HAS_CUSTOM_ALIGNED_NEW_DELETE,
        "MClassHasCustomAlignedNewDelete",
    ),
    (SCHEMA_CF1_UNK016, "Unknown 0x10000"),
    (
        SCHEMA_CF1_INFO_TAG_MCONSTRUCTIBLE_CLASS_BASE,
        "MConstructibleClassBase",
    ),
    (
        SCHEMA_CF1_INFO_TAG_MHAS_KV3_TRANSFER_POLYMORPHIC_CLASSNAME,
        "MHasKV3TransferPolymorphicClassname",
    ),
];

const ENUM_FLAG_LABELS: &[(u8, &str)] = &[
    (SCHEMA_EF_IS_REGISTERED, "Is Registered"),
    (SCHEMA_EF_MODULE_LOCAL_TYPE_SCOPE, "Local Type Scope"),
    (SCHEMA_EF_GLOBAL_TYPE_SCOPE, "Global Type Scope"),
];

/// Modules the LoadLibrary schema dumper can force-register. A live process
/// dump only sees scopes that are actually loaded at attach time.
pub const KNOWN_SCHEMA_MODULES: &[&str] = &[
    "client.dll",
    "server.dll",
    "engine2.dll",
    "schemasystem.dll",
    "animationsystem.dll",
    "materialsystem2.dll",
    "particles.dll",
    "scenesystem.dll",
    "soundsystem.dll",
    "vphysics2.dll",
    "networksystem.dll",
    "host.dll",
    "panorama.dll",
    "panorama_text_pango.dll",
    "panorama_ui_client.dll",
    "rendersystemdx11.dll",
    "resourcesystem.dll",
    "worldrenderer.dll",
    "pulse_system.dll",
    "steamaudio.dll",
    "meshsystem.dll",
    "scenefilecache.dll",
    "filesystem_stdio.dll",
    "inputsystem.dll",
    "localize.dll",
    "matchmaking.dll",
    "navsystem.dll",
    "vscript.dll",
    "v8system.dll",
    "vconcomm.dll",
];

pub fn class_flag_names(flags: u32) -> Vec<String> {
    decode_bits(flags, CLASS_FLAG_LABELS)
}

/// Decode `m_nClassFlags`, leftover `flags2` bits, and whether a manipulator
/// function pointer is present. ASLR-unstable manipulator VAs are not emitted.
pub fn class_flag_labels(class_flags: u32, flags2: u32, has_manipulator: bool) -> Vec<String> {
    let mut names = class_flag_names(class_flags);
    if flags2 != 0 {
        names.push(format!("Flags2 {flags2:#X}"));
    }
    if has_manipulator {
        names.push("Has Manipulator".into());
    }
    names
}

pub fn enum_flag_names(flags: u8) -> Vec<String> {
    decode_bits(flags, ENUM_FLAG_LABELS)
}

fn decode_bits<T: Copy + Into<u32>>(value: T, labels: &[(T, &str)]) -> Vec<String> {
    let raw = value.into();
    let mut names = Vec::new();
    let mut known = 0u32;
    for &(bit, label) in labels {
        let mask = bit.into();
        if raw & mask != 0 {
            names.push(label.to_string());
            known |= mask;
        }
    }
    let rest = raw & !known;
    if rest != 0 {
        names.push(format!("Unknown {rest:#X}"));
    }
    names
}

pub fn missing_schema_modules(schemas: &SchemaMap) -> Vec<String> {
    KNOWN_SCHEMA_MODULES
        .iter()
        .filter(|module| {
            !schemas
                .keys()
                .any(|loaded| loaded.eq_ignore_ascii_case(module))
        })
        .map(|module| (*module).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::SchemaMap;

    #[test]
    fn decodes_shade_class_flags() {
        let flags = SCHEMA_CF1_HAS_VIRTUAL_MEMBERS | SCHEMA_CF1_CONSTRUCT_ALLOWED;
        assert_eq!(
            class_flag_names(flags),
            vec!["Has VTable".to_string(), "Construct Allowed".to_string()]
        );
        assert!(class_flag_names(0).is_empty());
    }

    #[test]
    fn decodes_remaining_shade_class_and_enum_bits() {
        let flags = SCHEMA_CF1_LIMITED_METADATA
            | SCHEMA_CF1_INFO_TAG_MNETWORK_NO_BASE
            | SCHEMA_CF1_INFO_TAG_MCONSTRUCTIBLE_CLASS_BASE;
        let names = class_flag_names(flags);
        assert!(names.iter().any(|n| n == "Limited Metadata"));
        assert!(names.iter().any(|n| n == "MNetworkNoBase"));
        assert!(names.iter().any(|n| n == "MConstructibleClassBase"));
        let labels = class_flag_labels(0, 0x20, true);
        assert_eq!(
            labels,
            vec!["Flags2 0x20".to_string(), "Has Manipulator".to_string()]
        );
        assert_eq!(
            enum_flag_names(SCHEMA_EF_IS_REGISTERED | SCHEMA_EF_GLOBAL_TYPE_SCOPE),
            vec!["Is Registered".to_string(), "Global Type Scope".to_string()]
        );
        assert_eq!(class_flag_names(1 << 30), vec!["Unknown 0x40000000".to_string()]);
    }

    #[test]
    fn reports_schema_modules_the_loadlibrary_dumper_can_see() {
        let schemas = SchemaMap::from([("client.dll".into(), (Vec::new(), Vec::new()))]);
        let missing = missing_schema_modules(&schemas);
        assert!(missing.iter().any(|m| m == "meshsystem.dll"));
        assert!(missing.iter().any(|m| m == "vscript.dll"));
        assert!(!missing.iter().any(|m| m == "client.dll"));
    }
}
