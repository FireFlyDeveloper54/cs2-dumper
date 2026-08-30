//! Shared schema → C++ storage-type table.
//!
//! `sdk.rs` (global-namespace SDK) flattens engine typedefs to the integer or
//! float they occupy. `sdk_classes.rs` (include-tree) keeps those typedef
//! names because `macros.hpp` declares them. Both sides must agree on the
//! *primitive* tokens (`int32`, `float32`, …) so a game update cannot map
//! `int32` to `int32_t` in one emitter and leave it raw in the other.

use phf::{Map, phf_map};

static PRIMITIVES: Map<&'static str, &'static str> = phf_map! {
    "bool" => "bool",
    "char" => "char",
    "void" => "void",
    "float" => "float",
    "float32" => "float",
    "float64" => "double",
    "double" => "double",
    "int" => "int32_t",
    "int8" => "int8_t",
    "int8_t" => "int8_t",
    "int16" => "int16_t",
    "int16_t" => "int16_t",
    "int32" => "int32_t",
    "int32_t" => "int32_t",
    "int64" => "int64_t",
    "int64_t" => "int64_t",
    "uint8" => "uint8_t",
    "uint8_t" => "uint8_t",
    "uint16" => "uint16_t",
    "uint16_t" => "uint16_t",
    "uint32" => "uint32_t",
    "uint32_t" => "uint32_t",
    "uint64" => "uint64_t",
    "uint64_t" => "uint64_t",
    "unsignedint" => "uint32_t",
    "long" => "long",
    "unsignedlong" => "unsigned long",
};

/// Engine typedefs flattened to their storage type. Used only by `sdk/`.
static STORAGE_ALIASES: Map<&'static str, &'static str> = phf_map! {
    "Color" => "uint32_t",
    "GameTime_t" => "float",
    "GameTick_t" => "int32_t",
    "CUtlStringToken" => "uint32_t",
    "CGlobalSymbol" => "uint64_t",
    "PulseSymbol_t" => "uint64_t",
    "CEntityIndex" => "uint32_t",
    "CEntityHandle" => "uint32_t",
    "ItemId_t" => "uint64_t",
    "ItemIdLow_t" => "uint32_t",
    "AttachmentHandle_t" => "uint8_t",
    "AmmoIndex_t" => "uint8_t",
    "SceneHandle_t" => "uint32_t",
    "HSequence" => "int32_t",
    "attributeprovidertypes_t" => "uint32_t",
    "EntityPlatformTypes_t" => "uint8_t",
    "SplitScreenSlot_t" => "uint32_t",
    "CSPlayerState" => "uint32_t",
    "CSPlayerBullets_t" => "int32_t",
    "WorldGroupId_t" => "int32_t",
    "CNetworkedQuantizedFloat" => "float",
    "HSCRIPT" => "uint64_t",
    "ScriptOrdinal_t" => "uint32_t",
    "SubclassMdlData_t" => "uint32_t",
    "RenderMode_t" => "uint8_t",
    "RenderGroup_t" => "uint32_t",
    "SolidType_t" => "uint8_t",
    "SurroundingBoundsType_t" => "uint8_t",
    "DamageMode_t" => "uint8_t",

    "ShatterPanelMode" => "uint8_t",
    "ShatterDamageCause" => "uint8_t",
    "ShatterGlassEdge_t" => "uint8_t",
    "ShatterGlassTint_t" => "uint8_t",
    "ShadowType_t" => "uint8_t",
    "Touch_t" => "uint8_t",
    "WaterWakeMode_t" => "uint8_t",
    "CounterType_t" => "uint8_t",
    "FontLerpMode_t" => "uint8_t",
    "FadeBlendMode_t" => "uint8_t",
    "ExplosionType_t" => "uint8_t",
    "ClaimResult_t" => "uint32_t",
    "ChickenActivity_t" => "uint32_t",
    "ChickenToCrowActivity_t" => "uint32_t",
    "ItemFlagTypes_t" => "uint8_t",
    "MoneyShellPage_t" => "uint8_t",
    "eSpectatorTeamContentChannel" => "uint32_t",
    "BoneDomain_t" => "uint32_t",
    "VPhysExpiry_t" => "uint32_t",
    "ShootMode_t" => "uint32_t",
    "PlayerConnectedState" => "uint32_t",
    "DisplacementLookups_t" => "uint32_t",
    "CStrongHandle" => "uint64_t",
    "CWeakHandle" => "uint64_t",
    "SkeletonBoneBits_t" => "uint32_t",
    "fixtures1_t" => "uint32_t",
    "AEarRspBox_t" => "uint32_t",
};

/// Primitive schema token (`int32`, `float32`, …) → C++ storage type without `std::`.
pub fn map_primitive(schema: &str) -> Option<&'static str> {
    PRIMITIVES.get(schema).copied()
}

/// Primitive or flattened engine alias. This is what `sdk/sdk.hpp` wants.
pub fn map_storage(schema: &str) -> Option<&'static str> {
    map_primitive(schema).or_else(|| STORAGE_ALIASES.get(schema).copied())
}

/// `int32_t` → `std::int32_t`. Leaves `bool` / `float` / `long` alone.
pub fn with_std_prefix(cpp: &str) -> std::borrow::Cow<'_, str> {
    match cpp {
        "int8_t" => std::borrow::Cow::Borrowed("std::int8_t"),
        "int16_t" => std::borrow::Cow::Borrowed("std::int16_t"),
        "int32_t" => std::borrow::Cow::Borrowed("std::int32_t"),
        "int64_t" => std::borrow::Cow::Borrowed("std::int64_t"),
        "uint8_t" => std::borrow::Cow::Borrowed("std::uint8_t"),
        "uint16_t" => std::borrow::Cow::Borrowed("std::uint16_t"),
        "uint32_t" => std::borrow::Cow::Borrowed("std::uint32_t"),
        "uint64_t" => std::borrow::Cow::Borrowed("std::uint64_t"),
        other => std::borrow::Cow::Borrowed(other),
    }
}

/// Mask a schema enumerator to the storage width used in generated C++.
pub fn enum_value_masked(value: i64, type_name: &str) -> u64 {
    let bits = match type_name {
        "uint8_t" | "u8" | "byte" => 8u32,
        "uint16_t" | "u16" | "ushort" => 16,
        "uint32_t" | "u32" | "uint" => 32,
        "uint64_t" | "u64" | "ulong" => 64,
        _ => 32,
    };
    if bits == 64 {
        value as u64
    } else {
        (value as u64) & ((1u64 << bits) - 1)
    }
}

/// Split a schema array token `int32[4]` / `char[2][3]` into the element type
/// and the `[N]…` suffix. Non-numeric bounds are rejected so `T[]` / `T[N]`
/// template noise is left to the caller.
pub fn split_fixed_array(raw: &str) -> Option<(&str, &str)> {
    let start = raw.find('[')?;
    if !raw.ends_with(']') {
        return None;
    }
    let suffix = &raw[start..];
    let bytes = suffix.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'[' {
            return None;
        }
        i += 1;
        let dim_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == dim_start || i >= bytes.len() || bytes[i] != b']' {
            return None;
        }
        i += 1;
    }
    Some((raw[..start].trim_end(), suffix))
}

/// Enum storage width without `std::` (`uint32_t`).
pub fn enum_underlying(storage_bytes: u8) -> &'static str {
    match storage_bytes {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "uint32_t",
    }
}

/// Enum storage width with `std::` prefix, signed if any member is negative.
pub fn enum_underlying_std(storage_bytes: u8, signed: bool) -> Option<&'static str> {
    Some(match (storage_bytes, signed) {
        (1, true) => "std::int8_t",
        (1, false) => "std::uint8_t",
        (2, true) => "std::int16_t",
        (2, false) => "std::uint16_t",
        (4, true) => "std::int32_t",
        (4, false) => "std::uint32_t",
        (8, true) => "std::int64_t",
        (8, false) => "std::uint64_t",
        _ => return None,
    })
}

/// An enumerator narrowed to the range of an enum's fixed underlying type.
///
/// Schema keeps an enumerator in an 8-byte union and the analysis pass reads the
/// whole union, so a 1- or 2-byte enum can carry leftovers in the bytes above
/// its width, and a mixed-sign enum can carry a value outside the signed range
/// of that width. C++11 makes an enumerator outside its fixed underlying type's
/// range ill-formed, so the value has to be narrowed the way the compiler that
/// produced it did — masked to the width, then sign-extended when the chosen
/// underlying type is signed.
///
/// Prefer this over [`enum_value_masked`] when the underlying type is known by
/// width rather than by spelling: `enum_value_masked` matches on type *names*
/// and falls back to 32 bits for anything it does not recognise, including the
/// `std::`-qualified names [`enum_underlying_std`] returns.
pub fn enum_value_for_width(value: i64, storage_bytes: u8, signed: bool) -> i64 {
    let bits = u32::from(storage_bytes).saturating_mul(8);
    if bits == 0 || bits >= 64 {
        return value;
    }
    let masked = (value as u64) & ((1u64 << bits) - 1);
    if signed && masked & (1u64 << (bits - 1)) != 0 {
        (masked as i64).wrapping_sub(1i64 << bits)
    } else {
        masked as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_fixed_array_keeps_every_numeric_rank() {
        assert_eq!(split_fixed_array("int32[4]"), Some(("int32", "[4]")));
        assert_eq!(split_fixed_array("char[2][3]"), Some(("char", "[2][3]")));
        assert_eq!(split_fixed_array("Vector[8]"), Some(("Vector", "[8]")));
        assert_eq!(split_fixed_array("int32[]"), None);
        assert_eq!(split_fixed_array("int32[N]"), None);
        assert_eq!(split_fixed_array("int32"), None);
    }

    #[test]
    fn primitives_agree_across_dialects() {
        assert_eq!(map_primitive("int32"), Some("int32_t"));
        assert_eq!(map_primitive("float32"), Some("float"));
        assert_eq!(with_std_prefix("int32_t"), "std::int32_t");
        assert_eq!(with_std_prefix("float"), "float");
    }

    #[test]
    fn storage_aliases_flatten_engine_typedefs() {
        assert_eq!(map_storage("GameTime_t"), Some("float"));
        assert_eq!(map_storage("int32"), Some("int32_t"));
        assert_eq!(map_primitive("GameTime_t"), None);
        assert_eq!(
            map_storage("TakeDamageFlags_t"),
            None,
            "real schema enums must not be flattened to the wrong width"
        );
        assert_eq!(map_storage("CFiringModeFloat"), None);
        assert_eq!(map_storage("CFiringModeInt"), None);
        assert_eq!(map_storage("DoorState_t"), None);
    }

    #[test]
    fn enum_value_masked_accepts_language_storage_names() {
        assert_eq!(enum_value_masked(0x100, "byte"), 0);
        assert_eq!(enum_value_masked(-1, "u8"), 0xFF);
        assert_eq!(
            enum_value_masked(i32::MAX as i64 + 1, "uint32_t"),
            0x8000_0000
        );
    }

    #[test]
    fn enum_widths_match_schema_size() {
        assert_eq!(enum_underlying(4), "uint32_t");
        assert_eq!(enum_underlying_std(4, true), Some("std::int32_t"));
        assert_eq!(enum_underlying_std(3, false), None);
    }

    /// The schema value is read out of an 8-byte union, so it can carry bits
    /// above the enum's own width. A fixed underlying type makes an out-of-range
    /// enumerator a compile error, not a wrap.
    #[test]
    fn enum_values_narrow_to_their_storage_width() {
        // High leftovers in a one-byte enum are dropped, not emitted.
        assert_eq!(enum_value_for_width(0x1234_00AB, 1, false), 0xAB);
        assert_eq!(enum_value_for_width(0x1234_ABCD, 2, false), 0xABCD);
        // A signed underlying gets the value sign-extended back into range.
        assert_eq!(enum_value_for_width(0xFF, 1, true), -1);
        assert_eq!(enum_value_for_width(0x8000_0000, 4, true), i32::MIN as i64);
        // An unsigned underlying keeps the same bits as a positive value.
        assert_eq!(enum_value_for_width(-1, 4, false), 0xFFFF_FFFF);
        // Eight-byte enums are already the full width.
        assert_eq!(enum_value_for_width(-1, 8, true), -1);
        assert_eq!(enum_value_for_width(i64::MIN, 8, true), i64::MIN);
    }

    /// `enum_value_masked` matches on type *names* and defaults to 32 bits, so
    /// it silently mis-narrows the `std::`-qualified names `enum_underlying_std`
    /// returns. Width-based narrowing is the one to use with those.
    #[test]
    fn masked_by_name_does_not_understand_std_qualified_types() {
        assert_eq!(enum_value_masked(0x1234_00AB, "std::uint8_t"), 0x1234_00AB);
        assert_eq!(enum_value_for_width(0x1234_00AB, 1, false), 0xAB);
    }
}
