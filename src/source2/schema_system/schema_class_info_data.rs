use memflow::prelude::v1::*;

use super::*;

pub type SchemaClassBinding = SchemaClassInfoData;

/// Runtime `CSchemaClassInfo` / `SchemaClassInfoData_t`.
///
/// Offsets in comments are the actual `#[repr(C)]` layout, locked by
/// `field_offsets_match_repr_c`. `pad_1` is the static-field pointer slot;
/// [`crate::analysis::static_fields`] probes it instead of hardcoding a type.
/// There is no extra pad after `static_metadata`, so `type_scope` sits at
/// `0x50` — do not "fix" this back to `0x58` without a live process check.
#[rustfmt::skip]
#[derive(Pod)]
#[repr(C)]
pub struct SchemaClassInfoData {
    pub base: Pointer64<SchemaClassInfoData>,                  // 0x0000
    pub name: Pointer64<ReprCString>,                          // 0x0008
    pub binary_name: Pointer64<ReprCString>,                   // 0x0010
    pub module_name: Pointer64<ReprCString>,                   // 0x0018
    pub size: i32,                                             // 0x0020
    pub field_count: i16,                                      // 0x0024
    pub static_metadata_count: i16,                            // 0x0026
    pad_0: [u8; 0x2],                                          // 0x0028
    pub alignment: u8,                                         // 0x002A
    pub has_base_class: u8,                                    // 0x002B
    pub total_class_size: i16,                                 // 0x002C
    pub derived_class_size: i16,                               // 0x002E
    pub fields: Pointer64<[SchemaClassFieldData]>,             // 0x0030
    pad_1: [u8; 0x8],                                          // 0x0038
    pub base_classes: Pointer64<SchemaBaseClassInfoData>,      // 0x0040
    pub static_metadata: Pointer64<[SchemaMetadataEntryData]>, // 0x0048
    pub type_scope: Pointer64<SchemaSystemTypeScope>,          // 0x0050
    pub r#type: Pointer64<SchemaType>,                         // 0x0058
    /// SCHEMA_CF1_* bits (Has VTable, abstract, construct allowed, …).
    pub class_flags: u32,                                      // 0x0060
    pub flags2: u32,                                           // 0x0064
    pub manipulator: Pointer64<u8>,                            // 0x0068
}

#[cfg(test)]
mod tests {
    use super::SchemaClassInfoData;
    use std::mem::offset_of;

    #[test]
    fn field_offsets_match_repr_c() {
        assert_eq!(offset_of!(SchemaClassInfoData, name), 0x08);
        assert_eq!(offset_of!(SchemaClassInfoData, binary_name), 0x10);
        assert_eq!(offset_of!(SchemaClassInfoData, module_name), 0x18);
        assert_eq!(offset_of!(SchemaClassInfoData, size), 0x20);
        assert_eq!(offset_of!(SchemaClassInfoData, field_count), 0x24);
        assert_eq!(offset_of!(SchemaClassInfoData, static_metadata_count), 0x26);
        assert_eq!(offset_of!(SchemaClassInfoData, alignment), 0x2A);
        assert_eq!(offset_of!(SchemaClassInfoData, fields), 0x30);
        assert_eq!(offset_of!(SchemaClassInfoData, base_classes), 0x40);
        assert_eq!(offset_of!(SchemaClassInfoData, static_metadata), 0x48);
        assert_eq!(offset_of!(SchemaClassInfoData, type_scope), 0x50);
        assert_eq!(offset_of!(SchemaClassInfoData, r#type), 0x58);
        assert_eq!(offset_of!(SchemaClassInfoData, class_flags), 0x60);
        assert_eq!(offset_of!(SchemaClassInfoData, flags2), 0x64);
        assert_eq!(offset_of!(SchemaClassInfoData, manipulator), 0x68);
    }
}
