use memflow::prelude::v1::*;

use super::SchemaSystemTypeScope;

use crate::source2::UtlVector;

#[repr(C)]
pub struct SchemaSystem {
    pad_0: [u8; 0x190],                                           // 0x0000
    pub type_scopes: UtlVector<Pointer64<SchemaSystemTypeScope>>, // 0x0190
    pad_1: [u8; 0xE0],                                            // 0x01A0
    pub registration_count: i32,                                  // 0x0280
}

unsafe impl Pod for SchemaSystem {}

#[cfg(test)]
mod tests {
    use super::SchemaSystem;
    use crate::source2::SchemaSystemTypeScope;
    use memflow::prelude::v1::Pointer64;
    use std::mem::{offset_of, size_of};

    #[test]
    fn type_scopes_vector_sits_at_0x190() {
        assert_eq!(size_of::<crate::source2::UtlVector<Pointer64<SchemaSystemTypeScope>>>(), 0x10);
        assert_eq!(offset_of!(SchemaSystem, type_scopes), 0x190);
        assert_eq!(offset_of!(SchemaSystem, registration_count), 0x280);
    }
}
