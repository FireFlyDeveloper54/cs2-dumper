//! Shared remote-string reads and little-endian integer loads.
//!
//! Walkers used to copy the C-string helper with different max lengths; one
//! implementation with a generous cap is enough because `read_utf8_lossy`
//! stops at a NUL. Integer helpers return `None` instead of panicking when
//! the slice is short.

use memflow::prelude::v1::*;

const CSTR_MAX: usize = 256;

#[inline]
pub fn u16_le(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

#[inline]
pub fn u32_le(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

#[inline]
pub fn i32_le(bytes: &[u8]) -> Option<i32> {
    Some(i32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

#[inline]
pub fn u64_le(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

#[inline]
pub fn u16_le_at(bytes: &[u8], offset: usize) -> Option<u16> {
    u16_le(bytes.get(offset..)?)
}

#[inline]
pub fn u32_le_at(bytes: &[u8], offset: usize) -> Option<u32> {
    u32_le(bytes.get(offset..)?)
}

#[inline]
pub fn i32_le_at(bytes: &[u8], offset: usize) -> Option<i32> {
    i32_le(bytes.get(offset..)?)
}

#[inline]
pub fn u64_le_at(bytes: &[u8], offset: usize) -> Option<u64> {
    u64_le(bytes.get(offset..)?)
}

/// Remote integer load with a caller-chosen fallback. Walkers used to copy
/// `read::<T>().data_part().unwrap_or(...)` with slightly different defaults.
#[inline]
pub fn or<T: Pod, P: MemoryView>(mem: &mut P, va: u64, fallback: T) -> T {
    mem.read::<T>(Address::from(va)).data_part().unwrap_or(fallback)
}

#[inline]
pub fn u8_va<P: MemoryView>(mem: &mut P, va: u64) -> u8 {
    or(mem, va, 0)
}

#[inline]
pub fn u16_va<P: MemoryView>(mem: &mut P, va: u64) -> u16 {
    or(mem, va, 0)
}

#[inline]
pub fn i16_va<P: MemoryView>(mem: &mut P, va: u64) -> i16 {
    or(mem, va, 0)
}

#[inline]
pub fn u32_va<P: MemoryView>(mem: &mut P, va: u64) -> u32 {
    or(mem, va, 0)
}

#[inline]
pub fn i32_va<P: MemoryView>(mem: &mut P, va: u64) -> i32 {
    or(mem, va, 0)
}

#[inline]
pub fn u64_va<P: MemoryView>(mem: &mut P, va: u64) -> u64 {
    or(mem, va, 0)
}

#[inline]
pub fn f32_va<P: MemoryView>(mem: &mut P, va: u64) -> f32 {
    or(mem, va, 0.0)
}

pub fn cstr<P: MemoryView>(mem: &mut P, ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    mem.read_utf8_lossy(Address::from(ptr), CSTR_MAX)
        .data_part()
        .unwrap_or_default()
}

pub fn cstr_at<P: MemoryView>(mem: &mut P, ptr_field_va: u64) -> String {
    let ptr = u64_va(mem, ptr_field_va);
    cstr(mem, ptr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::fake::FakeMemory;

    #[test]
    fn empty_on_null_pointer() {
        let mut mem = FakeMemory::new();
        assert!(cstr(&mut mem, 0).is_empty());
    }

    #[test]
    fn reads_nul_terminated_string() {
        let mut mem = FakeMemory::new();
        let addr = mem.alloc(16);
        mem.put_cstr(addr, "hello");
        assert_eq!(cstr(&mut mem, addr), "hello");
    }

    #[test]
    fn remote_integer_loads_use_fallback_on_unmapped_memory() {
        let mut mem = FakeMemory::new();
        let addr = mem.alloc(8);
        mem.put_u64(addr, 0x1122_3344_5566_7788);
        assert_eq!(u64_va(&mut mem, addr), 0x1122_3344_5566_7788);
        assert_eq!(u32_va(&mut mem, addr), 0x5566_7788);
        // memflow `read::<T>` folds a failed raw read into a zeroed value, so
        // the fallback only shows up when `data_part` itself is `Err`.
        assert_eq!(u64_va(&mut mem, 0x1000), 0);
        let ptr = mem.alloc_cstr("pawn");
        let field = mem.alloc(8);
        mem.put_u64(field, ptr);
        assert_eq!(cstr_at(&mut mem, field), "pawn");
        assert!(cstr_at(&mut mem, 0x1000).is_empty());
    }

    #[test]
    fn little_endian_loads_reject_short_slices() {
        assert_eq!(u16_le(&[1]), None);
        assert_eq!(u32_le(&[1, 2, 3]), None);
        assert_eq!(u64_le(&[1, 2, 3, 4, 5, 6, 7]), None);
        assert_eq!(u32_le_at(&[1, 2, 3, 4, 5], 2), None);
        assert_eq!(i32_le_at(&[1, 2, 3, 4], 2), None);
        assert_eq!(u16_le(&[0x34, 0x12]), Some(0x1234));
        assert_eq!(u32_le(&[0x78, 0x56, 0x34, 0x12]), Some(0x1234_5678));
        assert_eq!(i32_le(&[0xff, 0xff, 0xff, 0xff]), Some(-1));
        assert_eq!(
            u64_le_at(&[0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], 2),
            Some(0x8877_6655_4433_2211)
        );
        assert_eq!(u16_le_at(&[0x34, 0x12, 0x00], 0), Some(0x1234));
        assert_eq!(i32_le_at(&[0xff, 0xff, 0xff, 0xff], 0), Some(-1));
        // `get(offset..)` must not add `offset + width` (that panics near usize::MAX).
        assert_eq!(u32_le_at(&[0; 8], usize::MAX), None);
        assert_eq!(i32_le_at(&[0; 4], usize::MAX - 1), None);
        assert_eq!(u64_le_at(&[], usize::MAX), None);
    }
}
