//! An in-process fake [`MemoryView`] for offline tests.
//!
//! Most of this crate reads the game through `MemoryView`, so almost none of
//! the pointer-walking logic could be exercised without a running `cs2.exe`.
//! `FakeMemory` closes that gap: a test builds the exact object graph it wants
//! — vtables, registry linked lists, chunked entity arrays, schema nodes — and
//! then runs the real production walker over it.
//!
//! Semantics chosen to match how the game actually behaves:
//!
//! - Memory is sparse. Only bytes a test explicitly wrote are mapped, so a
//!   walker that follows a bogus pointer sees an unreadable address instead of
//!   silently reading zeroes.
//! - A read that lands entirely outside mapped memory is reported as failed.
//!   memflow folds that into `Ok` with a zero-filled buffer for `read::<T>`
//!   (see `PartialResultExt::map_data`), which is exactly why the walkers in
//!   this crate range-check pointers instead of trusting a successful read.
//! - A read that starts inside mapped memory and runs off the end succeeds with
//!   the bytes that were there. memflow pre-zeroes read buffers, so this is
//!   also how a real short string read near a page boundary behaves.
//!
//! Test-only: this module is compiled out of the shipped binary.

use std::collections::BTreeMap;

use memflow::cglue::{CTup2, CTup3};
use memflow::mem::mem_data::{MemOps, ReadRawMemOps, WriteRawMemOps, opt_call};
use memflow::prelude::v1::*;

/// Where [`FakeMemory::alloc`] starts handing out addresses. High enough that
/// every plausibility check in the crate (`va < 0x10000` and friends) treats
/// the result as a real user-space pointer.
const ALLOC_BASE: u64 = 0x0000_7FF6_0000_0000;

/// Allocations are 16-byte aligned, like a real allocator, so a test that
/// assumes alignment is not accidentally passing.
const ALLOC_ALIGN: u64 = 0x10;

#[derive(Debug)]
pub struct FakeMemory {
    bytes: BTreeMap<u64, u8>,
    next: u64,
}

impl Default for FakeMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeMemory {
    pub fn new() -> Self {
        Self {
            bytes: BTreeMap::new(),
            next: ALLOC_BASE,
        }
    }

    /// Map `data` at `addr`, overwriting whatever was there.
    pub fn put(&mut self, addr: u64, data: &[u8]) -> &mut Self {
        for (i, byte) in data.iter().enumerate() {
            self.bytes.insert(addr + i as u64, *byte);
        }
        self
    }

    pub fn put_u8(&mut self, addr: u64, value: u8) -> &mut Self {
        self.put(addr, &[value])
    }

    pub fn put_u16(&mut self, addr: u64, value: u16) -> &mut Self {
        self.put(addr, &value.to_le_bytes())
    }

    pub fn put_u32(&mut self, addr: u64, value: u32) -> &mut Self {
        self.put(addr, &value.to_le_bytes())
    }

    pub fn put_i32(&mut self, addr: u64, value: i32) -> &mut Self {
        self.put(addr, &value.to_le_bytes())
    }

    pub fn put_f32(&mut self, addr: u64, value: f32) -> &mut Self {
        self.put(addr, &value.to_le_bytes())
    }

    pub fn put_u64(&mut self, addr: u64, value: u64) -> &mut Self {
        self.put(addr, &value.to_le_bytes())
    }

    /// Write a pointer-sized value. Spelled out separately from [`put_u64`]
    /// so pointer graphs read as pointer graphs at the call site.
    pub fn put_ptr(&mut self, addr: u64, target: u64) -> &mut Self {
        self.put_u64(addr, target)
    }

    /// Write a NUL-terminated string.
    pub fn put_cstr(&mut self, addr: u64, value: &str) -> &mut Self {
        self.put(addr, value.as_bytes());
        self.put_u8(addr + value.len() as u64, 0)
    }

    /// Write the signed 32-bit displacement at `field` that makes an
    /// instruction ending at `field + 4` point at `target`.
    pub fn put_rel32(&mut self, field: u64, target: u64) -> &mut Self {
        let disp = target.wrapping_sub(field.wrapping_add(4)) as i64;
        self.put_i32(field, disp as i32)
    }

    /// Lay down a 7-byte RIP-relative instruction at `at` whose displacement
    /// resolves to `target`, matching [`crate::memory::address::resolve_rip`]'s
    /// 3-byte opcode assumption (`48 8B 0D <disp32>` and friends).
    pub fn put_rip(&mut self, at: u64, opcode: &[u8; 3], target: u64) -> &mut Self {
        self.put(at, opcode);
        self.put_rel32(at + 3, target)
    }

    /// Reserve `len` zeroed bytes and return their address.
    pub fn alloc(&mut self, len: usize) -> u64 {
        let addr = self.next;
        self.next = (self.next + len as u64).next_multiple_of(ALLOC_ALIGN);
        for i in 0..len as u64 {
            self.bytes.insert(addr + i, 0);
        }
        addr
    }

    pub fn alloc_bytes(&mut self, data: &[u8]) -> u64 {
        let addr = self.alloc(data.len());
        self.put(addr, data);
        addr
    }

    pub fn alloc_cstr(&mut self, value: &str) -> u64 {
        self.alloc_bytes(&[value.as_bytes(), &[0]].concat())
    }

    /// Reserve an array of `count` pointer slots and return its address.
    pub fn alloc_ptrs(&mut self, count: usize) -> u64 {
        self.alloc(count * size_of::<u64>())
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        self.bytes.contains_key(&addr)
    }

    /// Number of contiguous mapped bytes starting at `addr`, capped at `len`.
    fn readable_run(&self, addr: u64, len: usize) -> usize {
        (0..len)
            .take_while(|i| self.bytes.contains_key(&(addr + *i as u64)))
            .count()
    }

    fn copy_out(&self, addr: u64, out: &mut [u8]) -> bool {
        let run = self.readable_run(addr, out.len());
        for (i, slot) in out.iter_mut().take(run).enumerate() {
            *slot = self.bytes[&(addr + i as u64)];
        }
        // A read that could not touch a single mapped byte is a failed read;
        // one that ran off the end of a region keeps what it got.
        run != 0 || out.is_empty()
    }

    fn copy_in(&mut self, addr: u64, data: &[u8]) -> bool {
        if self.readable_run(addr, data.len()) != data.len() {
            return false;
        }
        self.put(addr, data);
        true
    }
}

impl MemoryView for FakeMemory {
    fn read_raw_iter(
        &mut self,
        MemOps {
            inp,
            mut out,
            mut out_fail,
        }: ReadRawMemOps,
    ) -> Result<()> {
        for CTup3(addr, meta, mut data) in inp {
            // A short read reports success on purpose: memflow's failure
            // handler zeroes the whole buffer, which would throw away the
            // readable prefix that a real short read would have returned.
            if self.copy_out(addr.to_umem(), &mut data) {
                opt_call(out.as_deref_mut(), CTup2(meta, data));
            } else {
                opt_call(out_fail.as_deref_mut(), CTup2(meta, data));
            }
        }
        Ok(())
    }

    fn write_raw_iter(
        &mut self,
        MemOps {
            inp,
            mut out,
            mut out_fail,
        }: WriteRawMemOps,
    ) -> Result<()> {
        for CTup3(addr, meta, data) in inp {
            if self.copy_in(addr.to_umem(), &data) {
                opt_call(out.as_deref_mut(), CTup2(meta, data));
            } else {
                opt_call(out_fail.as_deref_mut(), CTup2(meta, data));
            }
        }
        Ok(())
    }

    fn metadata(&self) -> MemoryViewMetadata {
        MemoryViewMetadata {
            max_address: Address::from(u64::MAX),
            real_size: self.bytes.len() as umem,
            readonly: false,
            little_endian: true,
            arch_bits: 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FakeMemory;
    use crate::memory::address;
    use memflow::prelude::v1::*;

    #[test]
    fn reads_back_what_was_written() {
        let mut mem = FakeMemory::new();
        let target = mem.alloc_cstr("weapon_ak47");
        let node = mem.alloc(0x20);
        mem.put_ptr(node + 0x8, target);
        mem.put_u32(node + 0x10, 0xDEAD_BEEF);

        assert_eq!(
            mem.read::<u64>(Address::from(node + 0x8)).data_part().ok(),
            Some(target)
        );
        assert_eq!(
            mem.read::<u32>(Address::from(node + 0x10)).data_part().ok(),
            Some(0xDEAD_BEEF)
        );
        assert_eq!(
            mem.read_utf8_lossy(Address::from(target), 128)
                .data_part()
                .ok()
                .as_deref(),
            Some("weapon_ak47")
        );
    }

    #[test]
    fn unmapped_reads_report_a_partial_failure() {
        let mut mem = FakeMemory::new();
        let mut buf = [0u8; 8];
        assert!(
            mem.read_raw_into(Address::from(0x1000u64), &mut buf)
                .is_err(),
            "a read that touched no mapped byte must report failure"
        );

        // memflow's `read::<T>` folds a partial read into `Ok` with the
        // unreadable bytes left zeroed, so an unmapped pointer surfaces as a
        // null one. Every walker in this crate is written against that
        // behaviour, which is why they range-check instead of trusting `Ok`.
        assert_eq!(
            mem.read::<u64>(Address::from(0x1000u64)).ok(),
            Some(0),
            "read::<T> is documented to zero-fill what it could not read"
        );
    }

    #[test]
    fn a_string_at_the_end_of_a_region_reads_short() {
        let mut mem = FakeMemory::new();
        // Exactly the string plus its terminator is mapped; the 128-byte
        // read must keep the prefix rather than failing outright.
        let text = mem.alloc_cstr("CCSPlayerController");
        assert!(!mem.is_mapped(text + 19 + 1));
        assert_eq!(
            mem.read_utf8_lossy(Address::from(text), 128)
                .data_part()
                .ok()
                .as_deref(),
            Some("CCSPlayerController")
        );
    }

    #[test]
    fn rip_relative_instructions_resolve_to_their_target() {
        let mut mem = FakeMemory::new();
        let global = mem.alloc(0x8);
        let code = mem.alloc(0x10);
        mem.put_rip(code, &[0x48, 0x8B, 0x0D], global);

        let resolved = address::resolve_rip(&mut mem, Address::from(code)).expect("resolve");
        assert_eq!(resolved.to_umem(), global);
    }

    #[test]
    fn allocations_do_not_overlap_and_stay_aligned() {
        let mut mem = FakeMemory::new();
        let first = mem.alloc_cstr("a");
        let second = mem.alloc(1);
        assert!(second >= first + 2);
        assert_eq!(second % 0x10, 0);
        assert!(mem.is_mapped(first));
        assert!(mem.is_mapped(second));
    }
}
