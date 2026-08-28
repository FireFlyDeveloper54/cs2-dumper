use std::mem::size_of;

use memflow::prelude::v1::*;

#[repr(C)]
pub struct UtlMemory<T> {
    pub data: Pointer64<[T]>, // 0x0000
    pub count: i32,           // 0x0008
    pub grow_size: i32,       // 0x000C
}

impl<T: Pod> UtlMemory<T> {
    #[inline]
    pub fn is_externally_allocated(&self) -> bool {
        self.grow_size < 0
    }

    pub fn element(&self, mem: &mut impl MemoryView, index: usize) -> Result<T> {
        if self.count < 0 || index >= self.count as usize {
            return Err(ErrorKind::OutOfBounds.into());
        }

        let stride = size_of::<T>() as u64;
        let offset = stride
            .checked_mul(index as u64)
            .ok_or(ErrorKind::OutOfBounds)?;
        let address = self
            .data
            .to_umem()
            .checked_add(offset)
            .ok_or(ErrorKind::OutOfBounds)?;
        mem.read_ptr(Pointer64::from(Address::from(address))).data_part()
    }
}

#[cfg(test)]
mod tests {
    use super::UtlMemory;
    use crate::memory::fake::FakeMemory;
    use memflow::prelude::v1::*;

    #[test]
    fn rejects_negative_counts_and_wrapping_addresses() {
        let negative = UtlMemory::<u32> {
            data: Pointer64::null(),
            count: -1,
            grow_size: 0,
        };
        assert!(negative.element(&mut FakeMemory::new(), 0).is_err());

        let wrapping = UtlMemory::<u32> {
            data: Pointer64::from(u64::MAX - 1),
            count: 2,
            grow_size: 0,
        };
        assert!(wrapping.element(&mut FakeMemory::new(), 1).is_err());
    }
}
