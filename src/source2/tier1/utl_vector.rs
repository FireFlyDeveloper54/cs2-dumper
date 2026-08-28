use std::mem::size_of;

use memflow::prelude::v1::*;

#[repr(C)]
pub struct UtlVector<T> {
    pub count: i32,           // 0x0000
    pad_0: [u8; 0x4],         // 0x0004
    pub data: Pointer64<[T]>, // 0x0008
}

impl<T: Pod> UtlVector<T> {
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

unsafe impl<T: 'static> Pod for UtlVector<T> {}

#[cfg(test)]
mod tests {
    use super::UtlVector;
    use crate::memory::fake::FakeMemory;
    use memflow::prelude::v1::*;

    #[test]
    fn rejects_wrapping_element_addresses() {
        let vector = UtlVector::<u32> {
            count: 2,
            pad_0: [0; 4],
            data: Pointer64::from(u64::MAX - 1),
        };
        assert!(vector.element(&mut FakeMemory::new(), 1).is_err());
    }
}
