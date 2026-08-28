use memflow::prelude::*;

#[inline]
pub fn resolve_rip(mem: &mut impl MemoryView, base: Address) -> Result<Address> {
    rel32_target(mem, base, 0x3)
}

fn rel32_target(mem: &mut impl MemoryView, base: Address, offset: usize) -> Result<Address> {
    let field = base
        .to_umem()
        .checked_add(offset as u64)
        .ok_or(ErrorKind::OutOfBounds)?;
    let rel32: i32 = mem.read(Address::from(field)).data_part()?; // RIP-relative displacement.
    let instr_end = field
        .checked_add(size_of::<i32>() as u64)
        .ok_or(ErrorKind::OutOfBounds)?;
    let target = instr_end as i128 + rel32 as i128;
    if !(0..=u64::MAX as i128).contains(&target) {
        return Err(ErrorKind::OutOfBounds.into());
    }
    Ok((target as u64).into())
}
