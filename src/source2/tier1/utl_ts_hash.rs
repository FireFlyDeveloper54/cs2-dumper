use std::collections::HashSet;

use memflow::prelude::v1::*;

use super::UtlMemoryPool;

#[repr(C)]
pub struct UtlTsHashAllocatedBlob<D> {
    pub next: Pointer64<UtlTsHashAllocatedBlob<D>>, // 0x0000
    pad_0: [u8; 0x8],                               // 0x0008
    pub data: Pointer64<D>,                         // 0x0010
    pad_1: [u8; 0x18],                              // 0x0018
}

unsafe impl<D: 'static> Pod for UtlTsHashAllocatedBlob<D> {}

#[repr(C)]
pub struct UtlTsHashFixedData<D, K> {
    pub ui_key: K,                                 // 0x0000
    pub next: Pointer64<UtlTsHashFixedData<D, K>>, // 0x0008
    pub data: Pointer64<D>,                        // 0x0010
}

unsafe impl<D: 'static, K: 'static> Pod for UtlTsHashFixedData<D, K> {}

#[repr(C)]
pub struct UtlTsHashBucket<D, K> {
    pub add_lock: usize,                                        // 0x0000
    pub first: Pointer64<UtlTsHashFixedData<D, K>>,             // 0x0008
    pub first_uncommitted: Pointer64<UtlTsHashFixedData<D, K>>, // 0x0010
}

#[repr(C)]
pub struct UtlTsHash<D, const C: usize = 256, K = u64> {
    pub entry_mem: UtlMemoryPool,            // 0x0000
    pub buckets: [UtlTsHashBucket<D, K>; C], // 0x0060
    pub needs_commit: bool,                  // 0x1860
    pad_0: [u8; 0x3],                        // 0x1861
    pub contention_check: i32,               // 0x1864
    pad_1: [u8; 0x8],                        // 0x1868
}

impl<D: Pod, const C: usize, K: Pod> UtlTsHash<D, C, K> {
    pub fn elements(&self, mem: &mut impl MemoryView) -> Vec<Pointer64<D>> {
        let allocated = self.allocated_elements(mem);
        let unallocated = self.unallocated_elements(mem);

        let mut result = Vec::with_capacity(allocated.len() + unallocated.len());

        result.extend(allocated);
        result.extend(unallocated);

        let mut seen = HashSet::with_capacity(result.capacity());

        // Remove duplicate pointers that exist in both lists.
        result.retain(|ptr| seen.insert(ptr.address().to_umem()));

        result
    }

    fn allocated_elements(&self, mem: &mut impl MemoryView) -> Vec<Pointer64<D>> {
        let used_count = bounded_count(self.entry_mem.blocks_allocated);
        if used_count == 0 {
            return Vec::new();
        }

        let mut elements = Vec::with_capacity(used_count);
        let mut seen_nodes = HashSet::new();

        'buckets: for bucket in &self.buckets {
            let mut node_ptr = bucket.first_uncommitted;

            while !node_ptr.is_null() {
                if !seen_nodes.insert(node_ptr.address().to_umem()) {
                    break;
                }
                let node = match mem.read_ptr(node_ptr).data_part() {
                    Ok(n) => n,
                    Err(_) => break,
                };

                if !node.data.is_null() {
                    elements.push(node.data);
                }

                // The pool counts blocks across every bucket, so reaching that
                // total means the walk is finished — not that this bucket is.
                // Leaving the outer loop running read one head per remaining
                // bucket and pushed elements past the count.
                if elements.len() >= used_count {
                    break 'buckets;
                }

                node_ptr = node.next;
            }
        }

        // `blocks_allocated` is also a lower bound, and this is the only place
        // that can say so. The walk starts at `first_uncommitted`, which points
        // *into* each bucket's chain rather than at its head, so a hash whose
        // `Commit()` has run loses every node before that point — and nothing
        // downstream can tell a scope that really has 40 classes from one with
        // 4000 of which 3960 were unreachable.
        if elements.len() < used_count {
            log::warn!(
                "hash walk reached {} of {} allocated node(s) (needs_commit = {}); \
                 the rest are absent from this dump, not absent from the game",
                elements.len(),
                used_count,
                self.needs_commit,
            );
        }

        elements
    }

    fn unallocated_elements(&self, mem: &mut impl MemoryView) -> Vec<Pointer64<D>> {
        let free_count = bounded_count(self.entry_mem.peak_allocated);
        if free_count == 0 {
            return Vec::new();
        }

        let mut elements = Vec::with_capacity(free_count);
        let mut seen_nodes = HashSet::new();

        let mut blob_ptr = Pointer64::<UtlTsHashAllocatedBlob<D>>::from(
            self.entry_mem.free_blocks.head.next.address(),
        );

        while !blob_ptr.is_null() {
            if !seen_nodes.insert(blob_ptr.address().to_umem()) {
                break;
            }
            let blob = match mem.read_ptr(blob_ptr).data_part() {
                Ok(b) => b,
                Err(_) => break,
            };

            if !blob.data.is_null() {
                elements.push(blob.data);
            }

            if elements.len() >= free_count {
                break;
            }

            blob_ptr = blob.next;
        }

        elements
    }
}

const MAX_HASH_ELEMENTS: usize = 1_000_000;

fn bounded_count(value: i32) -> usize {
    usize::try_from(value).unwrap_or(0).min(MAX_HASH_ELEMENTS)
}

unsafe impl<D: 'static, const C: usize, K: 'static> Pod for UtlTsHash<D, C, K> {}

#[cfg(test)]
mod tests {
    use super::{MAX_HASH_ELEMENTS, bounded_count};

    #[test]
    fn bounds_remote_hash_counts() {
        assert_eq!(bounded_count(-1), 0);
        assert_eq!(bounded_count(0), 0);
        assert_eq!(bounded_count(42), 42);
        assert_eq!(bounded_count(i32::MAX), MAX_HASH_ELEMENTS);
    }
}
