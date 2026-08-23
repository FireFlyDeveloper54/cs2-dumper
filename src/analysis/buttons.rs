use std::collections::{BTreeMap, HashSet};

use anyhow::{Result, bail};

use log::debug;

use memflow::prelude::v1::*;

use pelite::pattern;
use pelite::pe64::{Pe, PeView};

use crate::analysis::module_data;
use crate::source2::KeyButton;

pub type ButtonMap = BTreeMap<String, umem>;

// A normal client build has only a few dozen registered in_* commands. This
// bound makes a stale signature fail cleanly instead of following arbitrary memory.
const MAX_BUTTONS: usize = 256;

pub fn buttons<P: Process + MemoryView>(process: &mut P) -> Result<ButtonMap> {
    let module = process.module_by_name("client.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let view = PeView::from_bytes(&buf)?;

    let mut save = [0; 2];

    if !view
        .scanner()
        .finds_code(pattern!("488b15${'} 4885d2 74? 488b02 4885c0"), &mut save)
    {
        bail!("outdated button list pattern");
    }

    let list_head = process.read_addr64(module.base + save[1]).data_part()?;

    read_buttons(process, &module, list_head)
}

/// Read the button registry through a dynamically resolved global pointer.
/// The pattern pass supplies the current-process VA of the global; this path
/// is used after updates when the legacy local scanner no longer matches.
pub fn buttons_from_global<P: Process + MemoryView>(
    process: &mut P,
    global_va: u64,
) -> Result<ButtonMap> {
    let module = process.module_by_name("client.dll")?;
    let list_head = process.read_addr64(Address::from(global_va)).data_part()?;
    read_buttons(process, &module, list_head)
}

fn read_buttons(
    mem: &mut impl MemoryView,
    module: &ModuleInfo,
    list_head: Address,
) -> Result<ButtonMap> {
    let mut result = ButtonMap::new();
    let mut seen = HashSet::new();
    let module_base = module.base.to_umem();
    let module_end = module_base.saturating_add(module.size as umem);
    let mut button_ptr = Pointer64::<KeyButton>::from(list_head);

    while !button_ptr.is_null() {
        let button_va = button_ptr.address().to_umem();
        if !seen.insert(button_va) {
            bail!("button list contains a cycle at {button_va:#X}");
        }
        if seen.len() > MAX_BUTTONS {
            bail!("button list exceeded {MAX_BUTTONS} entries");
        }

        let button = mem.read_ptr(button_ptr).data_part()?;
        let name = mem.read_utf8_lossy(button.name.address(), 32).data_part()?;
        let state_addr = button_ptr.address() + offset_of!(KeyButton.state);
        let state_va = state_addr.to_umem();

        if is_button_name(&name) && (module_base..module_end).contains(&state_va) {
            let state_rva = state_va - module_base;
            debug!(
                "found \"{}\" at {:#X} ({} + {:#X})",
                name, state_va, module.name, state_rva
            );
            result.insert(name, state_rva);
        }

        button_ptr = button.next;
    }

    Ok(result)
}

fn is_button_name(name: &str) -> bool {
    name.strip_prefix("in_").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

// --- signature-free discovery of the button-list head ----------------------

/// `KeyButton` field offsets, mirroring [`crate::source2::KeyButton`]. Spelled
/// out here because the scan decodes candidate nodes straight out of the module
/// image rather than through a typed read.
const KB_NAME: u64 = 0x08;
const KB_NEXT: u64 = 0x88;

/// Chained `in_*` nodes a candidate head must reach. A client registers dozens;
/// a stray pointer that happens to land on one plausible node reaches one.
const MIN_BUTTON_CHAIN: usize = 8;

/// Locate the button-list global in `module` by describing the list it points
/// at, so the button map survives a recompile that invalidates the
/// `pButtonList` signature.
///
/// This one does not go through [`crate::analysis::global_anchor`], and the
/// reason is the cost model. The entity system, convar registry and event
/// manager are heap objects, so recognising them means reading process memory
/// per candidate. Every `KeyButton` is statically allocated inside `client.dll`
/// and its name is a `.rdata` literal, so the entire chain can be validated
/// inside the image the scan already read: no live reads at all, and the answer
/// does not depend on what the connector happened to have mapped.
pub fn find_button_list<P: Process + MemoryView>(process: &mut P, module: &str) -> Option<u64> {
    let (base, image) = module_data::read_image(process, module).ok()?;
    let ranges = module_data::writable_ranges(&PeView::from_bytes(&image).ok()?);
    find_button_list_in(&image, base, &ranges)
}

/// VA of the global holding the longest chain of `in_*` nodes.
///
/// Every node's `next` field is itself a pointer in writable data, so the tail
/// of the list supplies candidates too — and each reaches a strictly shorter
/// chain than the node before it. The real head is therefore the unique
/// maximum, which is why the chain is counted in full instead of saturating:
/// a saturating score would tie every node above the cap and force a decline.
fn find_button_list_in(image: &[u8], base: u64, ranges: &[(u64, u64)]) -> Option<u64> {
    // (global VA, head VA, chain length)
    let mut best: Option<(u64, u64, usize)> = None;
    let mut ambiguous = false;
    let mut chains: BTreeMap<u64, usize> = BTreeMap::new();
    let mut heads: HashSet<u64> = HashSet::new();

    for &(rva, size) in ranges {
        let start = rva as usize;
        let end = start.saturating_add(size as usize).min(image.len());
        let mut offset = start.next_multiple_of(8);

        while offset + 8 <= end {
            let slot = base + offset as u64;
            let target = u64::from_le_bytes(image[offset..offset + 8].try_into().unwrap());
            offset += 8;

            // The nodes are statically allocated, so a head pointer lands in
            // the module image — which is also what lets the whole chain be
            // validated without touching the process.
            if image_offset(image, base, target).is_none() {
                continue;
            }
            let chain = *chains
                .entry(target)
                .or_insert_with(|| chain_len(image, base, target));
            if chain < MIN_BUTTON_CHAIN || !heads.insert(target) {
                continue;
            }
            match best {
                None => best = Some((slot, target, chain)),
                Some((_, best_head, best_chain)) => {
                    if chain > best_chain {
                        best = Some((slot, target, chain));
                        ambiguous = false;
                    } else if chain == best_chain && target != best_head {
                        // Two different lists of equal length: the scan cannot
                        // tell which one the input system walks, and a wrong
                        // button map reports confident nonsense.
                        ambiguous = true;
                    }
                }
            }
        }
    }

    let (slot, _, _) = best?;
    (!ambiguous).then_some(slot)
}

/// How many chained `in_*` nodes `head` reaches, counting the head itself.
/// Zero when `head` is not a button node at all.
fn chain_len(image: &[u8], base: u64, head: u64) -> usize {
    let mut seen = HashSet::new();
    let mut node = head;
    let mut len = 0usize;

    while node != 0 && seen.insert(node) && len <= MAX_BUTTONS {
        let Some(at) = image_offset(image, base, node) else {
            break;
        };
        let Some(name_ptr) = image_u64(image, at + KB_NAME as usize) else {
            break;
        };
        let name = image_offset(image, base, name_ptr)
            .and_then(|at| image_cstr(image, at))
            .unwrap_or_default();
        if !is_button_name(name) {
            break;
        }
        len += 1;
        node = image_u64(image, at + KB_NEXT as usize).unwrap_or(0);
    }
    len
}

/// Byte offset of `va` within `image`, or `None` when it points outside the
/// module the image is a copy of.
fn image_offset(image: &[u8], base: u64, va: u64) -> Option<usize> {
    let offset = va.checked_sub(base)? as usize;
    (offset < image.len()).then_some(offset)
}

fn image_u64(image: &[u8], at: usize) -> Option<u64> {
    image
        .get(at..at + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
}

/// The NUL-terminated name at `at`, or `None` when it is unterminated within a
/// button name's length or not text.
fn image_cstr(image: &[u8], at: usize) -> Option<&str> {
    let window = image.get(at..(at + 32).min(image.len()))?;
    let end = window.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&window[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memory::fake::FakeMemory;

    const MODULE_BASE: u64 = 0x0000_7FF6_2000_0000;
    const MODULE_SIZE: u64 = 0x0100_0000;

    fn module() -> ModuleInfo {
        ModuleInfo {
            address: Address::from(MODULE_BASE),
            parent_process: Address::from(0u64),
            base: Address::from(MODULE_BASE),
            size: MODULE_SIZE as umem,
            name: ReprCString::from("client.dll"),
            path: ReprCString::from("client.dll"),
            arch: ArchitectureIdent::X86(64, false),
        }
    }

    /// Place a `KeyButton` at a fixed module RVA, the way the real list lives
    /// inside `client.dll`'s data section, and chain it to `next`.
    fn push_button(mem: &mut FakeMemory, rva: u64, name: &str, next: u64) -> u64 {
        let node = MODULE_BASE + rva;
        mem.put(node, &[0u8; 0x90]);
        let name_ptr = mem.alloc_cstr(name);
        mem.put_ptr(node + 0x8, name_ptr);
        mem.put_u32(node + 0x30, 0);
        mem.put_ptr(node + 0x88, next);
        node
    }

    #[test]
    fn accepts_only_client_input_button_names() {
        assert!(is_button_name("in_attack"));
        assert!(is_button_name("in_attack2"));
        assert!(is_button_name("in_toggle_duck"));
        assert!(!is_button_name("in_"));
        assert!(!is_button_name("attack"));
        assert!(!is_button_name("in-attack"));
        assert!(!is_button_name("in_Attack"));
    }

    #[test]
    fn reports_the_state_field_rva_of_each_button() {
        let mut mem = FakeMemory::new();
        let second = push_button(&mut mem, 0x20_0000, "in_jump", 0);
        let head = push_button(&mut mem, 0x10_0000, "in_attack", second);

        let found = read_buttons(&mut mem, &module(), Address::from(head)).expect("walk");

        assert_eq!(found.len(), 2);
        // `state` sits at +0x30 inside the node, and that is what consumers aim at.
        assert_eq!(found.get("in_attack"), Some(&(0x10_0030 as umem)));
        assert_eq!(found.get("in_jump"), Some(&(0x20_0030 as umem)));
    }

    #[test]
    fn a_node_outside_client_dll_is_skipped() {
        let mut mem = FakeMemory::new();
        let inside = push_button(&mut mem, 0x30_0000, "in_use", 0);
        // A node living in some other module must not produce a bogus RVA.
        let stray = mem.alloc(0x90);
        let stray_name = mem.alloc_cstr("in_reload");
        mem.put_ptr(stray + 0x8, stray_name);
        mem.put_ptr(stray + 0x88, inside);

        let found = read_buttons(&mut mem, &module(), Address::from(stray)).expect("walk");
        assert_eq!(found.len(), 1);
        assert_eq!(found.get("in_use"), Some(&(0x30_0030 as umem)));
    }

    #[test]
    fn a_cyclic_button_list_is_rejected() {
        let mut mem = FakeMemory::new();
        let first = push_button(&mut mem, 0x40_0000, "in_attack", 0);
        let second = push_button(&mut mem, 0x41_0000, "in_jump", first);
        mem.put_ptr(first + 0x88, second);

        let error = read_buttons(&mut mem, &module(), Address::from(first))
            .expect_err("a cycle must not be walked forever");
        assert!(error.to_string().contains("cycle"), "{error}");
    }

    #[test]
    fn an_overlong_button_list_is_capped() {
        let mut mem = FakeMemory::new();
        let mut head = 0u64;
        for index in 0..=MAX_BUTTONS as u64 {
            head = push_button(&mut mem, 0x50_0000 + index * 0x100, "in_attack", head);
        }

        let error = read_buttons(&mut mem, &module(), Address::from(head))
            .expect_err("the walk must be bounded");
        assert!(error.to_string().contains("exceeded"), "{error}");
    }

    // --- the signature-free scan, driven entirely off a module image --------

    /// A synthetic `client.dll`: names in a read-only region, nodes and globals
    /// in the writable one, matching how the real list is laid out.
    const NAMES_RVA: u64 = 0x1000;
    const NODES_RVA: u64 = 0x10000;
    const GLOBALS_RVA: u64 = 0x18000;
    const IMAGE_SIZE: u64 = 0x20000;

    struct FakeImage {
        bytes: Vec<u8>,
        next_name: u64,
        next_node: u64,
    }

    impl FakeImage {
        fn new() -> Self {
            Self {
                bytes: vec![0u8; IMAGE_SIZE as usize],
                next_name: NAMES_RVA,
                next_node: NODES_RVA,
            }
        }

        fn put_u64(&mut self, rva: u64, value: u64) {
            self.bytes[rva as usize..][..8].copy_from_slice(&value.to_le_bytes());
        }

        fn name(&mut self, text: &str) -> u64 {
            let rva = self.next_name;
            self.bytes[rva as usize..][..text.len()].copy_from_slice(text.as_bytes());
            self.next_name += text.len() as u64 + 1;
            MODULE_BASE + rva
        }

        /// Append a `KeyButton` node named `name` and chain it to `next`.
        fn node(&mut self, name: &str, next: u64) -> u64 {
            let rva = self.next_node;
            self.next_node += 0x90;
            let name_va = self.name(name);
            self.put_u64(rva + KB_NAME, name_va);
            self.put_u64(rva + KB_NEXT, next);
            MODULE_BASE + rva
        }

        /// Build a list of `count` nodes and return the head, tail-first so the
        /// head is the node reaching every other one.
        fn list(&mut self, count: usize, prefix: &str) -> u64 {
            let mut head = 0u64;
            for index in 0..count {
                head = self.node(&format!("in_{prefix}{index}"), head);
            }
            head
        }

        /// Publish `target` through a global at `rva`, the way client.dll does.
        fn global(&mut self, rva: u64, target: u64) {
            self.put_u64(GLOBALS_RVA + rva, target);
        }

        fn find(&self) -> Option<u64> {
            // The node region is writable too: the real `next` fields live
            // there, and the scan must cope with them being candidates.
            let ranges = [(NODES_RVA, IMAGE_SIZE - NODES_RVA)];
            find_button_list_in(&self.bytes, MODULE_BASE, &ranges)
        }
    }

    /// The point of the scan: the global is found by describing the list, with
    /// no signature over the code that touches it.
    #[test]
    fn finds_the_button_list_global_without_a_signature() {
        let mut image = FakeImage::new();
        let head = image.list(12, "key");
        image.global(0x40, head);

        assert_eq!(image.find(), Some(MODULE_BASE + GLOBALS_RVA + 0x40));
    }

    /// Every node's `next` field is a pointer in writable data, so the list's
    /// own tail competes with the head. The head reaches strictly more nodes,
    /// and that is what must decide it.
    #[test]
    fn the_head_wins_over_its_own_tail() {
        let mut image = FakeImage::new();
        let head = image.list(40, "key");
        image.global(0x40, head);

        let found = image.find().expect("the head must be resolved");
        assert_eq!(found, MODULE_BASE + GLOBALS_RVA + 0x40);
        // Sanity: the tail really was a candidate the scan had to reject.
        assert_eq!(chain_len(&image.bytes, MODULE_BASE, head), 40);
    }

    #[test]
    fn a_module_without_a_button_list_yields_nothing() {
        assert_eq!(FakeImage::new().find(), None);
    }

    /// A lone plausible node is what a stray pointer into `.data` looks like,
    /// so it is not enough to publish an anchor on.
    #[test]
    fn a_short_chain_is_not_enough_evidence() {
        let mut image = FakeImage::new();
        let head = image.list(MIN_BUTTON_CHAIN - 1, "key");
        image.global(0x40, head);

        assert_eq!(image.find(), None);
    }

    /// Two globals on one list are aliases and resolve to the first; two
    /// *different* lists of equal length mean the scan cannot tell which one the
    /// input system walks, so it declines.
    #[test]
    fn aliases_resolve_while_rival_lists_decline() {
        let mut aliased = FakeImage::new();
        let head = aliased.list(12, "key");
        aliased.global(0x40, head);
        aliased.global(0x400, head);
        assert_eq!(aliased.find(), Some(MODULE_BASE + GLOBALS_RVA + 0x40));

        let mut rivals = FakeImage::new();
        let first = rivals.list(12, "a");
        let second = rivals.list(12, "b");
        rivals.global(0x40, first);
        rivals.global(0x400, second);
        assert_eq!(rivals.find(), None);
    }

    /// A node whose name is not an `in_*` command ends the chain, so a region
    /// of pointer-shaped junk cannot accumulate evidence.
    #[test]
    fn a_non_button_name_ends_the_chain() {
        let mut image = FakeImage::new();
        let tail = image.list(MIN_BUTTON_CHAIN, "key");
        let bogus = image.node("CBaseEntity", tail);
        let head = image.node("in_attack", bogus);
        image.global(0x40, head);

        // The head reaches one node before the junk name stops it, and the
        // surviving good chain is published instead — through the `next` field
        // of the node whose name broke the walk.
        assert_eq!(chain_len(&image.bytes, MODULE_BASE, head), 1);
        assert_eq!(chain_len(&image.bytes, MODULE_BASE, tail), MIN_BUTTON_CHAIN);
        assert_eq!(
            image.find(),
            Some(MODULE_BASE + NODES_RVA + 0x90 * MIN_BUTTON_CHAIN as u64 + KB_NEXT)
        );
    }

    /// A `next` pointer that closes a loop must not be counted forever.
    #[test]
    fn a_cyclic_chain_terminates() {
        let mut image = FakeImage::new();
        let head = image.list(12, "key");
        // The first node allocated is the list's last, so pointing it back at
        // the head closes the loop.
        image.put_u64(NODES_RVA + KB_NEXT, head);

        assert_eq!(chain_len(&image.bytes, MODULE_BASE, head), 12);
    }
}
