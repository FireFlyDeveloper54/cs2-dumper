//! Where a module keeps its mutable globals.
//!
//! Several anchors in this crate are found by *describing* the object they
//! point at rather than by signing the code that references them (see
//! [`crate::analysis::schema_anchor`] and [`crate::analysis::entity_anchor`]).
//! Every such scan needs the same two things: a live copy of the module image
//! and the ranges within it that hold writable data, which is where a global
//! can be. Both live here so the scans agree on where they are allowed to look.

use anyhow::Result;

use memflow::prelude::v1::*;

use pelite::pe64::{Pe, PeView};

/// Live copy of `module`'s mapped image, with its base VA.
///
/// The image is read out of the process rather than off disk, so pointers in it
/// are the relocated values the game is actually using.
pub fn read_image<P: Process + MemoryView>(
    process: &mut P,
    module: &str,
) -> Result<(u64, Vec<u8>)> {
    let info = process.module_by_name(module)?;
    let image = process
        .read_raw(info.base, info.size as _)
        .data_part()
        .map_err(|err| anyhow::anyhow!("failed to read image of {module}: {err}"))?;
    Ok((info.base.to_umem(), image))
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 0x40 && bytes.starts_with(b"MZ")
}

/// PE bytes for signature scanning. Prefers the live mapped image; if that
/// read fails, falls back to the module file on disk (cs2-best-dumper).
/// Disk images are not relocated, so this must not be used by data-anchor scans.
pub fn read_pe_image<P: Process + MemoryView>(
    process: &mut P,
    module: &str,
) -> Result<(u64, Vec<u8>)> {
    let info = process.module_by_name(module)?;
    let base = info.base.to_umem();
    match process.read_raw(info.base, info.size as _).data_part() {
        Ok(image) if looks_like_pe(&image) => Ok((base, image)),
        live => {
            let path = info.path.to_string();
            if !path.is_empty() {
                if let Ok(disk) = std::fs::read(&path) {
                    if looks_like_pe(&disk) {
                        log::info!("using on-disk PE for {module} ({path})");
                        return Ok((base, disk));
                    }
                }
            }
            live.map(|image| (base, image))
                .map_err(|err| anyhow::anyhow!("failed to read image of {module}: {err}"))
        }
    }
}

/// `(rva, size)` of every writable, non-executable section: where a module's
/// mutable globals live, and so where an anchor scan looks.
pub fn writable_ranges(view: &PeView<'_>) -> Vec<(u64, u64)> {
    ranges_of(view.section_headers().iter().map(|section| {
        (
            section.Characteristics,
            section.VirtualAddress,
            section.VirtualSize,
        )
    }))
}

/// Section filter behind [`writable_ranges`], split out so the choice of where
/// to scan is checkable without a real PE image.
fn ranges_of<I: IntoIterator<Item = (u32, u32, u32)>>(sections: I) -> Vec<(u64, u64)> {
    sections
        .into_iter()
        .filter(|(characteristics, _, size)| {
            characteristics & pelite::image::IMAGE_SCN_MEM_WRITE != 0
                && characteristics & pelite::image::IMAGE_SCN_MEM_EXECUTE == 0
                && *size > 0
        })
        .map(|(_, rva, size)| (rva as u64, size as u64))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ranges_of;

    /// An anchor scan must look only where mutable globals live: scanning
    /// `.text` wastes the whole image, and skipping a writable section would
    /// hide the object being looked for.
    #[test]
    fn only_writable_non_executable_sections_are_scanned() {
        use pelite::image::{
            IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
            IMAGE_SCN_MEM_WRITE,
        };

        let text = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        let rdata = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        let data = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        // Some linkers emit writable code sections; those are not data.
        let wx = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

        let ranges = ranges_of([
            (text, 0x1000, 0x8000),
            (rdata, 0x9000, 0x2000),
            (data, 0xB000, 0x3000),
            (wx, 0xE000, 0x1000),
            // An empty writable section has nothing to find in it.
            (data, 0xF000, 0),
            (data, 0x10000, 0x400),
        ]);

        assert_eq!(ranges, vec![(0xB000, 0x3000), (0x10000, 0x400)]);
    }
}
