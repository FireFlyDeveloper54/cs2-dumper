//! Where a module keeps its mutable globals.
//!
//! Several anchors in this crate are found by *describing* the object they
//! point at rather than by signing the code that references them (see
//! `schema_anchor` and `entity_anchor` modules).
//! Every such scan needs the same two things: a live copy of the module image
//! and the ranges within it that hold writable data, which is where a global
//! can be. Both live here so the scans agree on where they are allowed to look.
//!
//! During a dump, [`ImageSession`] caches those reads so `client.dll` is not
//! pulled out of the process once per walker. Tests and one-off scans skip the
//! cache so FakeMemory graphs cannot leak across cases.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;

use memflow::prelude::v1::*;

use pelite::pe64::{Pe, PeFile, PeView};

pub type CachedImage = (u64, Arc<[u8]>);
pub type ModuleRecord = (Arc<str>, u64, u64);
pub type ModuleList = Arc<Vec<ModuleRecord>>;
type ImageCache = RefCell<BTreeMap<String, CachedImage>>;

thread_local! {
    static SESSION: Cell<bool> = const { Cell::new(false) };
    static SESSION_ID: Cell<u64> = const { Cell::new(0) };
    static LIVE: ImageCache = const { RefCell::new(BTreeMap::new()) };
    static PE: ImageCache = const { RefCell::new(BTreeMap::new()) };
    static MODULES: RefCell<Option<ModuleList>> = const { RefCell::new(None) };
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static SHARED_MODULES: Mutex<Option<(u64, ModuleList)>> = Mutex::new(None);

fn shared_modules() -> std::sync::MutexGuard<'static, Option<(u64, ModuleList)>> {
    SHARED_MODULES
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Holds the per-dump image cache. Drop clears it so the next run or test
/// cannot see stale bytes. The module-name intern list is also mirrored to
/// `SHARED_MODULES` so rayon workers (no TLS session) can intern `"client.dll"`.
pub struct ImageSession {
    id: u64,
}

impl ImageSession {
    pub fn begin() -> Self {
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        LIVE.with(|c| c.borrow_mut().clear());
        PE.with(|c| c.borrow_mut().clear());
        MODULES.with(|c| *c.borrow_mut() = None);
        SESSION_ID.with(|s| s.set(id));
        SESSION.with(|s| s.set(true));
        Self { id }
    }

    /// Publish the intern table for this session so dump-thread and worker
    /// lookups share the same `"client.dll"` `Arc`.
    pub fn publish_modules(&self, list: ModuleList) {
        store_module_list(list);
    }
}

impl Drop for ImageSession {
    fn drop(&mut self) {
        SESSION.with(|s| s.set(false));
        SESSION_ID.with(|s| s.set(0));
        LIVE.with(|c| c.borrow_mut().clear());
        PE.with(|c| c.borrow_mut().clear());
        MODULES.with(|c| *c.borrow_mut() = None);
        let mut shared = shared_modules();
        if shared.as_ref().is_some_and(|(id, _)| *id == self.id) {
            *shared = None;
        }
    }
}

fn session_active() -> bool {
    SESSION.with(|s| s.get())
}

fn cache_get(map: &'static std::thread::LocalKey<ImageCache>, key: &str) -> Option<CachedImage> {
    if !session_active() {
        return None;
    }
    map.with(|c| c.borrow().get(key).cloned())
}

fn cache_put(map: &'static std::thread::LocalKey<ImageCache>, key: String, value: CachedImage) {
    if !session_active() {
        return;
    }
    map.with(|c| {
        c.borrow_mut().insert(key, value);
    });
}

pub(crate) fn ascii_lower_cow(s: &str) -> Cow<'_, str> {
    if s.as_bytes().iter().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

/// Live mapped image from the current dump session, if this thread already
/// pulled `module` out of the process. Disk PE fallback is not returned.
pub fn cached_live(module: &str) -> Option<CachedImage> {
    cache_get(&LIVE, ascii_lower_cow(module).as_ref())
}

fn intern_from_list(list: &ModuleList, name: &str) -> Option<Arc<str>> {
    list.iter()
        .find(|(n, _, _)| n.as_ref().eq_ignore_ascii_case(name))
        .map(|(n, _, _)| Arc::clone(n))
}

/// Reuse the session module-list `Arc` when `name` is an already-loaded
/// module. Schema type scopes and pattern hits then share `"client.dll"`
/// instead of each allocating their own copy.
///
/// The dump thread reads the TLS list. Rayon workers have no session TLS, so
/// they fall back to the process-wide list published when the session loaded
/// modules. `None` when no dump session has published a list, or when the
/// name is not a loaded module.
///
/// Comparison is ASCII case-insensitive because Toolhelp / PE names and
/// schema type-scope names do not always use the same casing, while the
/// session list is stored lowercase.
pub fn intern_loaded_name(name: &str) -> Option<Arc<str>> {
    let local = MODULES.with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|list| intern_from_list(list, name))
    });
    if local.is_some() {
        return local;
    }
    shared_modules()
        .as_ref()
        .and_then(|(_, list)| intern_from_list(list, name))
}

fn store_module_list(list: ModuleList) {
    let id = SESSION_ID.with(|s| s.get());
    MODULES.with(|c| *c.borrow_mut() = Some(Arc::clone(&list)));
    if id != 0 {
        *shared_modules() = Some((id, list));
    }
}

/// `(name, base, size)` for every loaded module, interned for the dump session.
///
/// Name is lowercase `Arc<str>` so vtable classify and fingerprints can share
/// it without cloning `"client.dll"` once per vtable slot.
pub fn cached_module_list<P: Process + MemoryView>(process: &mut P) -> Result<ModuleList> {
    if session_active()
        && let Some(hit) = MODULES.with(|c| c.borrow().clone())
    {
        return Ok(hit);
    }
    let list = process
        .module_list()
        .map_err(|err| anyhow::anyhow!("failed to list modules: {err}"))?;
    let list: Vec<ModuleRecord> = list
        .into_iter()
        .map(|module| {
            (
                Arc::<str>::from(module.name.to_string().to_ascii_lowercase()),
                module.base.to_umem(),
                module.size,
            )
        })
        .collect();
    let list = Arc::new(list);
    if session_active() {
        store_module_list(Arc::clone(&list));
    }
    Ok(list)
}

/// Live copy of `module`'s mapped image, with its base VA.
///
/// The image is read out of the process rather than off disk, so pointers in it
/// are the relocated values the game is actually using.
pub fn read_image<P: Process + MemoryView>(
    process: &mut P,
    module: &str,
) -> Result<(u64, Arc<[u8]>)> {
    let key = ascii_lower_cow(module);
    if let Some(hit) = cache_get(&LIVE, key.as_ref()) {
        return Ok(hit);
    }
    let info = process.module_by_name(module)?;
    let expected_len = usize::try_from(info.size)
        .map_err(|_| anyhow::anyhow!("module image size does not fit usize"))?;
    let image = process
        .read_raw(info.base, info.size as _)
        .data_part()
        .map_err(|err| anyhow::anyhow!("failed to read image of {module}: {err}"))?;
    if image.len() != expected_len {
        return Err(anyhow::anyhow!(
            "short image read for {module}: got {}, expected {} bytes",
            image.len(),
            expected_len
        ));
    }
    let image: Arc<[u8]> = Arc::from(image);
    let value = (info.base.to_umem(), image);
    cache_put(&LIVE, key.into_owned(), value.clone());
    Ok(value)
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 0x40 && bytes.starts_with(b"MZ")
}

const MAX_MAPPED_PE: usize = 512 * 1024 * 1024;

/// File-layout PE → `SizeOfImage` virtual image so RVA indexes match a mapped view.
///
/// Pattern / offset scanners slice `.text` at `VirtualAddress`. That is only
/// valid on a loaded image; on-disk bytes sit at `PointerToRawData`.
pub fn map_file_pe_to_image(file: &[u8]) -> Result<Vec<u8>> {
    let pe =
        PeFile::from_bytes(file).map_err(|err| anyhow::anyhow!("invalid on-disk PE: {err}"))?;
    let size = usize::try_from(pe.optional_header().SizeOfImage)
        .map_err(|_| anyhow::anyhow!("SizeOfImage does not fit usize"))?;
    if size == 0 || size > MAX_MAPPED_PE {
        anyhow::bail!("unreasonable SizeOfImage {size:#X}");
    }
    let mut mapped = vec![0u8; size];
    let headers = usize::try_from(pe.optional_header().SizeOfHeaders).unwrap_or(0);
    let header_bytes = headers.min(file.len()).min(size);
    mapped[..header_bytes].copy_from_slice(&file[..header_bytes]);
    for section in pe.section_headers() {
        let va = section.VirtualAddress as usize;
        if va >= size {
            continue;
        }
        let raw_ptr = section.PointerToRawData as usize;
        let raw_size = section.SizeOfRawData as usize;
        let virt_size = section.VirtualSize as usize;
        let dest_len = virt_size.min(size - va);
        if raw_ptr >= file.len() || dest_len == 0 {
            continue;
        }
        let src_len = raw_size.min(file.len() - raw_ptr).min(dest_len);
        if src_len > 0 {
            mapped[va..va + src_len].copy_from_slice(&file[raw_ptr..raw_ptr + src_len]);
        }
    }
    Ok(mapped)
}

/// PE bytes for signature scanning. Prefers the live mapped image; if that
/// read fails, falls back to the module file on disk (cs2-best-dumper).
/// Disk images are not relocated, so this must not be used by data-anchor scans.
pub fn read_pe_image<P: Process + MemoryView>(
    process: &mut P,
    module: &str,
) -> Result<(u64, Arc<[u8]>)> {
    let key = ascii_lower_cow(module);
    if let Some(hit) = cache_get(&LIVE, key.as_ref()).filter(|(_, image)| looks_like_pe(image)) {
        return Ok(hit);
    }
    if let Some(hit) = cache_get(&PE, key.as_ref()) {
        return Ok(hit);
    }
    let owned_key = key.into_owned();
    let info = process.module_by_name(module)?;
    let base = info.base.to_umem();
    let expected_len = usize::try_from(info.size).ok();
    match process.read_raw(info.base, info.size as _).data_part() {
        Ok(image) if expected_len == Some(image.len()) && looks_like_pe(&image) => {
            let image: Arc<[u8]> = Arc::from(image);
            let value = (base, image);
            cache_put(&LIVE, owned_key.clone(), value.clone());
            cache_put(&PE, owned_key, value.clone());
            Ok(value)
        }
        live => {
            let path = info.path.to_string();
            if !path.is_empty()
                && let Ok(disk) = std::fs::read(&path)
                && looks_like_pe(&disk)
            {
                log::info!("using on-disk PE for {module} ({path})");
                let mapped = map_file_pe_to_image(&disk)?;
                let image: Arc<[u8]> = Arc::from(mapped);
                let value = (base, image);
                cache_put(&PE, owned_key, value.clone());
                return Ok(value);
            }
            if let Ok(image) = &live
                && expected_len != Some(image.len())
            {
                return Err(anyhow::anyhow!(
                    "short image read for {module}: got {}, expected {} bytes",
                    image.len(),
                    expected_len.unwrap_or(0)
                ));
            }
            live.map(|image| {
                let image: Arc<[u8]> = Arc::from(image);
                let value = (base, image);
                cache_put(&PE, owned_key, value.clone());
                value
            })
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
    use std::sync::Mutex;

    fn intern_tests_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

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

    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_pe64_with_text(payload: &[u8]) -> Vec<u8> {
        const E_LFANEW: usize = 0x80;
        const OPT_SIZE: usize = 0xF0;
        const FILE_ALIGN: u32 = 0x200;
        const SEC_ALIGN: u32 = 0x1000;
        const TEXT_VA: u32 = 0x1000;
        const TEXT_RAW: u32 = 0x200;
        let raw_size = payload.len() as u32;
        let raw_size = raw_size.div_ceil(FILE_ALIGN) * FILE_ALIGN;
        let mut file = vec![0u8; (TEXT_RAW + raw_size) as usize];
        file[0] = b'M';
        file[1] = b'Z';
        put_u32(&mut file, 0x3C, E_LFANEW as u32);
        let nt = E_LFANEW;
        file[nt..nt + 4].copy_from_slice(b"PE\0\0");
        put_u16(&mut file, nt + 4, 0x8664);
        put_u16(&mut file, nt + 6, 1);
        put_u16(&mut file, nt + 20, OPT_SIZE as u16);
        put_u16(&mut file, nt + 22, 0x0022);
        let opt = nt + 24;
        put_u16(&mut file, opt, 0x20B);
        put_u32(&mut file, opt + 16, TEXT_VA);
        put_u32(&mut file, opt + 20, TEXT_VA);
        put_u64(&mut file, opt + 24, 0x1400_0000);
        put_u32(&mut file, opt + 32, SEC_ALIGN);
        put_u32(&mut file, opt + 36, FILE_ALIGN);
        put_u16(&mut file, opt + 40, 6);
        put_u16(&mut file, opt + 48, 6);
        put_u32(&mut file, opt + 56, TEXT_VA + SEC_ALIGN);
        put_u32(&mut file, opt + 60, TEXT_RAW);
        put_u16(&mut file, opt + 68, 3);
        put_u64(&mut file, opt + 72, 0x100000);
        put_u64(&mut file, opt + 80, 0x1000);
        put_u64(&mut file, opt + 88, 0x100000);
        put_u64(&mut file, opt + 96, 0x1000);
        put_u32(&mut file, opt + 108, 16);
        let sec = opt + OPT_SIZE;
        file[sec..sec + 5].copy_from_slice(b".text");
        put_u32(&mut file, sec + 8, payload.len() as u32);
        put_u32(&mut file, sec + 12, TEXT_VA);
        put_u32(&mut file, sec + 16, raw_size);
        put_u32(&mut file, sec + 20, TEXT_RAW);
        put_u32(&mut file, sec + 36, 0x6000_0020);
        let raw = TEXT_RAW as usize;
        file[raw..raw + payload.len()].copy_from_slice(payload);
        file
    }

    #[test]
    fn map_file_pe_to_image_places_sections_at_virtual_addresses() {
        let payload = [0x90u8, 0x90, 0xC3];
        let file = minimal_pe64_with_text(&payload);
        assert_eq!(&file[0x200..0x203], &payload);
        let mapped = super::map_file_pe_to_image(&file).expect("map file PE");
        assert_eq!(mapped.len(), 0x2000);
        assert_eq!(&mapped[0x1000..0x1003], &payload);
        assert_ne!(
            &mapped[0x200..0x203],
            &payload,
            "file offset 0x200 must not be treated as the .text RVA"
        );
        assert_eq!(
            mapped[0x1003], 0,
            "bytes past VirtualSize stay zero in the mapped image"
        );
    }

    #[test]
    fn map_file_pe_to_image_rejects_non_pe_bytes() {
        assert!(super::map_file_pe_to_image(b"MZ not a pe").is_err());
    }

    #[test]
    fn cached_live_is_none_outside_a_session() {
        assert!(super::cached_live("client.dll").is_none());
    }

    #[test]
    fn cached_live_round_trips_inside_a_session() {
        let _session = super::ImageSession::begin();
        assert!(super::cached_live("client.dll").is_none());
        let image: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"MZ\x00\x00"[..]);
        super::cache_put(
            &super::LIVE,
            "client.dll".into(),
            (0x1800_0000, image.clone()),
        );
        let hit = super::cached_live("client.dll").expect("cached");
        assert_eq!(hit.0, 0x1800_0000);
        assert_eq!(&*hit.1, b"MZ\x00\x00");
    }

    #[test]
    fn image_session_drop_clears_the_flag() {
        {
            let _session = super::ImageSession::begin();
            assert!(super::session_active());
        }
        assert!(!super::session_active());
    }

    #[test]
    fn image_session_drop_clears_module_list_cache() {
        {
            let _session = super::ImageSession::begin();
            super::MODULES.with(|c| {
                *c.borrow_mut() = Some(std::sync::Arc::new(Vec::new()));
            });
            assert!(super::MODULES.with(|c| c.borrow().is_some()));
        }
        assert!(super::MODULES.with(|c| c.borrow().is_none()));
    }

    #[test]
    fn intern_loaded_name_is_none_outside_a_session() {
        let _lock = intern_tests_lock();
        assert!(super::intern_loaded_name("client.dll").is_none());
    }

    #[test]
    fn intern_loaded_name_reuses_session_module_arc() {
        let _lock = intern_tests_lock();
        let _session = super::ImageSession::begin();
        let name: std::sync::Arc<str> = std::sync::Arc::from("client.dll");
        _session.publish_modules(std::sync::Arc::new(vec![(
            std::sync::Arc::clone(&name),
            0x1000,
            0x2000,
        )]));
        let interned = super::intern_loaded_name("client.dll").expect("interned");
        assert!(std::sync::Arc::ptr_eq(&name, &interned));
        let mixed = super::intern_loaded_name("CLIENT.DLL").expect("case-insensitive intern");
        assert!(std::sync::Arc::ptr_eq(&name, &mixed));
        assert!(super::intern_loaded_name("engine2.dll").is_none());
    }

    #[test]
    fn intern_loaded_name_is_visible_on_a_worker_thread() {
        let _lock = intern_tests_lock();
        let _session = super::ImageSession::begin();
        let name: std::sync::Arc<str> = std::sync::Arc::from("client.dll");
        _session.publish_modules(std::sync::Arc::new(vec![(
            std::sync::Arc::clone(&name),
            0x1000,
            0x2000,
        )]));
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let interned = super::intern_loaded_name("CLIENT.DLL").expect("worker intern");
                assert!(std::sync::Arc::ptr_eq(&name, &interned));
            });
        });
    }

    #[test]
    fn cached_live_lookup_is_case_insensitive() {
        let _session = super::ImageSession::begin();
        let image: std::sync::Arc<[u8]> = std::sync::Arc::from(&b"MZ\x00\x00"[..]);
        super::cache_put(
            &super::LIVE,
            "client.dll".into(),
            (0x1800_0000, image.clone()),
        );
        let hit = super::cached_live("CLIENT.DLL").expect("cached");
        assert_eq!(hit.0, 0x1800_0000);
        assert_eq!(&*hit.1, b"MZ\x00\x00");
    }

    #[test]
    fn ascii_lower_cow_borrows_already_lowercase() {
        let name = "client.dll";
        let out = super::ascii_lower_cow(name);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert!(std::ptr::eq(out.as_ref().as_ptr(), name.as_ptr()));
        assert_eq!(super::ascii_lower_cow("CLIENT.DLL").as_ref(), "client.dll");
    }
}
