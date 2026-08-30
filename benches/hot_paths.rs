//! Microbenchmarks of the dump's real hot paths.
//!
//! These call the same public functions the exe uses. They do not attach to
//! `cs2.exe` and they do not reimplement the matcher, intern table, or
//! identifier sanitizer.

use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use cs2_dumper::analysis::module_data::{ImageSession, intern_loaded_name};
use cs2_dumper::analysis::read::{u32_le_at, u64_le_at};
use cs2_dumper::output::ident::{slugify, type_ident};
use cs2_dumper::patterns::database::CS2_PATTERNS;
use cs2_dumper::patterns::{CachedPatternHit, PatternCache, PatternCacheIndex, find_ida};

const HAYSTACK: usize = 1 << 20;
const PLANT_AT: usize = 0x000A_BCDE;

fn short_criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(300))
        .measurement_time(Duration::from_secs(1))
        .sample_size(40)
}

fn packed_offset_table() -> Vec<u8> {
    (0u64..1024)
        .flat_map(|i| (i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes())
        .collect()
}

fn le_loads(c: &mut Criterion) {
    let table = packed_offset_table();
    c.bench_function("read::u32_le_at / u64_le_at over 1024 slots", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            let mut off = 0usize;
            while off + 8 <= table.len() {
                acc ^= u32_le_at(&table, off).unwrap() as u64;
                acc ^= u64_le_at(&table, off).unwrap();
                off += 8;
            }
            black_box(acc)
        });
    });
}

fn typical_modules() -> Vec<(Arc<str>, u64, u64)> {
    const NAMES: &[&str] = &[
        "client.dll",
        "engine2.dll",
        "schemasystem.dll",
        "animationsystem.dll",
        "scenesystem.dll",
        "resourcesystem.dll",
        "materialsystem2.dll",
        "soundsystem.dll",
        "particles.dll",
        "panorama.dll",
        "worldrenderer.dll",
        "pulse_system.dll",
        "server.dll",
        "host.dll",
        "networksystem.dll",
        "inputsystem.dll",
        "localize.dll",
        "matchmaking.dll",
        "vphysics2.dll",
        "meshsystem.dll",
    ];
    NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            (
                Arc::<str>::from(*name),
                0x0000_1800_0000 + i as u64 * 0x0100_0000,
                0x0020_0000,
            )
        })
        .collect()
}

fn intern_hit(c: &mut Criterion) {
    let session = ImageSession::begin();
    let modules = typical_modules();
    session.publish_modules(Arc::new(modules));
    const LOOKUPS: &[&str] = &[
        "client.dll",
        "CLIENT.DLL",
        "Client.Dll",
        "engine2.dll",
        "SCHEMASYSTEM.DLL",
        "schemasystem.dll",
        "animationsystem.dll",
        "inputsystem.dll",
        "particles.dll",
        "PANORAMA.DLL",
    ];
    c.bench_function("intern_loaded_name hit (case-insensitive)", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for name in LOOKUPS {
                hits += intern_loaded_name(black_box(name)).is_some() as usize;
            }
            black_box(hits)
        });
    });
    drop(session);
}

fn intern_miss(c: &mut Criterion) {
    let session = ImageSession::begin();
    session.publish_modules(Arc::new(typical_modules()));
    const LOOKUPS: &[&str] = &[
        "not_loaded.dll",
        "cs2.exe",
        "ntdll.dll",
        "missing_module.dll",
        "engine.dll",
    ];
    c.bench_function("intern_loaded_name miss", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for name in LOOKUPS {
                hits += intern_loaded_name(black_box(name)).is_some() as usize;
            }
            black_box(hits)
        });
    });
    drop(session);
}

fn shipped_cache() -> PatternCache {
    PatternCache {
        hits: CS2_PATTERNS
            .iter()
            .map(|pattern| CachedPatternHit {
                name: pattern.name.to_string(),
                module: pattern.module.to_string(),
                pattern: pattern.needle.to_string(),
                found: true,
                match_rva: Some(0x1000),
                matches: 1,
            })
            .collect(),
    }
}

fn pattern_cache_build(c: &mut Criterion) {
    let cache = shipped_cache();
    c.bench_function("PatternCacheIndex::from_cache (shipped DB)", |b| {
        b.iter(|| PatternCacheIndex::from_cache(black_box(Some(&cache))));
    });
}

fn pattern_cache_get(c: &mut Criterion) {
    let cache = shipped_cache();
    let index = PatternCacheIndex::from_cache(Some(&cache));
    let add_nametag = CS2_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "AddNametagEntity")
        .expect("shipped AddNametagEntity pattern");
    c.bench_function("PatternCacheIndex::get every shipped pattern", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for pattern in CS2_PATTERNS {
                hits += index
                    .get(
                        black_box(pattern.module),
                        black_box(pattern.name),
                        black_box(pattern.needle),
                    )
                    .is_some() as usize;
            }
            // Mixed-case module names are how Toolhelp / schema scopes show up.
            hits += index
                .get("CLIENT.DLL", add_nametag.name, add_nametag.needle)
                .is_some() as usize;
            black_box(hits)
        });
    });
}

fn plant_ida(hay: &mut [u8], at: usize, needle: &str) {
    for (i, tok) in (at..).zip(needle.split_ascii_whitespace()) {
        if tok != "?" && tok != "??" {
            let byte = u8::from_str_radix(tok, 16)
                .unwrap_or_else(|_| panic!("bench needle token {tok:?} must be hex or wildcard"));
            hay[i] = byte;
        }
    }
}

fn find_ida_scan(c: &mut Criterion) {
    let pattern = CS2_PATTERNS
        .iter()
        .find(|pattern| pattern.name == "AddNametagEntity")
        .expect("shipped AddNametagEntity pattern");
    let mut hay = vec![0u8; HAYSTACK];
    let mut state = 0xA5A5_C3C3u32;
    for byte in &mut hay {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8;
    }
    plant_ida(&mut hay, PLANT_AT, pattern.needle);
    let hits = find_ida(&hay, pattern.needle).expect("parse shipped needle");
    assert!(
        hits.contains(&PLANT_AT),
        "planted {PLANT_AT:#x} missing from {hits:?}"
    );

    c.bench_function("find_ida AddNametagEntity in 1MiB haystack", |b| {
        b.iter(|| find_ida(black_box(&hay), black_box(pattern.needle)).unwrap());
    });
}

fn ident_slugify(c: &mut Criterion) {
    const CLEAN: &[&str] = &[
        "C_CSPlayerPawn",
        "m_iHealth",
        "CCSPlayerController",
        "dwEntityList",
        "CGameEntitySystem",
    ];
    const DIRTY: &[&str] = &[
        "client.dll",
        "engine2.dll",
        "CHandle< C_BaseEntity >",
        "Foo::Bar",
        "3d_type",
    ];
    c.bench_function("slugify already-ident names", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for name in CLEAN {
                n += slugify(black_box(name)).len();
            }
            black_box(n)
        });
    });
    c.bench_function("slugify punctuation / leading digit", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for name in DIRTY {
                n += slugify(black_box(name)).len();
            }
            black_box(n)
        });
    });
    c.bench_function("type_ident template stems", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for name in DIRTY {
                n += type_ident(black_box(name)).len();
            }
            black_box(n)
        });
    });
}

criterion_group! {
    name = hot_paths;
    config = short_criterion();
    targets = le_loads, intern_hit, intern_miss, pattern_cache_build, pattern_cache_get, find_ida_scan, ident_slugify
}
criterion_main!(hot_paths);
