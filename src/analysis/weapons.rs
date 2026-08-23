//! Read-only walker that builds a per-weapon gameplay-values table by reading
//! each spawned weapon entity's `CCSWeaponBaseVData` from live memory.
//!
//! The schema dump already gives the `CCSWeaponBaseVData` field offsets; this
//! reads the actual VALUES. Path (build 14169):
//!   entity list  (via the `pEntitySystem` pattern global)
//!   -> chunked CGameEntitySystem: chunk[i>>9] @ (list + 0x10 + 8*(i>>9))
//!   -> CEntityIdentity inline @ chunk + 0x70*(i & 0x1FF)
//!        identity+0x00 = CEntityInstance*   identity+0x20 = designer-name char*
//!   -> weapon entities (designer name "weapon_*")
//!   -> CCSWeaponBaseVData* at entity + <vdata offset>  (offset validated, see below)
//!
//! Coverage note: only weapons that exist as ENTITIES in the dumped session are
//! captured (held/dropped weapons + view models). Running the dump inside a
//! match / deathmatch / practice-with-bots maximises coverage.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use memflow::prelude::v1::*;
use serde::Serialize;

use crate::analysis::{SchemaMap, entity_list, field_offset};

/// Candidate offsets of the `CCSWeaponBaseVData*` within a weapon entity. The
/// generic `GetVData()` reads +0x340 on 14169; older builds used +0x388. We try
/// each and keep the first that dereferences to a vdata with sane values, so a
/// silent offset drift degrades to "picks the right one" rather than garbage.
const VDATA_PTR_CANDIDATES: &[u64] = &[0x340, 0x348, 0x388, 0x338, 0x350, 0x358];

#[derive(Clone, Copy)]
struct WeaponOffsets {
    price: u64,
    num_bullets: u64,
    cycle_time: u64,
    max_speed: u64,
    spread: u64,
    inaccuracy_stand: u64,
    inaccuracy_move: u64,
    recoil_magnitude: u64,
    damage: u64,
    headshot_multiplier: u64,
    armor_ratio: u64,
    penetration: u64,
    range: u64,
    range_modifier: u64,
}

#[derive(Debug, Serialize)]
pub struct Weapon {
    pub name: String,
    pub damage: i32,
    pub headshot_multiplier: f32,
    pub armor_ratio: f32,
    pub penetration: f32,
    pub range: f32,
    pub range_modifier: f32,
    pub cycle_time: f32,
    pub price: i32,
    pub num_bullets: i32,
    pub max_speed: f32,
    pub spread: f32,
    pub inaccuracy_stand: f32,
    pub inaccuracy_move: f32,
    pub recoil_magnitude: f32,
    /// VA of the CCSWeaponBaseVData object.
    pub address: u64,
    /// Offset the vdata pointer was found at (diagnostic).
    pub vdata_ptr_offset: u64,
}

/// Walk the entity list and collect one entry per distinct weapon.
/// `entity_system_global_va` is the resolved address of the `pEntitySystem`
/// global (a `CGameEntitySystem*`).
pub fn walk<P: MemoryView>(
    process: &mut P,
    entity_system_global_va: u64,
    schemas: &SchemaMap,
) -> Result<Vec<Weapon>> {
    let offsets = weapon_offsets(schemas)
        .ok_or_else(|| anyhow::anyhow!("CCSWeaponBaseVData fields not present in schema"))?;
    let list = rd_u64(process, entity_system_global_va);
    if list == 0 {
        bail!("entity system global is null");
    }

    let layout = entity_list::detect_layout(process, list);
    let mut entities: Vec<(String, u64)> = Vec::new();
    let mut cached_chunk_index = u32::MAX;
    let mut cached_chunk = 0;
    for idx in 0..entity_list::MAX_ENTITY_INDEX {
        let i = idx & entity_list::HANDLE_INDEX_MASK;
        let chunk_index = i >> 9;
        if chunk_index != cached_chunk_index {
            cached_chunk_index = chunk_index;
            cached_chunk = rd_u64(
                process,
                list + layout.chunk_array_base + layout.chunk_ptr_stride * chunk_index as u64,
            );
        }
        let chunk = cached_chunk;
        if chunk == 0 {
            continue;
        }
        let ident = chunk + layout.chunk_entry_stride * (i & entity_list::SLOT_INDEX_MASK) as u64;
        let inst = rd_u64(process, ident + layout.identity_instance);
        if inst == 0 {
            continue;
        }
        let name_ptr = rd_u64(process, ident + layout.identity_designer_name);
        let name = rd_cstr(process, name_ptr);
        if !name.starts_with("weapon_") || entities.iter().any(|(known, _)| known == &name) {
            continue;
        }
        entities.push((name, inst));
    }

    let preferred = select_vdata_offset(process, &entities, offsets);
    let mut by_name: BTreeMap<String, Weapon> = BTreeMap::new();
    for (name, inst) in entities {
        if let Some(w) = read_weapon(process, &name, inst, offsets, preferred) {
            by_name.insert(name, w);
        }
    }

    Ok(by_name.into_values().collect())
}
fn read_weapon<P: MemoryView>(
    process: &mut P,
    name: &str,
    entity: u64,
    offsets: WeaponOffsets,
    preferred: Option<u64>,
) -> Option<Weapon> {
    let mut candidates = Vec::with_capacity(VDATA_PTR_CANDIDATES.len());
    if let Some(off) = preferred {
        candidates.push(off);
    }
    candidates.extend(
        VDATA_PTR_CANDIDATES
            .iter()
            .copied()
            .filter(|off| Some(*off) != preferred),
    );
    for off in candidates {
        let vd = rd_u64(process, entity + off);
        if vd < 0x10000 {
            continue;
        }
        let damage = rd_i32(process, vd + offsets.damage);
        let penetration = rd_f32(process, vd + offsets.penetration);
        let price = rd_i32(process, vd + offsets.price);
        if (1..=1000).contains(&damage)
            && (0.0..=10.0).contains(&penetration)
            && (0..=20000).contains(&price)
        {
            return Some(Weapon {
                name: name.to_string(),
                damage,
                headshot_multiplier: rd_f32(process, vd + offsets.headshot_multiplier),
                armor_ratio: rd_f32(process, vd + offsets.armor_ratio),
                penetration,
                range: rd_f32(process, vd + offsets.range),
                range_modifier: rd_f32(process, vd + offsets.range_modifier),
                cycle_time: rd_f32(process, vd + offsets.cycle_time),
                price,
                num_bullets: rd_i32(process, vd + offsets.num_bullets),
                max_speed: rd_f32(process, vd + offsets.max_speed),
                spread: rd_f32(process, vd + offsets.spread),
                inaccuracy_stand: rd_f32(process, vd + offsets.inaccuracy_stand),
                inaccuracy_move: rd_f32(process, vd + offsets.inaccuracy_move),
                recoil_magnitude: rd_f32(process, vd + offsets.recoil_magnitude),
                address: vd,
                vdata_ptr_offset: off,
            });
        }
    }
    None
}

fn select_vdata_offset<P: MemoryView>(
    process: &mut P,
    entities: &[(String, u64)],
    offsets: WeaponOffsets,
) -> Option<u64> {
    let mut best = None;
    let mut best_score = 0usize;
    for &candidate in VDATA_PTR_CANDIDATES {
        let score = entities
            .iter()
            .filter(|(_, entity)| {
                let vd = rd_u64(process, *entity + candidate);
                if vd < 0x10000 {
                    return false;
                }
                let damage = rd_i32(process, vd + offsets.damage);
                let penetration = rd_f32(process, vd + offsets.penetration);
                let price = rd_i32(process, vd + offsets.price);
                (1..=1000).contains(&damage)
                    && (0.0..=10.0).contains(&penetration)
                    && (0..=20000).contains(&price)
            })
            .count();
        if score > best_score {
            best_score = score;
            best = Some(candidate);
        }
    }
    best
}
fn weapon_offsets(schemas: &SchemaMap) -> Option<WeaponOffsets> {
    let get = |name| field_offset(schemas, "CCSWeaponBaseVData", name);
    Some(WeaponOffsets {
        price: get("m_nPrice")?,
        num_bullets: get("m_nNumBullets")?,
        cycle_time: get("m_flCycleTime")?,
        max_speed: get("m_flMaxSpeed")?,
        spread: get("m_flSpread")?,
        inaccuracy_stand: get("m_flInaccuracyStand")?,
        inaccuracy_move: get("m_flInaccuracyMove")?,
        recoil_magnitude: get("m_flRecoilMagnitude")?,
        damage: get("m_nDamage")?,
        headshot_multiplier: get("m_flHeadshotMultiplier")?,
        armor_ratio: get("m_flArmorRatio")?,
        penetration: get("m_flPenetration")?,
        range: get("m_flRange")?,
        range_modifier: get("m_flRangeModifier")?,
    })
}
// --- read helpers (best-effort) --------------------------------------------

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    process
        .read::<u64>(Address::from(va))
        .data_part()
        .unwrap_or(0)
}
fn rd_i32<P: MemoryView>(process: &mut P, va: u64) -> i32 {
    process
        .read::<i32>(Address::from(va))
        .data_part()
        .unwrap_or(0)
}
fn rd_f32<P: MemoryView>(process: &mut P, va: u64) -> f32 {
    process
        .read::<f32>(Address::from(va))
        .data_part()
        .unwrap_or(0.0)
}
fn rd_cstr<P: MemoryView>(process: &mut P, ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    process
        .read_utf8_lossy(Address::from(ptr), 64)
        .data_part()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{VDATA_PTR_CANDIDATES, select_vdata_offset, walk, weapon_offsets};
    use crate::analysis::entity_list::fixture::ListBuilder;
    use crate::analysis::{Class, ClassField, SchemaMap};
    use crate::memory::fake::FakeMemory;

    /// A compact stand-in `CCSWeaponBaseVData` layout. Only the relative
    /// positions matter — the walk reads whatever the schema says.
    const FIELDS: &[(&str, u64)] = &[
        ("m_nPrice", 0x20),
        ("m_nNumBullets", 0x24),
        ("m_flCycleTime", 0x28),
        ("m_flMaxSpeed", 0x2C),
        ("m_flSpread", 0x30),
        ("m_flInaccuracyStand", 0x34),
        ("m_flInaccuracyMove", 0x38),
        ("m_flRecoilMagnitude", 0x3C),
        ("m_nDamage", 0x40),
        ("m_flHeadshotMultiplier", 0x44),
        ("m_flArmorRatio", 0x48),
        ("m_flPenetration", 0x4C),
        ("m_flRange", 0x50),
        ("m_flRangeModifier", 0x54),
    ];

    fn offset_of(name: &str) -> u64 {
        FIELDS
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, offset)| *offset)
            .expect("unknown test field")
    }

    fn schemas() -> SchemaMap {
        let fields = FIELDS
            .iter()
            .map(|(name, offset)| ClassField {
                name: name.to_string(),
                type_name: "float32".to_string(),
                offset: *offset as i32,
                metadata: Vec::new(),
            })
            .collect();
        SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "CCSWeaponBaseVData".to_string(),
                    module_name: "client.dll".to_string(),
                    parent_name: None,
                    size: 0x80,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields,
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )])
    }

    /// Lay down a `CCSWeaponBaseVData` with the gate-relevant values given and
    /// recognisable stand-ins for everything else.
    fn alloc_vdata(mem: &mut FakeMemory, damage: i32, price: i32, penetration: f32) -> u64 {
        let vdata = mem.alloc(0x80);
        mem.put_i32(vdata + offset_of("m_nPrice"), price);
        mem.put_i32(vdata + offset_of("m_nNumBullets"), 1);
        mem.put_f32(vdata + offset_of("m_flCycleTime"), 0.1);
        mem.put_f32(vdata + offset_of("m_flMaxSpeed"), 215.0);
        mem.put_f32(vdata + offset_of("m_flSpread"), 0.25);
        mem.put_f32(vdata + offset_of("m_flInaccuracyStand"), 6.5);
        mem.put_f32(vdata + offset_of("m_flInaccuracyMove"), 140.0);
        mem.put_f32(vdata + offset_of("m_flRecoilMagnitude"), 30.0);
        mem.put_i32(vdata + offset_of("m_nDamage"), damage);
        mem.put_f32(vdata + offset_of("m_flHeadshotMultiplier"), 4.0);
        mem.put_f32(vdata + offset_of("m_flArmorRatio"), 1.55);
        mem.put_f32(vdata + offset_of("m_flPenetration"), penetration);
        mem.put_f32(vdata + offset_of("m_flRange"), 8192.0);
        mem.put_f32(vdata + offset_of("m_flRangeModifier"), 0.98);
        vdata
    }

    /// Spawn a weapon entity at `index` whose vdata pointer lives at
    /// `vdata_ptr_offset`, and return the vdata VA.
    fn spawn_weapon(
        mem: &mut FakeMemory,
        list: &mut ListBuilder,
        index: u32,
        name: &str,
        vdata_ptr_offset: u64,
        damage: i32,
    ) -> u64 {
        let entity = list.place(mem, index, name);
        let vdata = alloc_vdata(mem, damage, 2700, 1.75);
        mem.put_ptr(entity + vdata_ptr_offset, vdata);
        vdata
    }

    #[test]
    fn the_test_layout_covers_every_field_the_walk_requires() {
        assert!(
            weapon_offsets(&schemas()).is_some(),
            "the fixture must describe all CCSWeaponBaseVData fields"
        );
        assert!(weapon_offsets(&SchemaMap::new()).is_none());
    }

    #[test]
    fn reads_gameplay_values_for_every_spawned_weapon() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let ak = spawn_weapon(&mut mem, &mut list, 12, "weapon_ak47", 0x340, 36);
        spawn_weapon(&mut mem, &mut list, 640, "weapon_deagle", 0x340, 63);
        // Non-weapon entities in the same list must be ignored.
        list.place(&mut mem, 13, "cs_player_controller");

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");

        let names: Vec<_> = found.iter().map(|w| w.name.as_str()).collect();
        assert_eq!(names, vec!["weapon_ak47", "weapon_deagle"]);

        let entry = &found[0];
        assert_eq!(entry.damage, 36);
        assert_eq!(entry.price, 2700);
        assert_eq!(entry.penetration, 1.75);
        assert_eq!(entry.headshot_multiplier, 4.0);
        assert_eq!(entry.range, 8192.0);
        assert_eq!(entry.cycle_time, 0.1);
        assert_eq!(entry.num_bullets, 1);
        assert_eq!(entry.address, ak, "the vdata VA is reported as found");
        assert_eq!(entry.vdata_ptr_offset, 0x340);
    }

    #[test]
    fn the_same_weapon_spawned_twice_is_reported_once() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        spawn_weapon(&mut mem, &mut list, 20, "weapon_ak47", 0x340, 36);
        spawn_weapon(&mut mem, &mut list, 21, "weapon_ak47", 0x340, 36);

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");
        assert_eq!(found.len(), 1);
    }

    /// The whole point of the candidate list: a build that moved the vdata
    /// pointer is followed from live evidence rather than a hardcoded offset.
    #[test]
    fn a_moved_vdata_pointer_is_recovered_from_every_candidate_offset() {
        for &candidate in VDATA_PTR_CANDIDATES {
            let mut mem = FakeMemory::new();
            let mut list = ListBuilder::new(&mut mem);
            spawn_weapon(&mut mem, &mut list, 30, "weapon_ak47", candidate, 36);
            let global = list.global(&mut mem);

            let found = walk(&mut mem, global, &schemas()).expect("walk");
            assert_eq!(found.len(), 1, "candidate {candidate:#X} was not followed");
            assert_eq!(found[0].vdata_ptr_offset, candidate);
            assert_eq!(found[0].damage, 36);
        }
    }

    #[test]
    fn the_offset_that_validates_for_the_most_weapons_wins() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        // Three weapons agree on 0x388.
        for (slot, name) in ["weapon_ak47", "weapon_awp", "weapon_glock"]
            .into_iter()
            .enumerate()
        {
            spawn_weapon(&mut mem, &mut list, 40 + slot as u32, name, 0x388, 36);
        }
        // A fourth also has a plausible-looking pointer at the first candidate
        // offset, which a first-wins scan would have preferred.
        let decoy_entity = list.place(&mut mem, 50, "weapon_deagle");
        let decoy = alloc_vdata(&mut mem, 999, 100, 0.5);
        let real = alloc_vdata(&mut mem, 63, 700, 2.0);
        mem.put_ptr(decoy_entity + 0x340, decoy);
        mem.put_ptr(decoy_entity + 0x388, real);

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");

        assert_eq!(found.len(), 4);
        assert!(
            found.iter().all(|w| w.vdata_ptr_offset == 0x388),
            "consensus must override the candidate ordering: {:?}",
            found.iter().map(|w| w.vdata_ptr_offset).collect::<Vec<_>>()
        );
        let deagle = found.iter().find(|w| w.name == "weapon_deagle").unwrap();
        assert_eq!(deagle.damage, 63, "the decoy vdata must not be reported");
        assert_eq!(deagle.address, real);
    }

    #[test]
    fn an_entity_whose_vdata_fails_the_gates_is_dropped() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let entity = list.place(&mut mem, 60, "weapon_knife");
        // Damage far outside any real weapon's range: this is pointer garbage,
        // not gameplay data, and must not be emitted.
        let junk = alloc_vdata(&mut mem, 50_000, 2700, 1.75);
        mem.put_ptr(entity + 0x340, junk);

        let global = list.global(&mut mem);
        assert!(walk(&mut mem, global, &schemas()).expect("walk").is_empty());
    }

    #[test]
    fn no_weapons_means_no_preferred_offset_rather_than_a_guess() {
        let mut mem = FakeMemory::new();
        let offsets = weapon_offsets(&schemas()).expect("offsets");
        assert_eq!(select_vdata_offset(&mut mem, &[], offsets), None);
    }

    #[test]
    fn a_null_entity_system_global_is_an_error_not_an_empty_table() {
        let mut mem = FakeMemory::new();
        let global = mem.alloc(0x8);
        assert!(walk(&mut mem, global, &schemas()).is_err());
    }

    #[test]
    fn a_schema_without_the_vdata_class_is_an_error() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        spawn_weapon(&mut mem, &mut list, 70, "weapon_ak47", 0x340, 36);
        let global = list.global(&mut mem);

        let error = walk(&mut mem, global, &SchemaMap::new())
            .expect_err("missing schema fields must not silently emit nothing");
        assert!(error.to_string().contains("CCSWeaponBaseVData"), "{error}");
    }
}
