//! Read-only "live entity snapshot" — walks the CGameEntitySystem entity list
//! and decodes each entity's index, classname, and a few universal
//! `C_BaseEntity` fields (health, team, world origin) at their schema offsets.
//!
//! Reuses the chunked entity-list geometry from the weapons walk. Coverage is
//! whatever exists in the world at dump time (a genuine live snapshot). All
//! reads are best-effort + sanity-gated so non-spatial/logic entities don't
//! emit pointer garbage.

use anyhow::{Result, bail};
use memflow::prelude::v1::*;
use serde::Serialize;

use crate::analysis::{SchemaMap, class_index, entity_list, field_offset_in};

#[derive(Debug, Serialize)]
pub struct EntitySnapshotEntry {
    pub index: u32,
    pub classname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_health: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<[f32; 3]>,
}

pub fn walk<P: MemoryView>(
    process: &mut P,
    entity_system_global_va: u64,
    schemas: &SchemaMap,
) -> Result<Vec<EntitySnapshotEntry>> {
    let list = rd_u64(process, entity_system_global_va);
    if list == 0 {
        bail!("entity system global is null");
    }
    let layout = entity_list::detect_layout(process, list);

    let classes = class_index(schemas);
    let off_scene_node = field_offset_in(&classes, "C_BaseEntity", "m_pGameSceneNode");
    let off_max_health = field_offset_in(&classes, "C_BaseEntity", "m_iMaxHealth");
    let off_health = field_offset_in(&classes, "C_BaseEntity", "m_iHealth");
    let off_team = field_offset_in(&classes, "C_BaseEntity", "m_iTeamNum");
    let off_origin = field_offset_in(&classes, "CGameSceneNode", "m_vecAbsOrigin");
    let mut out = Vec::new();
    for entity in entity_list::live_entities(process, list, layout) {
        let inst = entity.instance;

        // Universal C_BaseEntity fields — sanity-gated so logic/non-spatial
        // entities that don't actually have these don't emit garbage.
        let health = off_health.and_then(|off| {
            let value = rd_i32(process, inst.checked_add(off)?);
            (-16384..=1_000_000).contains(&value).then_some(value)
        });
        let max_health = off_max_health.and_then(|off| {
            let value = rd_i32(process, inst.checked_add(off)?);
            (0..=1_000_000).contains(&value).then_some(value)
        });
        let team = off_team.and_then(|off| {
            let value = rd_u8(process, inst.checked_add(off)?);
            (value <= 4).then_some(value)
        });

        let scene = off_scene_node
            .and_then(|off| inst.checked_add(off))
            .map(|va| rd_u64(process, va))
            .unwrap_or(0);
        let origin = (scene > 0x10000)
            .then(|| {
                let base = off_origin?;
                let x = scene.checked_add(base)?;
                let y = x.checked_add(4)?;
                let z = x.checked_add(8)?;
                let o = [rd_f32(process, x), rd_f32(process, y), rd_f32(process, z)];
                let ok = o.iter().all(|c| c.is_finite() && c.abs() < 1_048_576.0);
                ok.then_some(o)
            })
            .flatten();

        out.push(EntitySnapshotEntry {
            index: entity.index,
            classname: entity.classname,
            health,
            max_health,
            team,
            origin,
        });
    }

    Ok(out)
}

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    crate::analysis::read::u64_va(process, va)
}
fn rd_i32<P: MemoryView>(process: &mut P, va: u64) -> i32 {
    crate::analysis::read::or(process, va, i32::MIN)
}
fn rd_u8<P: MemoryView>(process: &mut P, va: u64) -> u8 {
    crate::analysis::read::or(process, va, 0xFF)
}
fn rd_f32<P: MemoryView>(process: &mut P, va: u64) -> f32 {
    crate::analysis::read::or(process, va, f32::NAN)
}

#[cfg(test)]
mod tests {
    use super::walk;
    use crate::analysis::entity_list::fixture::ListBuilder;
    use crate::analysis::{Class, ClassField, SchemaMap};
    use crate::memory::fake::FakeMemory;

    const OFF_SCENE_NODE: i32 = 0x0328;
    const OFF_MAX_HEALTH: i32 = 0x0334;
    const OFF_HEALTH: i32 = 0x0338;
    const OFF_TEAM: i32 = 0x03E3;
    const OFF_ORIGIN: i32 = 0x00D0;

    fn field(name: &str, offset: i32) -> ClassField {
        ClassField {
            name: name.to_string(),
            type_name: "int32".to_string(),
            offset,
            metadata: Vec::new(),
        }
    }

    fn class(name: &str, fields: Vec<ClassField>) -> Class {
        Class {
            name: name.to_string(),
            module_name: "client.dll".into(),
            parent_name: None,
            size: 0x1000,
            alignment: 8,
            metadata: Vec::new(),
            fields,
            static_fields: Vec::new(),
            flags: Vec::new(),
        }
    }

    /// A schema map holding only the fields the snapshot walk looks up.
    fn schemas() -> SchemaMap {
        SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![
                    class(
                        "C_BaseEntity",
                        vec![
                            field("m_pGameSceneNode", OFF_SCENE_NODE),
                            field("m_iMaxHealth", OFF_MAX_HEALTH),
                            field("m_iHealth", OFF_HEALTH),
                            field("m_iTeamNum", OFF_TEAM),
                        ],
                    ),
                    class("CGameSceneNode", vec![field("m_vecAbsOrigin", OFF_ORIGIN)]),
                ],
                Vec::new(),
            ),
        )])
    }

    /// Give `instance` a `CGameSceneNode` whose absolute origin is `origin`.
    fn attach_scene_node(mem: &mut FakeMemory, instance: u64, origin: [f32; 3]) {
        let node = mem.alloc(0x200);
        mem.put_ptr(instance + OFF_SCENE_NODE as u64, node);
        for (axis, value) in origin.iter().enumerate() {
            mem.put_f32(node + OFF_ORIGIN as u64 + axis as u64 * 4, *value);
        }
    }

    #[test]
    fn snapshots_every_live_entity_with_its_schema_fields() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);

        let player = list.place(&mut mem, 1, "cs_player_controller");
        mem.put_i32(player + OFF_HEALTH as u64, 87);
        mem.put_i32(player + OFF_MAX_HEALTH as u64, 100);
        mem.put_u8(player + OFF_TEAM as u64, 3);
        attach_scene_node(&mut mem, player, [1.5, -2.0, 64.25]);

        // A late index proves the chunk arithmetic: 600 >> 9 == chunk 1,
        // 600 & 0x1FF == slot 88.
        let world = list.place(&mut mem, 600, "worldent");
        mem.put_i32(world + OFF_HEALTH as u64, 0);
        mem.put_u8(world + OFF_TEAM as u64, 0);

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");

        let seen: Vec<_> = found
            .iter()
            .map(|entry| (entry.index, entry.classname.as_str()))
            .collect();
        assert_eq!(seen, vec![(1, "cs_player_controller"), (600, "worldent")]);

        let entry = &found[0];
        assert_eq!(entry.health, Some(87));
        assert_eq!(entry.max_health, Some(100));
        assert_eq!(entry.team, Some(3));
        assert_eq!(entry.origin, Some([1.5, -2.0, 64.25]));

        // The world entity has no scene node, so no origin is invented for it.
        assert_eq!(found[1].origin, None);
    }

    #[test]
    fn out_of_range_field_values_are_dropped_rather_than_emitted() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);

        // A logic entity that happens to have pointer bytes where a player
        // would have health, team and a scene node.
        let logic = list.place(&mut mem, 2, "logic_relay");
        mem.put_i32(logic + OFF_HEALTH as u64, i32::MAX);
        mem.put_i32(logic + OFF_MAX_HEALTH as u64, -5);
        mem.put_u8(logic + OFF_TEAM as u64, 9);
        attach_scene_node(&mut mem, logic, [f32::NAN, 0.0, 0.0]);

        let far = list.place(&mut mem, 3, "prop_physics");
        attach_scene_node(&mut mem, far, [2_000_000.0, 0.0, 0.0]);

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");

        assert_eq!(found.len(), 2);
        assert_eq!(found[0].classname, "logic_relay");
        assert_eq!(found[0].health, None);
        assert_eq!(found[0].max_health, None);
        assert_eq!(found[0].team, None);
        assert_eq!(found[0].origin, None, "a NaN coordinate must be rejected");
        assert_eq!(
            found[1].origin, None,
            "a coordinate outside the world bounds must be rejected"
        );
    }

    #[test]
    fn an_identity_without_a_designer_name_is_skipped() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        list.place(&mut mem, 7, "func_brush");

        // A slot with a live instance but a null name pointer is half-torn-down
        // and must not reach the output as a blank classname.
        let ident = list.identity(&mut mem, 8);
        let instance = mem.alloc(0x600);
        mem.put_ptr(ident, instance);

        let global = list.global(&mut mem);
        let found = walk(&mut mem, global, &schemas()).expect("walk");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].index, 7);
    }

    #[test]
    fn a_null_entity_system_global_is_an_error_not_an_empty_snapshot() {
        let mut mem = FakeMemory::new();
        let global = mem.alloc(0x8);
        assert!(walk(&mut mem, global, &schemas()).is_err());
    }

    #[test]
    fn a_schema_without_the_expected_fields_still_lists_the_entities() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let entity = list.place(&mut mem, 4, "weapon_ak47");
        mem.put_i32(entity + OFF_HEALTH as u64, 42);
        let global = list.global(&mut mem);

        // An empty schema map means no field offsets resolve; the walk must
        // still report the identity instead of failing.
        let found = walk(&mut mem, global, &SchemaMap::new()).expect("walk");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].classname, "weapon_ak47");
        assert_eq!(found[0].health, None);
        assert_eq!(found[0].origin, None);
    }

    #[test]
    fn a_scene_without_an_origin_schema_field_does_not_emit_fake_coordinates() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let entity = list.place(&mut mem, 5, "prop_dynamic");
        attach_scene_node(&mut mem, entity, [12.0, 34.0, 56.0]);
        let global = list.global(&mut mem);

        let schemas = SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![class(
                    "C_BaseEntity",
                    vec![field("m_pGameSceneNode", OFF_SCENE_NODE)],
                )],
                Vec::new(),
            ),
        )]);
        let found = walk(&mut mem, global, &schemas).expect("walk");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, None);
    }
}
