//! Emitter for the weapon gameplay-values table (weapons.json).

use serde_json::json;

use crate::analysis::weapons::Weapon;

pub fn render_json(weapons: &[Weapon], build: Option<u32>) -> Result<String, serde_json::Error> {
    let rows: Vec<_> = weapons
        .iter()
        .map(|w| {
            json!({
                "name": w.name,
                "damage": w.damage,
                "headshot_multiplier": w.headshot_multiplier,
                "armor_ratio": w.armor_ratio,
                "penetration": w.penetration,
                "range": w.range,
                "range_modifier": w.range_modifier,
                "cycle_time": w.cycle_time,
                "price": w.price,
                "num_bullets": w.num_bullets,
                "max_speed": w.max_speed,
                "spread": w.spread,
                "inaccuracy_stand": w.inaccuracy_stand,
                "inaccuracy_move": w.inaccuracy_move,
                "recoil_magnitude": w.recoil_magnitude,
                "address": format!("0x{:X}", w.address),
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "build_number": build,
        "weapon_count": weapons.len(),
        "note": "Values read live from CCSWeaponBaseVData of weapons present in the dumped session.",
        "entity_handle_capacity": 32768,
        "entity_index_max": 32767,
        "weapons": rows,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_full_entity_handle_space() {
        let report: serde_json::Value =
            serde_json::from_str(&render_json(&[], None).expect("serialize")).unwrap();
        assert_eq!(report["entity_handle_capacity"], 32768);
        assert_eq!(report["entity_index_max"], 32767);
    }
}
