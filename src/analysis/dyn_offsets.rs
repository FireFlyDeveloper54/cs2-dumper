//! `dw*` offset symbols recovered without the signature that normally resolves
//! them.
//!
//! The offsets map is the dumper's most consumed output and every symbol in it
//! comes from a byte pattern over `client.dll`'s code, so a recompile empties
//! whole entries until the patterns have been re-authored by hand. Some of those
//! globals point at objects that describe themselves, and those are handled by
//! [`crate::analysis::global_anchor`]. The ones here are different: a
//! `CCSGameRules` looks like any other allocation, and a player pawn looks like
//! every other player pawn.
//!
//! What identifies them is *where they were found*. The entity list is already
//! reachable without a signature, the schema dump is already produced, and
//! together they name an object exactly: the entity called `cs_gamerules` holds
//! the game rules at the offset the schema reports. Once the object's address is
//! known, the global naming it is the slot in `client.dll`'s writable data that
//! holds that address — recovered by
//! [`global_anchor::find_publishing_global`], which declines whenever more than
//! one slot does, so a symbol is never a guess about which one a consumer should
//! read.

use log::debug;

use memflow::prelude::v1::*;

use pelite::pe64::PeView;

use crate::analysis::{
    SchemaMap, entity_list, field_offset, global_anchor, module_data, view_matrix,
};

/// The module whose globals these symbols live in.
const CLIENT: &str = "client.dll";

/// Highest canonical user-mode address; anything above is not an object.
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// One recovered offset symbol, in the shape the offsets map wants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovered {
    pub module: String,
    pub symbol: String,
    pub rva: u32,
}

/// Recover what the live process and the schema dump can prove about
/// `client.dll`'s globals.
///
/// `entity_system_global` is the global the entity walk dereferences, resolved
/// by pattern or by data scan. Without it the world cannot be read and only
/// symbols derivable from the module's own data are recovered — the view matrix.
/// Symbols are only ever *offered* — the caller decides whether a canonical
/// scanner result already claims the name.
pub fn recover<P: Process + MemoryView>(
    process: &mut P,
    schemas: &SchemaMap,
    entity_system_global: Option<u64>,
) -> Vec<Recovered> {
    let Ok((base, image)) = module_data::read_image(process, CLIENT) else {
        return Vec::new();
    };
    let Ok(view) = PeView::from_bytes(&image) else {
        return Vec::new();
    };
    let ranges = module_data::writable_ranges(&view);
    recover_in(
        process,
        schemas,
        entity_system_global,
        &image,
        base,
        &ranges,
    )
}

/// The recovery itself, over an already-read image so it can be driven from a
/// synthetic module: everything above this is finding `client.dll`.
fn recover_in<P: MemoryView>(
    process: &mut P,
    schemas: &SchemaMap,
    entity_system_global: Option<u64>,
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
) -> Vec<Recovered> {
    let mut out: Vec<Recovered> = Vec::new();
    let mut push = |symbol: &str, rva: u32| {
        debug!("{symbol} recovered without a signature at {CLIENT}+{rva:#X}");
        out.push(Recovered {
            module: CLIENT.to_string(),
            symbol: symbol.to_string(),
            rva,
        });
    };

    // The view matrix is data, not a pointer to data, so it needs no global and
    // no live world: the numbers in the image identify it on their own.
    if let Some(va) = view_matrix::find_in_image(image, base, ranges)
        && let Some(rva) = va.checked_sub(base).and_then(|rva| u32::try_from(rva).ok())
    {
        push("dwViewMatrix", rva);
    }

    let Some(entity_system_global) = entity_system_global else {
        return out;
    };
    let list = rd_u64(process, entity_system_global);
    if list < 0x10000 {
        return out;
    }
    let layout = entity_list::detect_layout(process, list);
    let entities = entity_list::live_entities(process, list, layout);
    if entities.is_empty() {
        return out;
    }
    debug!("offset recovery sees {} live entities", entities.len());

    let mut offer = |symbol: &str, object: u64| {
        if let Some(rva) = publishing_rva(image, base, ranges, symbol, object) {
            push(symbol, rva);
        }
    };

    if let Some(rules) = game_rules(process, schemas, &entities) {
        offer("dwGameRules", rules);
    }
    if let Some(controller) = sole_published(image, base, ranges, &entities, is_controller) {
        offer("dwLocalPlayerController", controller);
    }
    if let Some(pawn) = sole_published(image, base, ranges, &entities, is_pawn) {
        offer("dwLocalPlayerPawn", pawn);
    }

    out
}

/// RVA of the global publishing `object`, with the reason logged when there
/// isn't one. The count matters to whoever reads the log: zero means the object
/// is only reachable through the entity list, several means the symbol was
/// declined rather than missed.
fn publishing_rva(
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
    symbol: &str,
    object: u64,
) -> Option<u32> {
    let slots = global_anchor::globals_holding(image, base, ranges, object);
    if slots.len() != 1 {
        debug!(
            "{symbol}: object {object:#X} is published through {} slots, declining",
            slots.len()
        );
        return None;
    }
    let rva = u32::try_from(slots[0].checked_sub(base)?).ok()?;
    debug!("{symbol} recovered from a live object at {CLIENT}+{rva:#X}");
    Some(rva)
}

/// The `CCSGameRules` the `cs_gamerules` entity proxies.
///
/// The proxy entity is what the list names; the rules object itself is behind
/// one pointer at a schema offset this dump already produced, so no field offset
/// is assumed here.
fn game_rules<P: MemoryView>(
    process: &mut P,
    schemas: &SchemaMap,
    entities: &[entity_list::LiveEntity],
) -> Option<u64> {
    let offset = field_offset(schemas, "C_CSGameRulesProxy", "m_pGameRules")?;
    entities
        .iter()
        .filter(|entity| entity.classname == "cs_gamerules")
        .find_map(|entity| {
            let rules = rd_u64(process, entity.instance + offset);
            (0x10000..USER_SPACE_END).contains(&rules).then_some(rules)
        })
}

/// The one entity of a kind that `client.dll` keeps a raw pointer to.
///
/// A match holds ten player controllers and the list cannot say which one is
/// yours. The client can: it keeps a pointer to the local player's objects in
/// its own data, and to no one else's. So the discriminator is publication
/// itself — and it must be unambiguous in both directions. If two entities of
/// the kind are published, or the one that is appears in several slots, there is
/// nothing here worth a symbol.
fn sole_published(
    image: &[u8],
    base: u64,
    ranges: &[(u64, u64)],
    entities: &[entity_list::LiveEntity],
    kind: fn(&str) -> bool,
) -> Option<u64> {
    let mut found = None;
    for entity in entities.iter().filter(|entity| kind(&entity.classname)) {
        if global_anchor::globals_holding(image, base, ranges, entity.instance).is_empty() {
            continue;
        }
        match found {
            None => found = Some(entity.instance),
            Some(earlier) if earlier == entity.instance => {}
            Some(_) => return None,
        }
    }
    found
}

/// Designer names of a player controller. Both spellings have shipped, and the
/// match is exact so a `cs_player_controller`-adjacent entity cannot widen it.
fn is_controller(classname: &str) -> bool {
    matches!(
        classname,
        "cs_player_controller" | "csplayercontroller" | "player_controller"
    )
}

/// Designer names of a player pawn. `player` is what a pawn has been called for
/// as long as Source has existed; the `*_pawn` spellings appear in Source 2.
fn is_pawn(classname: &str) -> bool {
    matches!(classname, "player" | "cs_player_pawn" | "csplayerpawn")
}

fn rd_u64<P: MemoryView>(process: &mut P, va: u64) -> u64 {
    process
        .read::<u64>(Address::from(va))
        .data_part()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::analysis::entity_list::fixture::ListBuilder;
    use crate::analysis::{Class, ClassField};
    use crate::memory::fake::FakeMemory;

    /// A synthetic `client.dll`: `DATA_RVA` stands in for the writable section
    /// the globals live in.
    const CLIENT_BASE: u64 = 0x0000_7FF7_1000_0000;
    const DATA_RVA: u64 = 0x1000;
    const DATA_SIZE: u64 = 0x2000;

    const OFF_GAME_RULES: i32 = 0x0058;

    fn image() -> Vec<u8> {
        vec![0u8; (DATA_RVA + DATA_SIZE) as usize]
    }

    /// Publish `object` through the global at `rva` in the writable section.
    fn publish(image: &mut [u8], rva: u64, object: u64) {
        image[(DATA_RVA + rva) as usize..][..8].copy_from_slice(&object.to_le_bytes());
    }

    fn ranges() -> Vec<(u64, u64)> {
        vec![(DATA_RVA, DATA_SIZE)]
    }

    /// A schema map holding only the field the recovery reads.
    fn schemas() -> SchemaMap {
        SchemaMap::from([(
            "client.dll".to_string(),
            (
                vec![Class {
                    name: "C_CSGameRulesProxy".to_string(),
                    module_name: "client.dll".to_string(),
                    parent_name: None,
                    size: 0x1000,
                    alignment: 8,
                    metadata: Vec::new(),
                    fields: vec![ClassField {
                        name: "m_pGameRules".to_string(),
                        type_name: "CCSGameRules*".to_string(),
                        offset: OFF_GAME_RULES,
                        metadata: Vec::new(),
                    }],
                    static_fields: Vec::new(),
                    flags: Vec::new(),
                }],
                Vec::new(),
            ),
        )])
    }

    fn recovered(image: &[u8], mem: &mut FakeMemory, global: u64) -> Vec<Recovered> {
        recover_in(mem, &schemas(), Some(global), image, CLIENT_BASE, &ranges())
    }

    fn rva_of(found: &[Recovered], symbol: &str) -> Option<u32> {
        found
            .iter()
            .find(|item| item.symbol == symbol)
            .map(|item| item.rva)
    }

    /// The whole point: `dwGameRules` is derived from the live world — the entity
    /// list names the proxy, the schema locates the rules pointer inside it, and
    /// the global is the slot in `client.dll` that holds the same address.
    #[test]
    fn game_rules_is_recovered_from_the_proxy_entity_and_the_schema() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let proxy = list.place(&mut mem, 40, "cs_gamerules");
        let rules = mem.alloc(0x400);
        mem.put_ptr(proxy + OFF_GAME_RULES as u64, rules);
        let global = list.global(&mut mem);

        let mut image = image();
        publish(&mut image, 0x120, rules);

        let found = recovered(&image, &mut mem, global);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].module, "client.dll");
        assert_eq!(
            rva_of(&found, "dwGameRules"),
            Some((DATA_RVA + 0x120) as u32)
        );
    }

    /// A match holds ten controllers and the list cannot say which is yours. The
    /// one the client keeps a pointer to is the local player's, and the entities
    /// it does not point at must not be reported.
    #[test]
    fn the_published_player_is_the_local_one() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let others: Vec<u64> = (1..10)
            .map(|index| list.place(&mut mem, index, "cs_player_controller"))
            .collect();
        let local = list.place(&mut mem, 10, "cs_player_controller");
        let pawn = list.place(&mut mem, 300, "player");
        let global = list.global(&mut mem);

        let mut image = image();
        publish(&mut image, 0x300, local);
        publish(&mut image, 0x808, pawn);

        let found = recovered(&image, &mut mem, global);
        assert_eq!(
            rva_of(&found, "dwLocalPlayerController"),
            Some((DATA_RVA + 0x300) as u32)
        );
        assert_eq!(
            rva_of(&found, "dwLocalPlayerPawn"),
            Some((DATA_RVA + 0x808) as u32)
        );
        // Nothing about the other nine was published, so nothing was claimed.
        assert!(others.iter().all(|other| *other != local));
    }

    /// Publication is the only discriminator, so it has to be unambiguous: two
    /// published controllers, or one published twice, leave the symbol missing
    /// rather than name a slot a consumer cannot rely on.
    #[test]
    fn an_ambiguously_published_player_is_declined() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let first = list.place(&mut mem, 1, "cs_player_controller");
        let second = list.place(&mut mem, 2, "cs_player_controller");
        let global = list.global(&mut mem);

        let mut two_players = image();
        publish(&mut two_players, 0x300, first);
        publish(&mut two_players, 0x400, second);
        assert_eq!(
            rva_of(
                &recovered(&two_players, &mut mem, global),
                "dwLocalPlayerController"
            ),
            None
        );

        let mut two_slots = image();
        publish(&mut two_slots, 0x300, first);
        publish(&mut two_slots, 0x400, first);
        assert_eq!(
            rva_of(
                &recovered(&two_slots, &mut mem, global),
                "dwLocalPlayerController"
            ),
            None
        );
    }

    /// Nothing is invented when the world does not supply it: an entity list
    /// without a game-rules proxy, and a proxy whose rules pointer is null,
    /// both yield no symbol.
    #[test]
    fn a_world_without_the_object_yields_no_symbol() {
        let mut mem = FakeMemory::new();
        let mut list = ListBuilder::new(&mut mem);
        let proxy = list.place(&mut mem, 40, "cs_gamerules");
        let global = list.global(&mut mem);
        let image = image();

        assert!(recovered(&image, &mut mem, global).is_empty());

        // A rules object that exists but no global holding it: reachable through
        // the entity list, not addressable as an offset symbol.
        let rules = mem.alloc(0x400);
        mem.put_ptr(proxy + OFF_GAME_RULES as u64, rules);
        assert!(recovered(&image, &mut mem, global).is_empty());
    }

    /// A null entity-system global means there is no world to read, which is a
    /// different thing from a world with nothing in it — neither may produce a
    /// symbol.
    #[test]
    fn no_entity_list_means_no_recovery() {
        let mut mem = FakeMemory::new();
        let null_global = mem.alloc(0x8);
        let image = image();

        assert!(recovered(&image, &mut mem, null_global).is_empty());
        assert!(recover_in(&mut mem, &schemas(), None, &image, CLIENT_BASE, &ranges()).is_empty());
    }

    /// A minimal projection the scan's geometry accepts: `w` is a unit axis,
    /// both screen rows are perpendicular scalings of it, depth is parallel.
    fn projection() -> [f32; 16] {
        [
            0.0, 2.0, 0.0, 0.0, //
            0.0, 0.0, 3.0, 0.0, //
            5.0, 0.0, 0.0, -4.0, //
            1.0, 0.0, 0.0, 0.0,
        ]
    }

    /// The view matrix needs neither an entity system nor a live world — only
    /// its own numbers in the image — so it is recovered even when nothing else
    /// is.
    #[test]
    fn the_view_matrix_is_recovered_without_an_entity_system() {
        let mut mem = FakeMemory::new();
        let mut image = image();
        for (index, value) in projection().iter().enumerate() {
            image[(DATA_RVA + 0x400 + index as u64 * 4) as usize..][..4]
                .copy_from_slice(&value.to_le_bytes());
        }

        let found = recover_in(&mut mem, &schemas(), None, &image, CLIENT_BASE, &ranges());
        assert_eq!(found.len(), 1);
        assert_eq!(
            rva_of(&found, "dwViewMatrix"),
            Some((DATA_RVA + 0x400) as u32)
        );
    }
}
