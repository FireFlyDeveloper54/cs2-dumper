use std::collections::BTreeMap;

use anyhow::Result;

use log::{debug, error};

use memflow::prelude::v1::*;

use pelite::pattern;
use pelite::pattern::{Atom, save_len};
use pelite::pe64::{Pe, PeView, Rva};

use phf::{Map, phf_map};

pub type OffsetMap = BTreeMap<String, BTreeMap<String, Rva>>;

macro_rules! pattern_map {
    ($($module:ident => {
        $($name:expr => $pattern:expr $(=> $callback:expr)?),+ $(,)?
    }),+ $(,)?) => {
        $(
            mod $module {
                use super::*;

                pub(super) const PATTERNS: Map<
                    &'static str,
                    (
                        &'static [Atom],
                        Option<fn(&PeView, &mut BTreeMap<String, Rva>, Rva)>,
                    ),
                > = phf_map! {
                    $($name => ($pattern, $($callback)?)),+
                };

                pub fn offsets(view: PeView<'_>) -> BTreeMap<String, Rva> {
                    let mut map = BTreeMap::new();

                    for (&name, (pat, callback)) in &PATTERNS {
                        let mut save = vec![0; save_len(pat)];

                        if !view.scanner().finds_code(pat, &mut save) {
                            error!("outdated pattern: {}", name);

                            continue;
                        }

                        let rva = save[1];

                        map.insert(name.to_string(), rva);

                        if let Some(callback) = callback {
                            callback(&view, &mut map, rva);
                        }
                    }

                    for (name, value) in &map {
                        debug!(
                            "found \"{}\" at {:#X} ({}.dll + {:#X})",
                            name,
                            *value as u64 + view.optional_header().ImageBase,
                            stringify!($module),
                            value
                        );
                    }

                    map
                }
            }
        )+
    };
}

pattern_map! {
    client => {
        "dwCSGOInput" => pattern!("488905${'} 0f57c0 0f1105") => Some(|view, map, rva| {
            let mut save = [0; 2];

            if view.scanner().finds_code(pattern!("f2420f108428u4"), &mut save) {
                map.insert("dwViewAngles".to_string(), rva + save[1]);
            }
        }),
        "dwEntityList" => pattern!("48890d${'} e9${} cc") => None,
        "dwGameEntitySystem" => pattern!("488b1d${'} 48891d[4] 4c63b3") => None,
        "dwGameEntitySystem_highestEntityIndex" => pattern!("ff81u4 4885d2") => None,
        "dwGameRules" => pattern!("f6c1010f85${} 4c8b05${'} 4d85") => None,
        "dwGlobalVars" => pattern!("488915${'} 488942") => None,
        "dwGlowManager" => pattern!("488b05${'} c3 cccccccccccccccc 8b41") => None,
        "dwLocalPlayerController" => pattern!("488b05${'} 4189be") => None,
        "dwPlantedC4" => pattern!("488b1d${'} 4532f6") => None,
        "dwPrediction" => pattern!("488d05${'} c3 cccccccccccccccc 405356 4154") => Some(|view, map, rva| {
            let mut save = [0; 2];

            if view.scanner().finds_code(pattern!("4c39b6u4 74? 4488be"), &mut save) {
                map.insert("dwLocalPlayerPawn".to_string(), rva + save[1]);
            }
        }),
        "dwSensitivity" => pattern!("488d0d${[8]'} 660f6ecd") => Some(|_view, map, _rva| {
            map.insert("dwSensitivity_sensitivity".to_string(), 0x58);
        }),
        "dwViewMatrix" => pattern!("488d0d${'} 48c1e006") => None,
        "dwViewRender" => pattern!("488905${'} 488bc8 4885c0") => Some(|view, map, rva| {
            // `48 89 05 rel32; 48 8B C8; 48 85 C0` is a compiler idiom
            // (`mov [global], rax; mov rcx, rax; test rax, rax`), not a
            // unique symbol. best-dumper used the same bytes for
            // dwViewRender and dwVPhys2World, so both names bound the first
            // hit. Keep the first as dwViewRender; a single extra hit is
            // dwVPhys2World. More than one extra hit is ambiguous — skip.
            if let Some(phys) = second_store_global(view, rva) {
                map.insert("dwVPhys2World".to_string(), phys);
            }
        }),
        "dwWeaponC4" => pattern!("488b15${'} 488b5c24? ffc0 8905${} 488bc6 488934ea 80be") => None,
        "dwCreateMove" => pattern!("'488bc44c89401848894808555341544155") => None,
        "dwParticleManager" => pattern!("488b0d${'} 41b8${} f30f117424? 48c74424? ${}") => None,
        "dwClientMode" => pattern!("488d0d${'} 4869c0${} 4803c1 c3 cccc") => None,
    },
    engine2 => {
        "dwBuildNumber" => pattern!("8905${'} 488d0d${} ff15${} 488b0d") => None,
        "dwNetworkGameClient" => pattern!("48893d${'} ff87") => None,
        "dwNetworkGameClient_clientTickCount" => pattern!("8b81u4 c3 cccccccccccccccccc 8b81${} c3 cccccccccccccccccc 83b9") => None,
        "dwNetworkGameClient_deltaTick" => pattern!("4c8db7u4 4c897c24") => None,
        "dwNetworkGameClient_isBackgroundMap" => pattern!("0fb681u4 c3 cccccccccccccccc 0fb681${} c3 cccccccccccccccc 4883ec") => None,
        "dwNetworkGameClient_localPlayer" => pattern!("428b94d3u4 5b 49ffe3 32c0 5b c3 cccccccccccccccc 4053") => None,
        "dwNetworkGameClient_maxClients" => pattern!("8b81u4 c3????????? 8b81[4] c3????????? 8b81") => None,
        "dwNetworkGameClient_serverTickCount" => pattern!("8b81u4 c3 cccccccccccccccccc 83b9") => None,
        "dwNetworkGameClient_signOnState" => pattern!("448b81u4 488d0d") => None,
        "dwWindowHeight" => pattern!("8b05${'} 8903") => None,
        "dwWindowWidth" => pattern!("8b05${'} 8907") => None,
        "dwPVSManager" => pattern!("488d0d${'} 33d2 ff50") => None,
    },
    input_system => {
        "dwInputSystem" => pattern!("488905${'} 33c0") => None,
    },
    tier0 => {
        "dwCVar" => pattern!("488d05${'} c3 cccccccccccccccc e9") => None,
    },
    matchmaking => {
        "dwGameTypes" => pattern!("488d0d${'} ff90") => None,
    },
    soundsystem => {
        "dwSoundSystem" => pattern!("488d0d${'} e8${} 488b0d${} [3] 4c8b82") => None,
        "dwSoundSystem_engineViewData" => pattern!("0f1147u1 0f104e? 0f118f") => None,
    },
}

/// First extra RIP-relative store using the ViewRender idiom, if unique.
fn second_store_global(view: &PeView<'_>, view_render: Rva) -> Option<Rva> {
    let pat = pattern!("488905${'} 488bc8 4885c0");
    let mut save = vec![0; save_len(pat)];
    let mut others = Vec::new();
    let mut iter = view.scanner().matches_code(pat);
    while iter.next(&mut save) {
        if save[1] != view_render {
            others.push(save[1]);
        }
    }
    match others.as_slice() {
        [only] => Some(*only),
        _ => {
            if others.len() > 1 {
                debug!(
                    "dwVPhys2World skipped: {} extra hits of the ViewRender store idiom",
                    others.len()
                );
            }
            None
        }
    }
}

/// Unique extra hit of a repeated pattern, excluding `first`. Used so
/// dwVPhys2World is not silently aliased to dwViewRender.
pub fn unique_extra_hit(first: u32, hits: &[u32]) -> Option<u32> {
    let others: Vec<u32> = hits.iter().copied().filter(|&hit| hit != first).collect();
    match others.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

pub fn offsets<P: Process + MemoryView>(process: &mut P) -> Result<OffsetMap> {
    let mut map = BTreeMap::new();

    let modules: [(&str, fn(PeView) -> BTreeMap<String, u32>); 6] = [
        ("client.dll", client::offsets),
        ("engine2.dll", engine2::offsets),
        ("inputsystem.dll", input_system::offsets),
        ("matchmaking.dll", matchmaking::offsets),
        ("soundsystem.dll", soundsystem::offsets),
        ("tier0.dll", tier0::offsets),
    ];

    for (module_name, offsets) in &modules {
        let (_base, buf) = crate::analysis::module_data::read_pe_image(process, module_name)?;
        let view = PeView::from_bytes(&buf)?;
        map.insert(module_name.to_string(), offsets(view));
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Once;

    use serde_json::Value;

    use simplelog::*;

    use super::*;

    #[test]
    #[ignore = "requires a running cs2.exe and freshly generated output"]
    fn build_number() -> Result<()> {
        let mut process = setup()?;

        let engine_base = process.module_by_name("engine2.dll")?.base;

        let offset = read_offset("engine2.dll", "dwBuildNumber").unwrap();

        let build_number: u32 = process.read(engine_base + offset).data_part()?;

        debug!("build number: {}", build_number);

        Ok(())
    }

    #[test]
    #[ignore = "requires a running cs2.exe and freshly generated output"]
    fn global_vars() -> Result<()> {
        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let offset = read_offset("client.dll", "dwGlobalVars").unwrap();

        let global_vars: u64 = process.read(client_base + offset).data_part()?;

        let map_name_addr = process
            .read_addr64((global_vars + 0x180).into())
            .data_part()?;

        let map_name = process.read_utf8(map_name_addr, 128).data_part()?;

        debug!("[global vars] map name: \"{}\"", map_name);

        Ok(())
    }

    #[test]
    #[ignore = "requires a running cs2.exe and freshly generated output"]
    fn local_controller() -> Result<()> {
        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let local_controller_offset = read_offset("client.dll", "dwLocalPlayerController").unwrap();

        let player_name_offset =
            read_class_field("client.dll", "CBasePlayerController", "m_iszPlayerName").unwrap();

        let local_controller: u64 = process
            .read(client_base + local_controller_offset)
            .data_part()?;

        let player_name = process
            .read_utf8((local_controller + player_name_offset).into(), 128)
            .data_part()?;

        debug!("[local controller] name: \"{}\"", player_name);

        Ok(())
    }

    #[test]
    #[ignore = "requires a running cs2.exe and freshly generated output"]
    fn local_pawn() -> Result<()> {
        #[derive(Pod)]
        #[repr(C)]
        struct Vector3D {
            x: f32,
            y: f32,
            z: f32,
        }

        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let local_player_pawn_offset = read_offset("client.dll", "dwLocalPlayerPawn").unwrap();

        let game_scene_node_offset =
            read_class_field("client.dll", "C_BaseEntity", "m_pGameSceneNode").unwrap();

        let origin_offset =
            read_class_field("client.dll", "CGameSceneNode", "m_vecAbsOrigin").unwrap();

        let local_player_pawn: u64 = process
            .read(client_base + local_player_pawn_offset)
            .data_part()?;

        let game_scene_node: u64 = process
            .read((local_player_pawn + game_scene_node_offset).into())
            .data_part()?;

        let origin: Vector3D = process
            .read((game_scene_node + origin_offset).into())
            .data_part()?;

        debug!(
            "[local pawn] origin: {:.2}, y: {:.2}, z: {:.2}",
            origin.x, origin.y, origin.z
        );

        Ok(())
    }

    #[test]
    #[ignore = "requires a running cs2.exe and freshly generated output"]
    fn window_size() -> Result<()> {
        let mut process = setup()?;

        let engine_base = process.module_by_name("engine2.dll")?.base;

        let window_width_offset = read_offset("engine2.dll", "dwWindowWidth").unwrap();
        let window_height_offset = read_offset("engine2.dll", "dwWindowHeight").unwrap();

        let window_width: u32 = process
            .read(engine_base + window_width_offset)
            .data_part()?;

        let window_height: u32 = process
            .read(engine_base + window_height_offset)
            .data_part()?;

        debug!("window size: {}x{}", window_width, window_height);

        Ok(())
    }

    #[test]
    fn vphys2_world_is_only_bound_when_the_store_idiom_has_one_extra_hit() {
        assert_eq!(unique_extra_hit(0x1000, &[0x1000]), None);
        assert_eq!(unique_extra_hit(0x1000, &[0x1000, 0x2000]), Some(0x2000));
        assert_eq!(unique_extra_hit(0x1000, &[0x1000, 0x2000, 0x3000]), None);
        assert_eq!(unique_extra_hit(0x1000, &[0x2000, 0x1000]), Some(0x2000));
    }

    fn setup() -> Result<IntoProcessInstanceArcBox<'static>> {
        static LOGGER: Once = Once::new();

        LOGGER.call_once(|| {
            SimpleLogger::init(LevelFilter::Trace, Config::default()).ok();
        });

        let os = memflow_native::create_os(&OsArgs::default(), LibArc::default())?;

        let process = os.into_process_by_name("cs2.exe")?;

        Ok(process)
    }

    fn read_class_field(module_name: &str, class_name: &str, field_name: &str) -> Option<u64> {
        let content =
            fs::read_to_string(format!("output/{}.json", module_name.replace(".", "_"))).ok()?;

        let value: Value = serde_json::from_str(&content).ok()?;

        value
            .get(module_name)?
            .get("classes")?
            .get(class_name)?
            .get("fields")?
            .get(field_name)?
            .as_u64()
    }

    fn read_offset(module_name: &str, offset_name: &str) -> Option<u64> {
        let content = fs::read_to_string("output/offsets.json").ok()?;
        let value: Value = serde_json::from_str(&content).ok()?;

        let offset = value.get(module_name)?.get(offset_name)?;

        offset.as_u64()
    }
}
