//! Curated **engine struct** layouts — the non-schema (non-networked) client
//! structs that tool authors constantly re-reverse because they never appear in
//! schema dumps: `CCSGOInput`, its per-command `CUserCmd` ring entry, and
//! `CViewSetup`. Offsets are reverse-engineered from client.dll (build 14169)
//! and emitted as `engine/engine_structs.json` plus a drop-in `.h` per struct.
//!
//! These are hand-curated constants (like `verified_features`), not read from
//! live memory — struct layouts aren't values. Re-verify after a CS2 update.

use std::fmt::Write;

use serde_json::json;

pub struct EField {
    pub name: &'static str,
    pub offset: u32,
    pub ty: &'static str,
    pub note: &'static str,
}
pub struct EFunc {
    pub name: &'static str,
    pub rva: u32,
}
pub struct EStruct {
    pub name: &'static str,
    pub module: &'static str,
    pub desc: &'static str,
    /// RVA of the global that holds a pointer to the instance, if any.
    pub instance_rva: Option<u32>,
    pub instance_note: &'static str,
    pub fields: &'static [EField],
    pub functions: &'static [EFunc],
}

pub const ENGINE_STRUCTS: &[EStruct] = &[
    EStruct {
        name: "CCSGOInput",
        module: "client.dll",
        desc: "Client input singleton — turns raw mouse/keyboard state into the per-tick CUserCmd sent to the server. Not a schema (networked) class.",
        instance_rva: Some(0x23B95F0),
        instance_note: "(CCSGOInput*)(client.dll + 0x23B95F0) — static object embedded at this RVA (no deref; the GetInput getter returns its address)",
        fields: &[
            EField { name: "vtable",                offset: 0x000, ty: "void**",    note: "CCSGOInput vftable" },
            EField { name: "m_pButtons",            offset: 0x020, ty: "kbutton*[]", note: "registered in_* commands (in_forward, in_jump, ...)" },
            EField { name: "m_angSubtickMoveAngle", offset: 0x270, ty: "QAngle",     note: "per-subtick move-direction source" },
            EField { name: "m_angViewHistory",      offset: 0x288, ty: "QAngle",     note: "previous / interpolated view-angle history" },
            EField { name: "m_angViewAngles",       offset: 0x688, ty: "QAngle",     note: "current command view angles — pitch 0x688 / yaw 0x68C / roll 0x690; mouse delta is added into yaw here each frame" },
            EField { name: "m_mouseAccumHistory",   offset: 0x6F8, ty: "struct",     note: "input-delta smoothing sub-object {int count; void* samples; ...}" },
            EField { name: "m_nCommandNumber",      offset: 0xB50, ty: "int",        note: "command / sequence number (add 0x18*slot for splitscreen)" },
            EField { name: "m_pUserCmds",           offset: 0xB58, ty: "CUserCmd*",  note: "ring buffer base, 1088-byte entries (add 0x18*slot for splitscreen)" },
        ],
        functions: &[EFunc { name: "CreateMove", rva: 0xB1FB80 }],
    },
    EStruct {
        name: "CUserCmd",
        module: "client.dll",
        desc: "One entry in CCSGOInput's per-command ring buffer (1088 bytes / 0x440 each) — the resolved view angle + button masks CreateMove writes each tick. This is the client working buffer, not the networked protobuf.",
        instance_rva: None,
        instance_note: "CCSGOInput.m_pUserCmds[i]  (base at CCSGOInput+0xB58, stride 1088)",
        fields: &[
            EField { name: "m_nButtons",             offset: 0x000, ty: "uint64", note: "pressed (down) button mask" },
            EField { name: "m_nButtonsQueuedDown",   offset: 0x008, ty: "uint64", note: "bits forced DOWN this cmd (subtick)" },
            EField { name: "m_nButtonsQueuedChange", offset: 0x010, ty: "uint64", note: "bits that CHANGED this cmd (subtick gate)" },
            EField { name: "m_angViewAngles",        offset: 0x018, ty: "QAngle", note: "clamped view angle for this cmd — pitch 0x18 / yaw 0x1C / roll 0x20" },
            EField { name: "m_nSubtickCount",        offset: 0x02C, ty: "int",    note: "subtick move-step count" },
            EField { name: "m_pSubtickData",         offset: 0x030, ty: "void*",  note: "subtick move-step data" },
            EField { name: "m_flMouseDX",            offset: 0x430, ty: "float",  note: "raw mouse-delta X (accumulated)" },
            EField { name: "m_flMouseDY",            offset: 0x434, ty: "float",  note: "raw mouse-delta Y" },
        ],
        functions: &[],
    },
    EStruct {
        name: "CViewSetup",
        module: "client.dll",
        desc: "The camera/view description filled each frame (fov, world origin, view angles). Written by OverrideView; read by the renderer. Not a schema class.",
        instance_rva: None,
        instance_note: "received by OverrideView (client.dll + 0xC987F0) in rdx",
        fields: &[
            EField { name: "m_flFov",         offset: 0x498, ty: "float",  note: "field of view" },
            EField { name: "m_vecOrigin",     offset: 0x4A0, ty: "Vector", note: "world eye origin — x 0x4A0 / y 0x4A4 / z 0x4A8" },
            EField { name: "m_angViewAngles", offset: 0x4B8, ty: "QAngle", note: "view angles — pitch 0x4B8 / yaw 0x4BC / roll 0x4C0" },
        ],
        functions: &[EFunc { name: "OverrideView", rva: 0xC987F0 }],
    },
];

fn instance_rva_of(s: &EStruct, live_csgo_input: Option<u32>) -> Option<u32> {
    if s.name == "CCSGOInput" {
        live_csgo_input.or(s.instance_rva)
    } else {
        s.instance_rva
    }
}

/// Structured JSON of every engine struct.
///
/// `live_csgo_input` overlays the baked CCSGOInput instance RVA with the
/// value recovered from this run's offset/pattern pass. Field layouts stay
/// curated because they are not schema-exported.
pub fn render_json(
    build: Option<u32>,
    live_csgo_input: Option<u32>,
) -> Result<String, serde_json::Error> {
    let structs: Vec<_> = ENGINE_STRUCTS
        .iter()
        .map(|s| {
            let instance_rva = instance_rva_of(s, live_csgo_input);
            json!({
                "name": s.name,
                "module": s.module,
                "desc": s.desc,
                "instance_rva": instance_rva.map(|r| format!("0x{:X}", r)),
                "instance_rva_source": if s.name == "CCSGOInput" && live_csgo_input.is_some() {
                    "live"
                } else if s.instance_rva.is_some() {
                    "curated"
                } else {
                    "none"
                },
                "instance": s.instance_note,
                "fields": s.fields.iter().map(|f| json!({
                    "name": f.name,
                    "offset": format!("0x{:X}", f.offset),
                    "type": f.ty,
                    "note": f.note,
                })).collect::<Vec<_>>(),
                "functions": s.functions.iter().map(|fn_| json!({
                    "name": fn_.name,
                    "rva": format!("0x{:X}", fn_.rva),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "build_number": build,
        "note": "Non-schema client struct field layouts, reverse-engineered from client.dll. Instance RVAs prefer the live dump when available; field offsets still drift and must be re-verified after a CS2 update.",
        "struct_count": ENGINE_STRUCTS.len(),
        "structs": structs,
    }))
}

/// Generate a drop-in C++ header for a single struct (offset constants + notes).
pub fn render_header(s: &EStruct, build: Option<u32>, live_instance_rva: Option<u32>) -> String {
    let mut out = String::new();
    let guard = s.name.to_ascii_uppercase();
    let _ = writeln!(
        out,
        "// {}.h  ·  CS2{}  ·  cs2-dumper",
        lower(s.name),
        build.map(|b| format!(" build {b}")).unwrap_or_default()
    );
    let _ = writeln!(out, "// {}", s.desc);
    out.push_str("// Reverse-engineered from ");
    out.push_str(s.module);
    out.push_str("; field offsets drift between builds — re-verify after a CS2 update.\n");
    let _ = writeln!(
        out,
        "#pragma once\n#include <cstdint>\n\nnamespace {} {{",
        s.name
    );

    if let Some(rva) = live_instance_rva.or(s.instance_rva) {
        let source = if live_instance_rva.is_some() {
            "live dump"
        } else {
            "curated (re-verify)"
        };
        let _ = writeln!(
            out,
            "\n// instance ({source}):  {}\ninline constexpr std::ptrdiff_t kInstance_rva = 0x{:X};",
            s.instance_note, rva
        );
    } else {
        let _ = writeln!(out, "\n// instance:  {}", s.instance_note);
    }
    for fn_ in s.functions {
        let _ = writeln!(
            out,
            "inline constexpr std::ptrdiff_t k{}_rva = 0x{:X};",
            fn_.name, fn_.rva
        );
    }

    out.push_str("\n// --- fields ---\n");
    let w = s.fields.iter().map(|f| f.name.len()).max().unwrap_or(0);
    for f in s.fields {
        let _ = writeln!(
            out,
            "inline constexpr std::ptrdiff_t {:<w$} = 0x{:<4X}; // {} — {}",
            f.name,
            f.offset,
            f.ty,
            f.note,
            w = w
        );
    }
    let _ = writeln!(out, "}} // namespace {}", s.name);
    let _ = guard;
    out
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}
