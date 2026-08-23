pub use buttons::*;
pub use interfaces::*;
pub use offsets::*;
pub use protobufs::*;
pub use schemas::*;
pub use vtables::*;

use std::any::type_name;

use anyhow::Result;

use log::{error, info};

use memflow::prelude::v1::*;

mod buttons;
pub mod convars;
pub mod dyn_offsets;
pub mod entities;
pub mod entity_anchor;
pub mod entity_list;
pub mod gameevents;
pub mod global_anchor;
mod interfaces;
pub mod manual_iface;
pub mod module_data;
mod offsets;
mod protobufs;
pub mod rtti;
pub mod schema_anchor;
pub mod schema_flags;
mod schemas;
pub mod static_fields;
pub mod view_matrix;
mod vtables;
pub mod weapons;

#[derive(Debug)]
pub struct AnalysisResult {
    pub buttons: ButtonMap,
    pub interfaces: InterfaceMap,
    pub offsets: OffsetMap,
    pub schemas: SchemaMap,
    pub vtables: VTableMap,
}

pub fn analyze_all<P: Process + MemoryView>(process: &mut P) -> Result<AnalysisResult> {
    let buttons = analyze(process, buttons);

    info!("found {} buttons", buttons.len());

    let interfaces = analyze(process, interfaces);

    info!(
        "found {} interfaces across {} modules",
        interfaces
            .iter()
            .map(|(_, ifaces)| ifaces.len())
            .sum::<usize>(),
        interfaces.len()
    );

    let offsets = analyze(process, offsets);

    info!(
        "found {} offsets across {} modules",
        offsets
            .iter()
            .map(|(_, offsets)| offsets.len())
            .sum::<usize>(),
        offsets.len()
    );

    let schemas = analyze(process, schemas);

    let (class_count, enum_count) =
        schemas
            .values()
            .fold((0, 0), |(classes, enums), (class_vec, enum_vec)| {
                (classes + class_vec.len(), enums + enum_vec.len())
            });

    info!(
        "found {} classes and {} enums across {} modules",
        class_count,
        enum_count,
        schemas.len()
    );

    let vtables = match vtables::vtables(process, &interfaces) {
        Ok(value) => value,
        Err(err) => {
            error!("failed to read interface vtables: {}", err);
            VTableMap::default()
        }
    };
    Ok(AnalysisResult {
        buttons,
        interfaces,
        offsets,
        schemas,
        vtables,
    })
}

fn analyze<P, F, T>(process: &mut P, f: F) -> T
where
    P: Process + MemoryView,
    F: FnOnce(&mut P) -> Result<T>,
    T: Default,
{
    let name = type_name::<F>();

    match f(process) {
        Ok(result) => result,
        Err(err) => {
            error!("failed to read {}: {}", name, err);

            T::default()
        }
    }
}
