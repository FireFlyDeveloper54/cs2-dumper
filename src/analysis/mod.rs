pub(crate) use buttons::*;
pub(crate) use interfaces::*;
pub(crate) use offsets::*;
pub(crate) use protobufs::*;
pub(crate) use schemas::*;
pub(crate) use vtables::*;

use std::any::type_name;

use anyhow::Result;

use log::{error, info};

use memflow::prelude::v1::*;

mod buttons;
pub(crate) mod convars;
pub(crate) mod dyn_offsets;
pub(crate) mod entities;
pub(crate) mod entity_anchor;
pub(crate) mod entity_list;
pub(crate) mod gameevents;
pub(crate) mod global_anchor;
mod interfaces;
pub(crate) mod manual_iface;
pub mod module_data;
mod offsets;
mod protobufs;
pub mod read;
pub(crate) mod rtti;
pub(crate) mod schema_anchor;
pub(crate) mod schema_flags;
mod schemas;
pub(crate) mod static_fields;
pub(crate) mod view_matrix;
mod vtables;
pub(crate) mod weapons;

#[derive(Debug)]
pub(crate) struct AnalysisResult {
    pub buttons: ButtonMap,
    pub interfaces: InterfaceMap,
    pub offsets: OffsetMap,
    pub schemas: SchemaMap,
    pub vtables: VTableMap,
}

pub(crate) fn analyze_all<P: Process + MemoryView>(process: &mut P) -> Result<AnalysisResult> {
    let buttons = analyze(process, buttons);

    info!("found {} buttons", buttons.len());

    let interfaces = analyze(process, interfaces);

    info!(
        "found {} interfaces across {} modules",
        interfaces
            .values()
            .map(|ifaces| ifaces.len())
            .sum::<usize>(),
        interfaces.len()
    );

    let offsets = analyze(process, offsets);

    info!(
        "found {} offsets across {} modules",
        offsets.values().map(|offsets| offsets.len()).sum::<usize>(),
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
