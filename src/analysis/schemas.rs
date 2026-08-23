use std::collections::BTreeMap;
use std::ffi::CStr;

use anyhow::{Result, bail};

use log::debug;

use memflow::prelude::v1::*;

use pelite::pattern;
use pelite::pe64::{Pe, PeView};

use serde::{Deserialize, Serialize};

use crate::analysis::module_data;
use crate::analysis::schema_anchor;
use crate::analysis::schema_flags;
use crate::analysis::static_fields::{self, StaticField, StaticFieldLayout};
use crate::source2::*;

pub type SchemaMap = BTreeMap<String, (Vec<Class>, Vec<Enum>)>;

/// Resolve a schema field through its class inheritance chain.
///
/// Schema dumps store fields on the class that declares them, while callers
/// commonly ask for fields declared by a base class. The chain is bounded and
/// cycle-protected because malformed or partially-read schema data must never
/// make a live dump loop forever.
pub fn field_offset(schemas: &SchemaMap, class_name: &str, field_name: &str) -> Option<u64> {
    let classes = schemas.values().flat_map(|(classes, _)| classes);
    for class in classes {
        if class.name != class_name {
            continue;
        }
        let mut current = class;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            if !seen.insert(current.name.as_str()) {
                break;
            }
            if let Some(field) = current.fields.iter().find(|field| field.name == field_name) {
                return u64::try_from(field.offset).ok();
            }
            let Some(parent_name) = current.parent_name.as_deref() else {
                break;
            };
            let Some(parent) = schemas
                .values()
                .flat_map(|(classes, _)| classes)
                .find(|candidate| candidate.name == parent_name)
            else {
                break;
            };
            current = parent;
        }
    }
    None
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ClassMetadata {
    Unknown { name: String },
    NetworkChangeCallback { name: String },
    NetworkVarNames { name: String, type_name: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Class {
    pub name: String,
    pub module_name: String,
    pub parent_name: Option<String>,
    pub size: i32,
    pub alignment: u8,
    pub metadata: Vec<ClassMetadata>,
    pub fields: Vec<ClassField>,
    /// Static members, empty unless the static-field geometry validated against
    /// this process. See [`crate::analysis::static_fields`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_fields: Vec<StaticField>,
    /// Decoded SCHEMA_CF1_* labels, leftover Flags2 bits, and manipulator
    /// presence. Empty when none of those are set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClassField {
    pub name: String,
    pub type_name: String,
    pub offset: i32,
    pub metadata: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Enum {
    pub name: String,
    pub alignment: u8,
    /// Schema `m_nSize` in bytes (1/2/4/8). Not the enumerator count.
    pub size: u16,
    pub members: Vec<EnumMember>,
    /// Decoded SCHEMA_EF_* labels (Local/Global Type Scope).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

impl Enum {
    /// Storage width for generated `enum class : T`. Prefers schema size,
    /// then alignment, then 4.
    pub fn storage_bytes(&self) -> u8 {
        match u8::try_from(self.size).unwrap_or(0) {
            n @ (1 | 2 | 4 | 8) => n,
            _ => match self.alignment {
                n @ (1 | 2 | 4 | 8) => n,
                _ => 4,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TypeScope {
    pub module_name: String,
    pub classes: Vec<Class>,
    pub enums: Vec<Enum>,
}

pub fn schemas<P: Process + MemoryView>(process: &mut P) -> Result<SchemaMap> {
    let schema_system = read_schema_system(process)?;
    schemas_from_system(process, schema_system)
}

/// Dump schemas from a SchemaSystem object VA resolved by the dynamic pattern
/// pass. This lets `--pattern-file` repair the schema anchor after an update
/// without relying on the legacy scanner pattern.
pub fn schemas_from_system_va<P: Process + MemoryView>(
    process: &mut P,
    schema_system_va: u64,
) -> Result<SchemaMap> {
    let schema_system: SchemaSystem = process.read(schema_system_va.into()).data_part()?;
    validate_schema_system(&schema_system)?;
    schemas_from_system(process, schema_system)
}

fn schemas_from_system<P: Process + MemoryView>(
    process: &mut P,
    schema_system: SchemaSystem,
) -> Result<SchemaMap> {
    let type_scopes = read_type_scopes(process, &schema_system)?;

    Ok(type_scopes
        .into_iter()
        .map(|type_scope| {
            (
                type_scope.module_name,
                (type_scope.classes, type_scope.enums),
            )
        })
        .collect())
}

fn read_class_binding(
    mem: &mut impl MemoryView,
    binding_ptr: Pointer64<SchemaClassBinding>,
    statics: Option<StaticFieldLayout>,
) -> Result<Class> {
    let binding = mem.read_ptr(binding_ptr).data_part()?;

    let module_name = mem
        .read_utf8_lossy(binding.module_name.address(), 128)
        .data_part()
        .map(|m| format!("{}.dll", m))?;

    let name = mem
        .read_utf8_lossy(binding.name.address(), 128)
        .data_part()?;

    if name.is_empty() {
        bail!("invalid class name");
    }

    let parent_name = binding.base_classes.non_null().and_then(|ptr| {
        let base_class = mem.read_ptr(ptr).data_part().ok()?;
        let parent_class = mem.read_ptr(base_class.class).data_part().ok()?;

        let parent_name = mem
            .read_utf8_lossy(parent_class.name.address(), 128)
            .data_part()
            .ok()?;

        (!parent_name.is_empty()).then_some(parent_name)
    });

    let fields = read_class_binding_fields(mem, &binding)?;
    let metadata = read_class_binding_metadata(mem, &binding)?;
    let static_fields = statics
        .map(|layout| {
            static_fields::read_static_fields(mem, binding_ptr.address().to_umem(), layout)
        })
        .unwrap_or_default();

    Ok(Class {
        name,
        module_name,
        parent_name,
        size: binding.size,
        alignment: binding.alignment,
        metadata,
        fields,
        static_fields,
        flags: schema_flags::class_flag_labels(
            binding.class_flags,
            binding.flags2,
            !binding.manipulator.is_null(),
        ),
    })
}

fn read_class_binding_fields(
    mem: &mut impl MemoryView,
    binding: &SchemaClassBinding,
) -> Result<Vec<ClassField>> {
    if binding.fields.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.field_count).try_fold(Vec::new(), |mut acc, i| {
        let field = mem.read_ptr(binding.fields.at(i as _)).data_part()?;

        if field.r#type.is_null() {
            return Ok(acc);
        }

        let name = mem.read_utf8_lossy(field.name.address(), 128).data_part()?;
        let r#type = mem.read_ptr(field.r#type).data_part()?;

        let type_name = mem
            .read_utf8_lossy(r#type.name.address(), 128)
            .data_part()?
            .replace(" ", "");

        let metadata = read_field_metadata(mem, &field);

        acc.push(ClassField {
            name,
            type_name,
            offset: field.offset,
            metadata,
        });

        Ok(acc)
    })
}

fn read_field_metadata(mem: &mut impl MemoryView, field: &SchemaClassFieldData) -> Vec<String> {
    if field.metadata.is_null() || field.metadata_count <= 0 {
        return Vec::new();
    }

    (0..field.metadata_count)
        .filter_map(|i| {
            let entry = mem
                .read_ptr(
                    field.metadata + i as usize * std::mem::size_of::<SchemaMetadataEntryData>(),
                )
                .data_part()
                .ok()?;
            let name = mem
                .read_utf8_lossy(entry.name.address(), 128)
                .data_part()
                .ok()?;
            (!name.is_empty()).then_some(name)
        })
        .collect()
}
fn read_class_binding_metadata(
    mem: &mut impl MemoryView,
    binding: &SchemaClassBinding,
) -> Result<Vec<ClassMetadata>> {
    if binding.static_metadata.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.static_metadata_count).try_fold(Vec::new(), |mut acc, i| {
        let metadata = mem
            .read_ptr(binding.static_metadata.at(i as _))
            .data_part()?;

        if metadata.network_value.is_null() {
            return Ok(acc);
        }

        let name = mem
            .read_utf8_lossy(metadata.name.address(), 128)
            .data_part()?;

        let network_value = mem.read_ptr(metadata.network_value).data_part()?;

        let metadata = match name.as_str() {
            "MNetworkChangeCallback" => unsafe {
                let name = mem
                    .read_utf8_lossy(network_value.value.name_ptr.address(), 128)
                    .data_part()?;

                ClassMetadata::NetworkChangeCallback { name }
            },
            "MNetworkVarNames" => unsafe {
                let var_value = network_value.value.var_value;

                let name = mem
                    .read_utf8_lossy(var_value.name.address(), 128)
                    .data_part()?;

                let type_name = mem
                    .read_utf8_lossy(var_value.type_name.address(), 128)
                    .data_part()?
                    .replace(" ", "");

                ClassMetadata::NetworkVarNames { name, type_name }
            },
            _ => ClassMetadata::Unknown { name },
        };

        acc.push(metadata);

        Ok(acc)
    })
}

fn read_enum_binding(
    mem: &mut impl MemoryView,
    binding_ptr: Pointer64<SchemaEnumBinding>,
) -> Result<Enum> {
    let binding = mem.read_ptr(binding_ptr).data_part()?;

    let name = mem
        .read_utf8_lossy(binding.name.address(), 128)
        .data_part()?;

    if name.is_empty() {
        bail!("invalid enum name");
    }

    let members = read_enum_binding_members(mem, &binding)?;

    Ok(Enum {
        name,
        alignment: binding.alignment,
        size: binding.size as u16,
        members,
        flags: schema_flags::enum_flag_names(binding.flags),
    })
}

fn read_enum_binding_members(
    mem: &mut impl MemoryView,
    binding: &SchemaEnumBinding,
) -> Result<Vec<EnumMember>> {
    if binding.enumerators.is_null() {
        return Ok(Vec::new());
    }

    (0..binding.enumerator_count).try_fold(Vec::new(), |mut acc, i| {
        let r#enum = mem.read_ptr(binding.enumerators.at(i as _)).data_part()?;

        let name = mem
            .read_utf8_lossy(r#enum.name.address(), 128)
            .data_part()?;

        acc.push(EnumMember {
            name,
            value: unsafe { r#enum.value.ulong } as i64,
        });

        Ok(acc)
    })
}

fn read_schema_system<P: Process + MemoryView>(process: &mut P) -> Result<SchemaSystem> {
    let module = process.module_by_name("schemasystem.dll")?;

    let buf = process
        .read_raw(module.base, module.size as _)
        .data_part()?;

    let view = PeView::from_bytes(&buf)?;

    let mut save = [0; 2];

    if view
        .scanner()
        .finds_code(pattern!("4c8d35${'} 0f2845"), &mut save)
    {
        if let Ok(schema_system) = process
            .read::<SchemaSystem>(module.base + save[1])
            .data_part()
            && validate_schema_system(&schema_system).is_ok()
        {
            return Ok(schema_system);
        }
        debug!("schema system pattern matched but did not validate; scanning module data");
    } else {
        debug!("outdated schema system pattern; scanning module data");
    }

    // The signature describes the *code* that references the schema system, so
    // it breaks on every recompile. The object itself can be described instead,
    // which survives updates and works for other Source 2 titles.
    let ranges = module_data::writable_ranges(&view);
    let Some(va) = schema_anchor::find_schema_system(process, &buf, module.base.to_umem(), &ranges)
    else {
        bail!("schema system not found by pattern or data scan");
    };

    debug!("schema system recovered from module data at {:#X}", va);

    let schema_system: SchemaSystem = process.read(va.into()).data_part()?;

    validate_schema_system(&schema_system)?;

    Ok(schema_system)
}

fn validate_schema_system(schema_system: &SchemaSystem) -> Result<()> {
    if schema_system.registration_count <= 0 || schema_system.type_scopes.count <= 0 {
        bail!("no schema registrations");
    }
    if schema_system.type_scopes.count > 512 {
        bail!(
            "invalid schema scope count: {}",
            schema_system.type_scopes.count
        );
    }
    Ok(())
}

/// Class and enum binding pointers of one type scope, read once so the
/// static-field probe and the decode pass share a single expensive hash walk.
struct RawTypeScope {
    module_name: String,
    class_bindings: Vec<Pointer64<SchemaClassBinding>>,
    enum_bindings: Vec<Pointer64<SchemaEnumBinding>>,
}

/// How many class bindings the static-field probe samples. The geometry is the
/// same for every binding, so a sample is as conclusive as the whole set and
/// keeps the probe cost flat regardless of how many classes are registered.
const STATIC_FIELD_PROBE_SAMPLE: usize = 512;

fn read_type_scopes(
    mem: &mut impl MemoryView,
    schema_system: &SchemaSystem,
) -> Result<Vec<TypeScope>> {
    let raw = read_raw_type_scopes(mem, schema_system)?;

    let sample: Vec<u64> = raw
        .iter()
        .flat_map(|scope| scope.class_bindings.iter())
        .take(STATIC_FIELD_PROBE_SAMPLE)
        .map(|ptr| ptr.address().to_umem())
        .collect();
    let statics = static_fields::detect_layout(mem, &sample);
    match statics {
        Some(layout) => debug!("static fields validated with layout {:?}", layout),
        None => debug!("static-field geometry did not validate; omitting static fields"),
    }

    Ok(raw
        .into_iter()
        .filter_map(|scope| {
            let classes: Vec<_> = scope
                .class_bindings
                .iter()
                .filter_map(|ptr| read_class_binding(mem, *ptr, statics).ok())
                .collect();

            let enums: Vec<_> = scope
                .enum_bindings
                .iter()
                .filter_map(|ptr| read_enum_binding(mem, *ptr).ok())
                .collect();

            if classes.is_empty() && enums.is_empty() {
                return None;
            }

            debug!(
                "module \"{}\" contains {} class(es) and {} enum(s)",
                scope.module_name,
                classes.len(),
                enums.len(),
            );

            Some(TypeScope {
                module_name: scope.module_name,
                classes,
                enums,
            })
        })
        .collect())
}

fn read_raw_type_scopes(
    mem: &mut impl MemoryView,
    schema_system: &SchemaSystem,
) -> Result<Vec<RawTypeScope>> {
    let type_scopes = &schema_system.type_scopes;

    (0..type_scopes.count).try_fold(Vec::new(), |mut acc, i| {
        let type_scope_ptr = type_scopes.element(mem, i as _)?;
        let type_scope = mem.read_ptr(type_scope_ptr).data_part()?;

        let module_name = unsafe { CStr::from_ptr(type_scope.name.as_ptr()) }
            .to_string_lossy()
            .to_string();

        acc.push(RawTypeScope {
            module_name,
            class_bindings: type_scope.class_bindings.elements(mem).to_vec(),
            enum_bindings: type_scope.enum_bindings.elements(mem).to_vec(),
        });

        Ok(acc)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(name: &str, parent_name: Option<&str>, fields: &[(&str, i32)]) -> Class {
        Class {
            name: name.into(),
            module_name: "client.dll".into(),
            parent_name: parent_name.map(str::to_owned),
            size: 0,
            alignment: 1,
            metadata: Vec::new(),
            fields: fields
                .iter()
                .map(|(name, offset)| ClassField {
                    name: (*name).into(),
                    type_name: "int".into(),
                    offset: *offset,
                    metadata: Vec::new(),
                })
                .collect(),
            static_fields: Vec::new(),
            flags: Vec::new(),
        }
    }

    #[test]
    fn enum_storage_bytes_prefers_schema_size_over_alignment() {
        let e = Enum {
            name: "E".into(),
            alignment: 4,
            size: 1,
            members: Vec::new(),
            flags: Vec::new(),
        };
        assert_eq!(e.storage_bytes(), 1);
        let fallback = Enum {
            name: "E".into(),
            alignment: 2,
            size: 0,
            members: Vec::new(),
            flags: Vec::new(),
        };
        assert_eq!(fallback.storage_bytes(), 2);
    }

    #[test]
    fn field_offset_walks_base_classes() {
        let mut schemas = SchemaMap::new();
        schemas.insert(
            "client.dll".into(),
            (
                vec![
                    class("Derived", Some("Base"), &[]),
                    class("Base", None, &[("m_iHealth", 0x10)]),
                ],
                Vec::new(),
            ),
        );
        assert_eq!(field_offset(&schemas, "Derived", "m_iHealth"), Some(0x10));
        assert_eq!(field_offset(&schemas, "Derived", "missing"), None);
    }

    #[test]
    fn field_offset_stops_on_inheritance_cycles() {
        let mut schemas = SchemaMap::new();
        schemas.insert(
            "client.dll".into(),
            (
                vec![class("A", Some("B"), &[]), class("B", Some("A"), &[])],
                Vec::new(),
            ),
        );
        assert_eq!(field_offset(&schemas, "A", "missing"), None);
    }
}
