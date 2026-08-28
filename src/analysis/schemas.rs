use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(test)]
use std::ffi::CStr;
use std::sync::Arc;

use anyhow::{Result, bail};

use log::{debug, warn};

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

/// First-wins index of schema classes by name (BTreeMap module order, so
/// `client.dll` beats `server.dll` for shared bases).
pub fn class_index(schemas: &SchemaMap) -> HashMap<&str, &Class> {
    let mut index = HashMap::new();
    for (classes, _) in schemas.values() {
        for class in classes {
            index.entry(class.name.as_str()).or_insert(class);
        }
    }
    index
}

/// Resolve a schema field through its class inheritance chain.
///
/// Schema dumps store fields on the class that declares them, while callers
/// commonly ask for fields declared by a base class. The chain is bounded and
/// cycle-protected because malformed or partially-read schema data must never
/// make a live dump loop forever.
pub fn field_offset(schemas: &SchemaMap, class_name: &str, field_name: &str) -> Option<u64> {
    field_offset_in(&class_index(schemas), class_name, field_name)
}

/// [`field_offset`] against a pre-built [`class_index`], so a walk that looks
/// up many fields does not rebuild the map or rescan every module per call.
pub fn field_offset_in(
    classes: &HashMap<&str, &Class>,
    class_name: &str,
    field_name: &str,
) -> Option<u64> {
    let mut current = *classes.get(class_name)?;
    let mut seen = HashSet::new();
    for _ in 0..64 {
        if !seen.insert(current.name.as_str()) {
            break;
        }
        if let Some(field) = current.fields.iter().find(|field| field.name == field_name) {
            return u64::try_from(field.offset).ok();
        }
        let parent_name = current.parent_name.as_deref()?;
        current = *classes.get(parent_name)?;
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
    #[serde(serialize_with = "serialize_arc_str", deserialize_with = "deserialize_arc_str")]
    pub module_name: Arc<str>,
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

fn serialize_arc_str<S: serde::Serializer>(
    value: &Arc<str>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

fn deserialize_arc_str<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Arc<str>, D::Error> {
    Ok(Arc::from(String::deserialize(deserializer)?))
}

/// How many bytes a schema name read asks for on the first attempt, and the
/// ceiling a name that filled that window is re-read with.
///
/// 128 covers every name CS2 ships today. A result that filled the whole window
/// contains no NUL, so it is either a longer name — templated schema types run
/// well past 128 characters — or not a string at all; both deserve the wider
/// read before being believed. `rtti.rs` already allows 512 for this reason.
const SCHEMA_NAME_SPAN: usize = 128;
const SCHEMA_NAME_MAX: usize = 512;

/// A schema name, or `None` when there is not a usable one at `at`.
///
/// An unreadable address does not surface as an error here. memflow's default
/// `read_raw_list` zero-fills what it could not read and reports
/// `PartialError::PartialVirtualRead`, which `data_part()` folds back into
/// `Ok` — so a name behind an unmapped pointer reads back as `""` rather than
/// failing. Emitting that as a row is worse than dropping it: `output::ident`
/// turns an empty name into `anonymous`, so two such rows in one class collide
/// into a duplicate member and the generated header stops compiling while the
/// dump still reports success. Dropping the row keeps the invariant the rest of
/// the crate is written to — a dump loses a row rather than gaining a
/// fabricated one.
fn schema_name(mem: &mut impl MemoryView, at: Address) -> Option<String> {
    if at.is_null() {
        return None;
    }
    let short = mem
        .read_utf8_lossy(at, SCHEMA_NAME_SPAN)
        .data_part()
        .ok()?;
    let name = if short.len() >= SCHEMA_NAME_SPAN {
        mem.read_utf8_lossy(at, SCHEMA_NAME_MAX).data_part().ok()?
    } else {
        short
    };
    (!name.is_empty()).then_some(name)
}

fn read_class_binding(
    mem: &mut impl MemoryView,
    binding_ptr: Pointer64<SchemaClassBinding>,
    statics: Option<StaticFieldLayout>,
    module_name: &Arc<str>,
) -> Result<Class> {
    let binding = mem.read_ptr(binding_ptr).data_part()?;

    let Some(name) = schema_name(mem, binding.name.address()) else {
        bail!("invalid class name");
    };

    let parent_name = binding.base_classes.non_null().and_then(|ptr| {
        let base_class = mem.read_ptr(ptr).data_part().ok()?;
        let parent_class = mem.read_ptr(base_class.class).data_part().ok()?;

        schema_name(mem, parent_class.name.address())
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
        module_name: Arc::clone(module_name),
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
    let n = bounded_schema_count(binding.field_count, MAX_CLASS_FIELDS);
    if n == 0 || binding.fields.is_null() {
        return Ok(Vec::new());
    }

    (0..n as i16).try_fold(
        Vec::with_capacity(n),
        |mut acc, i| {
        let Some(field_addr) = array_element_address(
            binding.fields.to_umem(),
            i as usize,
            std::mem::size_of::<SchemaClassFieldData>(),
        ) else {
            return Ok(acc);
        };
        let field: SchemaClassFieldData = mem
            .read_ptr(Pointer64::from(Address::from(field_addr)))
            .data_part()?;

        if field.r#type.is_null() {
            return Ok(acc);
        }

        // A name or type name this walk could not read comes back empty rather
        // than as an error, and a field carrying one generates `anonymous` in
        // the SDK — two of them in a class collide into a duplicate member.
        // Skip the field instead of describing it wrongly.
        let Some(name) = schema_name(mem, field.name.address()) else {
            return Ok(acc);
        };
        let r#type = mem.read_ptr(field.r#type).data_part()?;

        let Some(mut type_name) = schema_name(mem, r#type.name.address()) else {
            return Ok(acc);
        };
        if type_name.as_bytes().contains(&b' ') {
            type_name.retain(|c| c != ' ');
        }

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
    let n = bounded_schema_count_i32(field.metadata_count, MAX_FIELD_METADATA);
    if n == 0 || field.metadata.is_null() {
        return Vec::new();
    }

    (0..n as i32)
        .filter_map(|i| {
            let entry_addr = array_element_address(
                field.metadata.to_umem(),
                i as usize,
                std::mem::size_of::<SchemaMetadataEntryData>(),
            )?;
            let entry: SchemaMetadataEntryData = mem
                .read_ptr(Pointer64::from(Address::from(entry_addr)))
                .data_part()
                .ok()?;
            schema_name(mem, entry.name.address())
        })
        .collect()
}
fn read_class_binding_metadata(
    mem: &mut impl MemoryView,
    binding: &SchemaClassBinding,
) -> Result<Vec<ClassMetadata>> {
    let n = bounded_schema_count(binding.static_metadata_count, MAX_STATIC_METADATA);
    if n == 0 || binding.static_metadata.is_null() {
        return Ok(Vec::new());
    }

    (0..n as i16).try_fold(
        Vec::with_capacity(n),
        |mut acc, i| {
        let Some(metadata_addr) = array_element_address(
            binding.static_metadata.to_umem(),
            i as usize,
            std::mem::size_of::<SchemaMetadataEntryData>(),
        ) else {
            return Ok(acc);
        };
        let metadata: SchemaMetadataEntryData = mem
            .read_ptr(Pointer64::from(Address::from(metadata_addr)))
            .data_part()?;

        if metadata.network_value.is_null() {
            return Ok(acc);
        }

        // The tag name is what selects the variant below, so an unreadable one
        // cannot be classified — and `Unknown { name: "" }` would reach the
        // netvar emitters as a nameless annotation.
        let Some(name) = schema_name(mem, metadata.name.address()) else {
            return Ok(acc);
        };

        let network_value = mem.read_ptr(metadata.network_value).data_part()?;

        let metadata = match name.as_str() {
            "MNetworkChangeCallback" => unsafe {
                let Some(name) = schema_name(mem, network_value.value.name_ptr.address()) else {
                    return Ok(acc);
                };

                ClassMetadata::NetworkChangeCallback { name }
            },
            "MNetworkVarNames" => unsafe {
                let var_value = network_value.value.var_value;

                let Some(name) = schema_name(mem, var_value.name.address()) else {
                    return Ok(acc);
                };

                let Some(mut type_name) = schema_name(mem, var_value.type_name.address()) else {
                    return Ok(acc);
                };
                if type_name.as_bytes().contains(&b' ') {
                    type_name.retain(|c| c != ' ');
                }

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

    let Some(name) = schema_name(mem, binding.name.address()) else {
        bail!("invalid enum name");
    };

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

    let count = (binding.enumerator_count as usize).min(MAX_ENUM_MEMBERS);
    (0..count).try_fold(
        Vec::with_capacity(count),
        |mut acc, i| {
        let Some(enumerator_addr) = array_element_address(
            binding.enumerators.to_umem(),
            i,
            std::mem::size_of::<SchemaEnumeratorInfoData>(),
        ) else {
            return Ok(acc);
        };
        let r#enum: SchemaEnumeratorInfoData = mem
            .read_ptr(Pointer64::from(Address::from(enumerator_addr)))
            .data_part()?;

        // An enumerator with no readable name would be emitted as
        // `anonymous = 0`, and a second one would redeclare it.
        let Some(name) = schema_name(mem, r#enum.name.address()) else {
            return Ok(acc);
        };

        acc.push(EnumMember {
            name,
            value: unsafe { r#enum.value.ulong } as i64,
        });

        Ok(acc)
    })
}

fn read_schema_system<P: Process + MemoryView>(process: &mut P) -> Result<SchemaSystem> {
    let module = process.module_by_name("schemasystem.dll")?;

    let (_, buf) = module_data::read_image(process, "schemasystem.dll")?;

    let view = PeView::from_bytes(&buf)?;

    let mut save = [0; 2];

    if view
        .scanner()
        .finds_code(pattern!("4c8d35${'} 0f2845"), &mut save)
    {
        if let Some(schema_address) = module
            .base
            .to_umem()
            .checked_add(save[1] as u64)
            .map(Address::from)
        {
            if let Ok(schema_system) = process
                .read::<SchemaSystem>(schema_address)
                .data_part()
                && validate_schema_system(&schema_system).is_ok()
            {
                return Ok(schema_system);
            }
        } else {
            debug!("schema system pattern resolved an overflowing address");
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
    module_name: Arc<str>,
    class_bindings: Vec<Pointer64<SchemaClassBinding>>,
    enum_bindings: Vec<Pointer64<SchemaEnumBinding>>,
}

#[cfg(test)]
fn intern_cstr_name(name: &CStr) -> Arc<str> {
    intern_name_bytes(name.to_bytes())
}

/// Intern a type-scope name from the fixed 256-byte buffer. Never scans past
/// those 256 bytes, even when the buffer has no NUL.
fn intern_scope_name(name: &[std::ffi::c_char; 256]) -> Arc<str> {
    intern_name_bytes(unsafe { std::slice::from_raw_parts(name.as_ptr().cast::<u8>(), name.len()) })
}

pub(crate) fn intern_name_bytes(bytes: &[u8]) -> Arc<str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let slice = &bytes[..end];
    match std::str::from_utf8(slice) {
        Ok(s) => module_data::intern_loaded_name(s).unwrap_or_else(|| Arc::from(s)),
        Err(_) => Arc::from(String::from_utf8_lossy(slice).as_ref()),
    }
}

const MAX_CLASS_FIELDS: usize = 4096;
const MAX_ENUM_MEMBERS: usize = 4096;
const MAX_STATIC_METADATA: usize = 1024;
const MAX_FIELD_METADATA: usize = 256;

pub(crate) fn bounded_schema_count(count: i16, cap: usize) -> usize {
    usize::try_from(count).ok().map(|n| n.min(cap)).unwrap_or(0)
}

fn bounded_schema_count_i32(count: i32, cap: usize) -> usize {
    usize::try_from(count).ok().map(|n| n.min(cap)).unwrap_or(0)
}

fn array_element_address(base: u64, index: usize, element_size: usize) -> Option<u64> {
    let index = u64::try_from(index).ok()?;
    let element_size = u64::try_from(element_size).ok()?;
    element_size
        .checked_mul(index)
        .and_then(|offset| base.checked_add(offset))
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
            let module = Arc::clone(&scope.module_name);
            let classes: Vec<_> = scope
                .class_bindings
                .iter()
                .filter_map(|ptr| read_class_binding(mem, *ptr, statics, &module).ok())
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
                module_name: scope.module_name.to_string(),
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
    if type_scopes.count <= 0 {
        return Ok(Vec::new());
    }
    let n = (type_scopes.count as usize).min(512);
    let mut acc = Vec::with_capacity(n);
    for i in 0..n {
        match read_one_raw_type_scope(mem, type_scopes, i) {
            Ok(scope) => acc.push(scope),
            Err(err) => warn!("skipping type scope {i}: {err}"),
        }
    }
    Ok(acc)
}

fn read_one_raw_type_scope(
    mem: &mut impl MemoryView,
    type_scopes: &crate::source2::UtlVector<Pointer64<SchemaSystemTypeScope>>,
    i: usize,
) -> Result<RawTypeScope> {
    let type_scope_ptr = type_scopes.element(mem, i)?;
    let type_scope = mem.read_ptr(type_scope_ptr).data_part()?;
    let module_name = intern_scope_name(&type_scope.name);
    if module_name.is_empty() {
        bail!("empty type scope name");
    }
    Ok(RawTypeScope {
        module_name,
        class_bindings: type_scope.class_bindings.elements(mem),
        enum_bindings: type_scope.enum_bindings.elements(mem),
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

    #[test]
    fn intern_cstr_name_utf8_is_exact() {
        let name = c"client.dll";
        assert_eq!(&*intern_cstr_name(name), "client.dll");
    }

    #[test]
    fn intern_cstr_name_lossy_on_invalid_utf8() {
        let name = c"bad\xFFdll";
        let interned = intern_cstr_name(name);
        assert!(!interned.as_bytes().contains(&0xFF));
        assert!(interned.starts_with("bad"));
        assert!(interned.ends_with("dll"));
    }

    #[test]
    fn intern_name_bytes_does_not_read_past_a_256_byte_buffer() {
        let bytes = [b'Z'; 256];
        let name = intern_name_bytes(&bytes);
        assert_eq!(name.len(), 256);
        assert!(name.bytes().all(|b| b == b'Z'));
    }

    #[test]
    fn negative_schema_counts_are_empty_and_do_not_panic() {
        assert_eq!(bounded_schema_count(-1, MAX_CLASS_FIELDS), 0);
        assert_eq!(bounded_schema_count(0, MAX_CLASS_FIELDS), 0);
        assert_eq!(bounded_schema_count(4, MAX_CLASS_FIELDS), 4);
        let mut mem = crate::memory::fake::FakeMemory::new();
        let mut binding: SchemaClassBinding = unsafe { std::mem::zeroed() };
        binding.field_count = -1;
        binding.fields = Pointer64::from(Address::from(0x1000u64));
        assert!(read_class_binding_fields(&mut mem, &binding)
            .expect("negative field count")
            .is_empty());
        binding.static_metadata_count = -1;
        binding.static_metadata = Pointer64::from(Address::from(0x2000u64));
        assert!(read_class_binding_metadata(&mut mem, &binding)
            .expect("negative metadata count")
            .is_empty());
        let mut field: SchemaClassFieldData = unsafe { std::mem::zeroed() };
        field.metadata_count = -3;
        field.metadata = Pointer64::from(Address::from(0x3000u64));
        assert!(read_field_metadata(&mut mem, &field).is_empty());
    }

    #[test]
    fn a_failing_type_scope_does_not_drop_already_read_scopes() {
        let mut mem = crate::memory::fake::FakeMemory::new();
        let scope_va = mem.alloc(std::mem::size_of::<SchemaSystemTypeScope>());
        let mut name = [0u8; 256];
        name[..10].copy_from_slice(b"client.dll");
        mem.put(scope_va + 8, &name);
        let list = mem.alloc(16);
        mem.put_ptr(list, scope_va);
        mem.put_ptr(list + 8, 0x1);
        let mut system: SchemaSystem = unsafe { std::mem::zeroed() };
        system.type_scopes.count = 2;
        system.type_scopes.data = Pointer64::from(Address::from(list));
        let scopes = read_raw_type_scopes(&mut mem, &system).expect("scopes");
        assert_eq!(scopes.len(), 1);
        assert_eq!(&*scopes[0].module_name, "client.dll");
    }

    /// memflow folds an unreadable read into zeroed bytes, so a name behind an
    /// unmapped pointer arrives as `""` rather than as an error. It must not
    /// become a row: `output::ident` renders an empty name as `anonymous`, and a
    /// second such field would redeclare that member.
    #[test]
    fn a_field_whose_name_is_unreadable_is_dropped_not_emitted_as_anonymous() {
        let mut mem = crate::memory::fake::FakeMemory::new();
        let type_name = mem.alloc_cstr("int32");
        let ty = mem.alloc(std::mem::size_of::<SchemaType>());
        mem.put_ptr(ty + 0x08, type_name);

        let stride = std::mem::size_of::<SchemaClassFieldData>() as u64;
        let fields = mem.alloc(2 * stride as usize);
        let good = mem.alloc_cstr("m_iHealth");
        mem.put_ptr(fields, good);
        mem.put_ptr(fields + 0x08, ty);
        mem.put_i32(fields + 0x10, 0x10);
        // A plausible pointer that was never mapped — the DMA short-read case.
        let unmapped = 0x0000_7FF0_DEAD_0000u64;
        assert!(!mem.is_mapped(unmapped));
        mem.put_ptr(fields + stride, unmapped);
        mem.put_ptr(fields + stride + 0x08, ty);
        mem.put_i32(fields + stride + 0x10, 0x14);

        let mut binding: SchemaClassBinding = unsafe { std::mem::zeroed() };
        binding.field_count = 2;
        binding.fields = Pointer64::from(Address::from(fields));

        let found = read_class_binding_fields(&mut mem, &binding).expect("fields");
        assert_eq!(found.len(), 1, "the unreadable field must not become a row");
        assert_eq!(found[0].name, "m_iHealth");
        assert_eq!(found[0].type_name, "int32");
    }

    /// A name that fills the first window has no NUL in it, so the short read
    /// cannot be trusted. Templated schema type names run past 128 bytes, and a
    /// truncated one misses `output::cpp_types`' exact-match table.
    #[test]
    fn a_name_longer_than_the_first_window_is_read_in_full() {
        let long = format!("CUtlOrderedMap<CUtlString,CUtlVector<{}>>", "C".repeat(120));
        assert!(long.len() > SCHEMA_NAME_SPAN && long.len() < SCHEMA_NAME_MAX);
        let mut mem = crate::memory::fake::FakeMemory::new();
        let at = mem.alloc_cstr(&long);
        assert_eq!(
            schema_name(&mut mem, Address::from(at)).as_deref(),
            Some(long.as_str())
        );
    }

    #[test]
    fn a_null_or_unreadable_name_pointer_has_no_name() {
        let mut mem = crate::memory::fake::FakeMemory::new();
        assert_eq!(schema_name(&mut mem, Address::null()), None);
        assert_eq!(schema_name(&mut mem, Address::from(0x1000u64)), None);
    }
}
