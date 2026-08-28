//! Protobuf message-layout dumper.
//!
//! CS2's usercmd / netmessage types are **Google protobuf**, not Source2
//! schema, so the schema pass never sees them. But libprotobuf stores the
//! exact in-memory field layout in the per-file reflection tables, so we can
//! recover it precisely (offsets + has-bits) instead of hand-RE'ing it.
//!
//! For each generated `.pb.cc` the binary holds a `DescriptorTable`:
//! ```text
//!   +0x04 i32   descriptor size
//!   +0x08 ptr   serialized FileDescriptorProto  (starts `0A <len> "<name>.proto"`)
//!   +0x10 ptr   filename "<name>.proto"
//!   +0x2C i32   num_messages
//!   +0x30 ptr   schemas[]   (MigrationSchema, 16 bytes each)
//!   +0x40 ptr   offsets[]   (u32 array)
//! ```
//! `MigrationSchema = { i32 offsets_index, i32 has_bit_indices_index, i32 _, u32 object_size }`.
//! `offsets[]` per message = `[6-entry header][field offsets...][has-bit indices...]`,
//! header[0] = `_has_bits_` byte offset. Field offsets and has-bit indices are in
//! **declaration** order, not field-number order: protoc emits one entry per
//! `descriptor->field(i)`, and `FieldDescriptor::index()` — what
//! `ReflectionSchema::GetFieldOffset` indexes with — is the declaration index.
//! The serialized `DescriptorProto` lists its `field` entries in that same
//! order, so the parse order is already the right one; do not sort the fields
//! before indexing `offsets[]` with their position. Verified against CS2's
//! `CSubtickMoveStep` (fields @ 0x18/0x20/0x24, has-bits 0/1/2) — a message
//! whose declaration order happens to match its field numbers, which is why
//! sorting looked harmless.

use std::collections::BTreeMap;

use anyhow::Result;
use log::debug;
use memflow::prelude::v1::*;

/// module name -> messages in that module.
pub type ProtobufMap = BTreeMap<String, Vec<ProtoMessage>>;

#[derive(Debug, Default, Clone)]
pub struct ProtoMessage {
    pub name: String,
    pub size: u32,
    pub has_bits_offset: Option<u32>,
    /// True for compiler-generated map-entry messages.
    pub map_entry: bool,
    pub fields: Vec<ProtoField>,
}

#[derive(Debug, Default, Clone)]
pub struct ProtoField {
    pub name: String,
    pub number: i64,
    pub offset: u32,
    pub has_bit: Option<u32>,
    pub label: i64, // 1=optional 2=required 3=repeated
    pub ty: i64,    // FieldDescriptorProto.Type
    pub type_name: String,
    /// True when this repeated message field targets a map-entry message.
    pub is_map: bool,
    /// Protobuf oneof group name, when this field is a member of one.
    pub oneof: Option<String>,
}

/// Modules known to carry generated protobuf message tables.
const MODULES: &[&str] = &[
    "client.dll",
    "engine2.dll",
    "networksystem.dll",
    "server.dll",
];

const HEADER_ENTRIES: i64 = 6; // has_bits, metadata, ext, oneof, weak, inlined
const MAX_PROTO_MESSAGES: usize = 4096;
const MAX_PROTO_FIELDS: usize = 65_536;
const MAX_PROTO_ONEOFS: usize = 65_536;
const MAX_PROTO_NESTING: usize = 64;

pub fn protobufs<P: Process + MemoryView>(process: &mut P) -> Result<ProtobufMap> {
    let mut out = ProtobufMap::new();
    for &module_name in MODULES {
        let (base, buf) = match crate::analysis::module_data::read_image(process, module_name) {
            Ok((base, b)) => (base, b),
            Err(_) => continue,
        };

        let msgs = scan_module(&buf, base);
        if !msgs.is_empty() {
            debug!("[protobuf] {}: {} messages", module_name, msgs.len());
            out.insert(module_name.to_string(), msgs);
        }
    }
    Ok(out)
}

fn rd_u32(buf: &[u8], rva: usize) -> Option<u32> {
    crate::analysis::read::u32_le_at(buf, rva)
}
fn rd_i32(buf: &[u8], rva: usize) -> Option<i32> {
    crate::analysis::read::i32_le_at(buf, rva)
}
fn rd_u64(buf: &[u8], rva: usize) -> Option<u64> {
    crate::analysis::read::u64_le_at(buf, rva)
}
/// Convert an in-image VA pointer to a buffer RVA, if it lands inside the module.
fn va_to_rva(va: u64, base: u64, len: usize) -> Option<usize> {
    let rva = usize::try_from(va.checked_sub(base)?).ok()?;
    if rva < len {
        Some(rva)
    } else {
        None
    }
}

fn scan_module(buf: &[u8], base: u64) -> Vec<ProtoMessage> {
    let mut messages = Vec::new();

    // 1) Locate every serialized FileDescriptorProto: `0A <len:varint> "<name>.proto"`.
    //    Record the blob's VA so we can find the DescriptorTable that points at it.
    let mut blob_vas: BTreeMap<u64, ()> = BTreeMap::new();
    let mut i = 0usize;
    while i.checked_add(2).is_some_and(|end| end < buf.len()) {
        if buf[i] == 0x0A
            && let Some((name_len, hdr)) = read_varint(buf, i + 1)
        {
                let Some(name_start) = i.checked_add(1).and_then(|v| v.checked_add(hdr)) else {
                    i += 1;
                    continue;
                };
                let Some(name_end) = name_start.checked_add(name_len as usize) else {
                    i += 1;
                    continue;
                };
                if name_len > 3
                    && name_len < 128
                    && name_end <= buf.len()
                    && buf[name_start..name_end].ends_with(b".proto")
                    && buf[name_start..name_end]
                        .iter()
                        .all(|&c| c.is_ascii_graphic())
                    && let Some(va) = base.checked_add(i as u64)
                {
                    blob_vas.insert(va, ());
                }
        }
        i += 1;
    }
    if blob_vas.is_empty() {
        return messages;
    }

    // 2) One aligned pass: any 8-byte slot holding a blob VA is a DescriptorTable's
    //    `descriptor` field (+0x08), so the table starts 8 bytes earlier. A blob can
    //    be referenced by several pointers — only parse each file once (first table
    //    that validates wins).
    let mut done: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut p = 0usize;
    while p.checked_add(8).is_some_and(|end| end <= buf.len()) {
        let Some(val) = crate::analysis::read::u64_le_at(buf, p) else {
            break;
        };
        if p >= 8
            && blob_vas.contains_key(&val)
            && !done.contains(&val)
            && let Some(file) = parse_descriptor_table(buf, base, p - 8)
            && !file.is_empty()
        {
            done.insert(val);
            messages.extend(file);
        }
        p += 8;
    }
    messages
}

fn parse_descriptor_table(buf: &[u8], base: u64, t: usize) -> Option<Vec<ProtoMessage>> {
    let at = |offset: usize| t.checked_add(offset);
    let desc_size = usize::try_from(rd_i32(buf, at(0x04)?)?).ok()?;
    let desc_va = rd_u64(buf, at(0x08)?)?;
    let filename_va = rd_u64(buf, at(0x10)?)?;
    let num_messages = rd_i32(buf, at(0x2C)?)?;
    let schemas_va = rd_u64(buf, at(0x30)?)?;
    let offsets_va = rd_u64(buf, at(0x40)?)?;

    if !(1..=MAX_PROTO_MESSAGES as i32).contains(&num_messages) {
        return None;
    }
    let desc_rva = va_to_rva(desc_va, base, buf.len())?;
    let _ = va_to_rva(filename_va, base, buf.len())?;
    let schemas_rva = va_to_rva(schemas_va, base, buf.len())?;
    let offsets_rva = va_to_rva(offsets_va, base, buf.len())?;
    let desc_end = desc_rva.checked_add(desc_size)?;
    if desc_size < 4 || desc_end > buf.len() {
        return None;
    }

    // Parse the FileDescriptorProto for message names + fields (number order).
    let descriptor = &buf[desc_rva..desc_end];
    let mut proto_messages = Vec::new();
    parse_file_descriptor(descriptor, &mut proto_messages);
    if proto_messages.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    for (idx, pm) in proto_messages.iter().enumerate() {
        if idx as i32 >= num_messages {
            break;
        }
        let s = schemas_rva.checked_add(idx.checked_mul(16)?)?;
        let offsets_index = rd_i32(buf, s)? as i64;
        let has_bit_index = rd_i32(buf, s.checked_add(4)?)? as i64;
        let object_size = rd_u32(buf, s.checked_add(12)?)?;
        if offsets_index < 0 {
            continue;
        }

        let oi = usize::try_from(offsets_index).ok()?;
        let has_bits_offset = oi
            .checked_mul(4)
            .and_then(|delta| offsets_rva.checked_add(delta))
            .and_then(|at| rd_u32(buf, at))
            .filter(|&v| v != u32::MAX);

        let mut fields = Vec::new();
        for (j, f) in pm.fields.iter().enumerate() {
            let field_index = oi
                .checked_add(HEADER_ENTRIES as usize)
                .and_then(|base| base.checked_add(j))?;
            let off = field_index
                .checked_mul(4)
                .and_then(|delta| offsets_rva.checked_add(delta))
                .and_then(|at| rd_u32(buf, at))?;
            let has_bit = if has_bit_index >= 0 {
                let has_index = usize::try_from(has_bit_index)
                    .ok()?
                    .checked_add(j)?;
                has_index
                    .checked_mul(4)
                    .and_then(|delta| offsets_rva.checked_add(delta))
                    .and_then(|at| rd_u32(buf, at))
                    .filter(|&v| v != u32::MAX)
            } else {
                None
            };
            fields.push(ProtoField {
                name: f.name.clone(),
                number: f.number,
                offset: off,
                has_bit,
                label: f.label,
                ty: f.ty,
                type_name: f.type_name.clone(),
                oneof: f.oneof.clone(),
                is_map: f.ty == 11
                    && f.label == 3
                    && proto_messages.iter().any(|candidate| {
                        candidate.map_entry && type_name_matches(&f.type_name, &candidate.name)
                    }),
            });
        }

        out.push(ProtoMessage {
            name: pm.name.clone(),
            size: object_size,
            has_bits_offset,
            map_entry: pm.map_entry,
            fields,
        });
    }
    Some(out)
}

// ---- minimal protobuf wire reader for descriptor.proto ---------------------

#[derive(Default)]
struct PField {
    name: String,
    number: i64,
    label: i64,
    ty: i64,
    type_name: String,
    oneof_index: Option<i32>,
    oneof: Option<String>,
}
#[derive(Default)]
struct PMessage {
    name: String,
    map_entry: bool,
    fields: Vec<PField>,
}

fn type_name_matches(type_name: &str, flattened_name: &str) -> bool {
    let normalized = type_name.trim_start_matches('.').replace('.', "_");
    normalized == flattened_name
        || normalized
            .strip_suffix(flattened_name)
            .is_some_and(|prefix| prefix.ends_with('_'))
}

/// LEB128 varint. Returns (value, bytes_consumed).
fn read_varint(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *buf.get(pos)?;
        let chunk = (b & 0x7F) as u64;
        if shift == 63 && chunk > 1 {
            return None;
        }
        val |= chunk << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    Some((val, pos - start))
}

/// Iterate top-level fields of a protobuf message, calling `f(field_number, wire, payload)`.
/// `payload` is the raw slice for length-delimited fields, or the varint bytes otherwise.
/// `payload` borrows `buf` (`'a`) so length-delimited slices may be collected.
fn for_each_field<'a, F: FnMut(u64, u64, &'a [u8])>(buf: &'a [u8], mut f: F) {
    let mut pos = 0usize;
    while pos < buf.len() {
        let (tag, n) = match read_varint(buf, pos) {
            Some(v) => v,
            None => break,
        };
        let tag_end = match pos.checked_add(n) {
            Some(end) if end <= buf.len() => end,
            _ => break,
        };
        pos = tag_end;
        let field = tag >> 3;
        let wire = tag & 7;
        match wire {
            0 => {
                let (_, n) = match read_varint(buf, pos) {
                    Some(v) => v,
                    None => break,
                };
                let end = match pos.checked_add(n) {
                    Some(end) if end <= buf.len() => end,
                    _ => break,
                };
                f(field, wire, &buf[pos..end]);
                pos = end;
            }
            2 => {
                let (len, n) = match read_varint(buf, pos) {
                    Some(v) => v,
                    None => break,
                };
                pos = match pos.checked_add(n) {
                    Some(end) if end <= buf.len() => end,
                    _ => break,
                };
                let len = match usize::try_from(len) {
                    Ok(len) => len,
                    Err(_) => break,
                };
                let end = match pos.checked_add(len) {
                    Some(end) if end <= buf.len() => end,
                    _ => break,
                };
                f(field, wire, &buf[pos..end]);
                pos = end;
            }
            1 => {
                let end = match pos.checked_add(8) {
                    Some(end) if end <= buf.len() => end,
                    _ => break,
                };
                f(field, wire, &buf[pos..end]);
                pos = end;
            }
            5 => {
                let end = match pos.checked_add(4) {
                    Some(end) if end <= buf.len() => end,
                    _ => break,
                };
                f(field, wire, &buf[pos..end]);
                pos = end;
            }
            _ => break,
        }
    }
}

fn varint_of(payload: &[u8]) -> i64 {
    read_varint(payload, 0).map(|(v, _)| v as i64).unwrap_or(0)
}

/// FileDescriptorProto: field 4 = message_type (DescriptorProto, repeated).
fn parse_file_descriptor(buf: &[u8], out: &mut Vec<PMessage>) {
    for_each_field(buf, |field, wire, payload| {
        if field == 4 && wire == 2 && out.len() < MAX_PROTO_MESSAGES {
            parse_descriptor_proto(payload, "", 0, out);
        }
    });
}

/// DescriptorProto: 1=name, 2=field (FieldDescriptorProto), 3=nested_type.
/// Flatten pre-order (message then nested) to match protoc's `FlattenMessagesInFile`
/// indexing. Nested messages are qualified `Parent_Nested` (protoc's C++ naming)
/// so distinct nested types with the same short name don't collide.
fn parse_descriptor_proto(buf: &[u8], prefix: &str, depth: usize, out: &mut Vec<PMessage>) {
    if depth > MAX_PROTO_NESTING || out.len() >= MAX_PROTO_MESSAGES {
        return;
    }
    let mut name = String::new();
    let mut fields = Vec::new();
    let mut nested: Vec<&[u8]> = Vec::new();
    let mut oneof_names: Vec<String> = Vec::new();
    for_each_field(buf, |field, wire, payload| match (field, wire) {
        (1, 2) => name = String::from_utf8_lossy(payload).into_owned(),
        (2, 2) if fields.len() < MAX_PROTO_FIELDS => {
            fields.push(parse_field_descriptor(payload));
        }
        (3, 2) if nested.len() < MAX_PROTO_MESSAGES => nested.push(payload),
        (8, 2) => {
            if oneof_names.len() >= MAX_PROTO_ONEOFS {
                return;
            }
            let mut name = String::new();
            for_each_field(payload, |inner, inner_wire, inner_payload| {
                if inner == 1 && inner_wire == 2 {
                    name = String::from_utf8_lossy(inner_payload).into_owned();
                }
            });
            oneof_names.push(name);
        }
        _ => {}
    });
    // Fields stay in the order `for_each_field` produced them, which is the
    // order the `DescriptorProto` lists them: declaration order. That is the
    // order `offsets[]` is indexed by (see the module docs) — sorting here by
    // field number silently shifted every offset and has-bit of any message
    // that declares its fields out of numeric order.
    for field in &mut fields {
        field.oneof = field
            .oneof_index
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| oneof_names.get(index).cloned())
            .filter(|name| !name.is_empty());
    }
    let full = if prefix.is_empty() {
        name
    } else {
        format!("{prefix}_{name}")
    };
    let mut map_entry = false;
    for_each_field(buf, |field, wire, payload| {
        if field == 7 && wire == 2 {
            for_each_field(payload, |inner, inner_wire, inner_payload| {
                if inner == 7 && inner_wire == 0 {
                    map_entry = varint_of(inner_payload) != 0;
                }
            });
        }
    });
    out.push(PMessage {
        name: full.clone(),
        map_entry,
        fields,
    });
    let next_depth = depth + 1;
    for n in nested {
        if out.len() >= MAX_PROTO_MESSAGES {
            break;
        }
        parse_descriptor_proto(n, &full, next_depth, out);
    }
}

/// FieldDescriptorProto: 1=name, 3=number, 4=label, 5=type, 6=type_name.
fn parse_field_descriptor(buf: &[u8]) -> PField {
    let mut f = PField::default();
    for_each_field(buf, |field, wire, payload| match (field, wire) {
        (1, 2) => f.name = String::from_utf8_lossy(payload).into_owned(),
        (3, 0) => f.number = varint_of(payload),
        (4, 0) => f.label = varint_of(payload),
        (5, 0) => f.ty = varint_of(payload),
        (6, 2) => f.type_name = String::from_utf8_lossy(payload).into_owned(),
        (9, 0) => f.oneof_index = i32::try_from(varint_of(payload)).ok(),
        _ => {}
    });
    f
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PROTO_NESTING, for_each_field, parse_descriptor_proto, parse_field_descriptor,
        read_varint,
    };

    fn encode_varint(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    /// A `DescriptorProto` naming `message` and declaring `fields` in the given
    /// order: field 1 = name, field 2 = FieldDescriptorProto (whose field 1 is
    /// the name and field 3 the number).
    fn descriptor_proto(message: &str, fields: &[(&str, usize)]) -> Vec<u8> {
        let mut out = vec![0x0A];
        out.extend(encode_varint(message.len()));
        out.extend(message.as_bytes());
        for (name, number) in fields {
            let mut field = vec![0x0A];
            field.extend(encode_varint(name.len()));
            field.extend(name.as_bytes());
            field.push(0x18);
            field.extend(encode_varint(*number));
            out.push(0x12);
            out.extend(encode_varint(field.len()));
            out.extend(field);
        }
        out
    }

    /// `offsets[]` is indexed by declaration position, so the parsed fields have
    /// to stay in the order the `DescriptorProto` listed them. Sorting them by
    /// field number shifted every offset and has-bit of any message that
    /// declares a high-numbered field first.
    #[test]
    fn parsed_fields_keep_declaration_order_not_field_number_order() {
        let descriptor = descriptor_proto("M", &[("late", 7), ("early", 1)]);
        let mut messages = Vec::new();
        parse_descriptor_proto(&descriptor, "", 0, &mut messages);
        assert_eq!(messages.len(), 1);
        let names: Vec<&str> = messages[0].fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["late", "early"]);
        let numbers: Vec<i64> = messages[0].fields.iter().map(|f| f.number).collect();
        assert_eq!(numbers, vec![7, 1]);
    }

    #[test]
    fn truncated_wire_fields_are_rejected_instead_of_truncated() {
        let mut seen = 0;
        // field 1, length-delimited, claims five bytes but only two remain.
        for_each_field(&[0x0A, 0x05, b'a', b'b'], |_, _, _| seen += 1);
        assert_eq!(seen, 0);

        // fixed-width fields must also be complete before being exposed.
        for_each_field(&[0x09, 1, 2, 3], |_, _, _| seen += 1);
        assert_eq!(seen, 0);
    }

    #[test]
    fn complete_wire_fields_are_forwarded() {
        let mut fields = Vec::new();
        for_each_field(&[0x08, 0x96, 0x01, 0x12, 0x02, b'o', b'k'], |field, wire, payload| {
            fields.push((field, wire, payload.to_vec()));
        });
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], (1, 0, vec![0x96, 0x01]));
        assert_eq!(fields[1], (2, 2, b"ok".to_vec()));
    }

    #[test]
    fn varint_rejects_overflowing_tenth_byte() {
        let mut malformed = vec![0x80; 9];
        malformed.push(0x02);
        assert_eq!(read_varint(&malformed, 0), None);

        let mut max = vec![0xFF; 9];
        max.push(0x01);
        assert_eq!(read_varint(&max, 0), Some((u64::MAX, 10)));
    }

    #[test]
    fn oversized_oneof_index_is_not_truncated_into_range() {
        let valid = parse_field_descriptor(&[0x48, 0x01]);
        assert_eq!(valid.oneof_index, Some(1));

        // Field 9 with value 2^32 previously truncated to index 0.
        let oversized = parse_field_descriptor(&[0x48, 0x80, 0x80, 0x80, 0x80, 0x10]);
        assert_eq!(oversized.oneof_index, None);
    }

    #[test]
    fn descriptor_nesting_is_bounded() {
        let mut descriptor = vec![0x0A, 0x01, b'X'];
        for _ in 0..MAX_PROTO_NESTING + 10 {
            let mut parent = vec![0x0A, 0x01, b'X', 0x1A];
            parent.extend(encode_varint(descriptor.len()));
            parent.extend(descriptor);
            descriptor = parent;
        }

        let mut messages = Vec::new();
        parse_descriptor_proto(&descriptor, "", 0, &mut messages);
        assert_eq!(messages.len(), MAX_PROTO_NESTING + 1);
    }
}
