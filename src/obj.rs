#![allow(dead_code)]

use std::{
    collections::HashMap,
    ffi::CStr,
    io::{BufRead, Seek, SeekFrom},
    sync::Arc,
};

use anyhow::{anyhow, bail, Result};

use crate::btf::*;
use crate::cbtf;

/// Main representation of a parsed BTF object. Provides helpers to resolve
/// types and their associated names and maintains a symbol to type map for
/// symbol resolution.
pub(super) struct BtfObj {
    endianness: cbtf::Endianness,
    // Map from str offsets to the strings. For internal use (name resolution)
    // only.
    str_cache: HashMap<u32, String>,
    // Map from symbol names to their type id, used for retrieving a type by its
    // name.
    strings: HashMap<String, Vec<u32>>,
    // Vector of all the types parsed from the BTF info. The vector makes the
    // retrieval by their id implicit as the id is incremental in the BTF file;
    // but that is really the goal here.
    types: HashMap<u32, Type>,
    // Length of the string section. Used to calculate the next string offset
    // of split BTFs.
    str_len: u32,
}

impl BtfObj {
    /// Parse a BTF object from a Reader.
    pub(super) fn from_reader<R: Seek + BufRead>(
        reader: &mut R,
        base: Option<Arc<BtfObj>>,
    ) -> Result<BtfObj> {
        // First parse the BTF header, retrieve the endianness & perform sanity
        // checks.
        let (header, endianness) = cbtf::btf_header::from_reader(reader)?;
        if header.version != 1 {
            bail!("Unsupported BTF version: {}", header.version);
        }

        // Cache the str section for later use (name resolution).
        let offset = header.hdr_len + header.str_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut str_cache = HashMap::new();
        let mut offset: u32 = 0;

        // For split BTFs both ids and string offsets are logically consecutive.
        let (mut id, start_str_off) = match base {
            None => (1, 0),
            Some(ref base) => (base.types.len() as u32, base.str_len),
        };

        while offset < header.str_len {
            let mut raw = Vec::new();
            let bytes = reader.read_until(b'\0', &mut raw)? as u32;

            let s = CStr::from_bytes_with_nul(&raw)
                .map_err(|e| anyhow!("Could not parse string: {}", e))?
                .to_str()?;
            str_cache.insert(start_str_off + offset, String::from(s));

            offset += bytes;
        }

        // Finally build our representation of the BTF types.
        let offset = header.hdr_len + header.type_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut strings: HashMap<String, Vec<u32>> = HashMap::new();
        let mut types = HashMap::new();

        if base.is_none() {
            // Add special type Void with ID 0 (not described in type section)
            // only on base BTF.
            types.insert(0, Type::Void);
        }

        let end_type_section = offset as u64 + header.type_len as u64;
        while reader.stream_position()? < end_type_section {
            let bt = cbtf::btf_type::from_reader(reader, &endianness)?;

            // Each BTF type needs specific handling to parse its type-specific
            // header.
            types.insert(
                id,
                match bt.kind() {
                    1 => Type::Int(Int::from_reader(reader, &endianness, bt)?),
                    2 => Type::Ptr(Ptr::new(bt)),
                    3 => Type::Array(Array::from_reader(reader, &endianness, bt)?),
                    4 => Type::Struct(Struct::from_reader(reader, &endianness, bt)?),
                    5 => Type::Union(Struct::from_reader(reader, &endianness, bt)?),
                    6 => Type::Enum(Enum::from_reader(reader, &endianness, bt)?),
                    7 => Type::Fwd(Fwd::new(bt)),
                    8 => Type::Typedef(Typedef::new(bt)),
                    9 => Type::Volatile(Volatile::new(bt)),
                    10 => Type::Const(Volatile::new(bt)),
                    11 => Type::Restrict(Volatile::new(bt)),
                    12 => Type::Func(Func::new(bt)),
                    13 => Type::FuncProto(FuncProto::from_reader(reader, &endianness, bt)?),
                    14 => Type::Var(Var::from_reader(reader, &endianness, bt)?),
                    15 => Type::Datasec(Datasec::from_reader(reader, &endianness, bt)?),
                    16 => Type::Float(Float::new(bt)),
                    17 => Type::DeclTag(DeclTag::from_reader(reader, &endianness, bt)?),
                    18 => Type::TypeTag(Typedef::new(bt)),
                    19 => Type::Enum64(Enum64::from_reader(reader, &endianness, bt)?),
                    // We can't ignore unsupported types as we can't guess their
                    // size and thus how much to skip to the next type.
                    x => bail!("Unsupported BTF type '{}'", x),
                },
            );

            if bt.name_off > 0 {
                let name_off = bt.name_off;
                let name = str_cache.get(&name_off);
                if let Some(name) = name {
                    match strings.get_mut(name) {
                        Some(entry) => entry.push(id),
                        None => _ = strings.insert(name.clone(), vec![id]),
                    }
                } else {
                    // Just verify the integrity of the split BTF, but do not duplicate the strings
                    if base.is_none() || base.as_ref().unwrap().str_cache.get(&name_off).is_none() {
                        bail!(
                            "Couldn't get string at offset {} defined in kind {}",
                            name_off,
                            bt.kind()
                        );
                    }
                }
            }

            id += 1;
        }

        // Sanity check
        if reader.stream_position()? != end_type_section {
            bail!("Invalid type section");
        }

        Ok(BtfObj {
            endianness,
            str_cache,
            strings,
            types,
            str_len: header.str_len,
        })
    }

    /// Find a list of BTF ids using their name as a key.
    pub(super) fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>> {
        match self.strings.get(&name.to_string()) {
            Some(id) => Ok(id.clone()),
            None => bail!("No id linked to name {name}"),
        }
    }

    /// Find a BTF type using its id as a key.
    pub(super) fn resolve_type_by_id(&self, id: u32) -> Result<Type> {
        match self.types.get(&id) {
            Some(t) => Ok(t.clone()),
            None => bail!("No type with id {}", id),
        }
    }

    /// Find a list of BTF types using their name as a key.
    pub(super) fn resolve_types_by_name(&self, name: &str) -> Result<Vec<Type>> {
        let mut types = Vec::new();
        for id in self.resolve_ids_by_name(name)? {
            types.push(self.resolve_type_by_id(id)?);
        }
        Ok(types)
    }

    /// Resolve a name referenced by a Type which is defined in the current BTF
    /// object.
    pub(super) fn resolve_name<T: BtfType>(&self, r#type: &T) -> Result<String> {
        let offset = r#type.get_name_offset()?;

        match self.str_cache.get(&offset) {
            Some(s) => Ok(s.clone()),
            None => bail!("No string at offset {}", offset),
        }
    }

    /// Types can have a reference to another one, e.g. `Ptr -> Int`. This
    /// helper resolve a Type referenced in an other one. It is the main helper
    /// to traverse the Type tree.
    pub(super) fn resolve_chained_type<T: BtfType>(&self, r#type: &T) -> Result<Type> {
        self.resolve_type_by_id(r#type.get_type_id()?)
    }
}
