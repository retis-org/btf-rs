#![allow(dead_code)]

use std::{
    collections::HashMap,
    ffi::CStr,
    io::{BufRead, Seek, SeekFrom},
    sync::Arc,
};

use crate::{btf::*, cbtf, Error, Result};

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
    // Map from id to associated Type structure, parsed from the BTF info.
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
            return Err(Error::Format(format!(
                "Unsupported BTF version: {}",
                header.version
            )));
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
                .map_err(|e| Error::Format(format!("Could not parse string: {e}")))?
                .to_str()
                .map_err(|e| Error::Format(format!("Invalid UTF-8 string: {e}")))?;
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
            // The first string in the string section is always a null string.
            // Use index 0 to store the special anonymous name.
            str_cache.insert(0, ANON_TYPE_NAME.to_string());
        }

        let end_type_section = offset as u64 + header.type_len as u64;
        while reader.stream_position()? < end_type_section {
            let bt = cbtf::btf_type::from_reader(reader, &endianness)?;

            let r#type = Type::from_reader(reader, &endianness, bt)?;

            if bt.name_off > 0 || r#type.can_be_anon() {
                let name_off = bt.name_off;
                // Look for the name in our own cache, and if not found try
                // looking into the base one (if any).
                let name = str_cache
                    .get(&name_off)
                    .or_else(|| base.as_ref().and_then(|base| base.str_cache.get(&name_off)));

                match name {
                    Some(name) => match strings.get_mut(name) {
                        Some(entry) => entry.push(id),
                        None => _ = strings.insert(name.clone(), vec![id]),
                    },
                    None => return Err(Error::InvalidString(name_off)),
                }
            }

            types.insert(id, r#type);

            id += 1;
        }

        // Sanity check
        if reader.stream_position()? != end_type_section {
            return Err(Error::Format("Invalid type section".to_string()));
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
    pub(super) fn resolve_ids_by_name(&self, name: &str) -> Vec<u32> {
        self.strings.get(name).cloned().unwrap_or_default()
    }

    /// Find a list of BTF ids whose names match a regex.
    #[cfg(feature = "regex")]
    pub(super) fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Vec<u32> {
        self.strings
            .iter()
            .filter_map(|(name, ids)| match re.is_match(name) {
                true => Some(ids.clone()),
                false => None,
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    /// Find a BTF type using its id as a key.
    pub(super) fn resolve_type_by_id(&self, id: u32) -> Option<Type> {
        self.types.get(&id).cloned()
    }

    /// Find a list of BTF types using their name as a key.
    pub(super) fn resolve_types_by_name(&self, name: &str) -> Result<Vec<Type>> {
        let mut types = Vec::new();
        self.resolve_ids_by_name(name)
            .iter()
            .try_for_each(|id| -> Result<()> {
                types.push(
                    self.resolve_type_by_id(*id)
                        .ok_or(Error::InvalidType(*id))?,
                );
                Ok(())
            })?;
        Ok(types)
    }

    /// Find a list of BTF types using a regex describing their name as a key.
    #[cfg(feature = "regex")]
    pub(super) fn resolve_types_by_regex(&self, re: &regex::Regex) -> Result<Vec<Type>> {
        let mut types = Vec::new();
        self.resolve_ids_by_regex(re)
            .iter()
            .try_for_each(|id| -> Result<()> {
                types.push(
                    self.resolve_type_by_id(*id)
                        .ok_or(Error::InvalidType(*id))?,
                );
                Ok(())
            })?;
        Ok(types)
    }

    /// Resolve a name referenced by a Type which is defined in the current BTF
    /// object.
    pub(super) fn resolve_name<T: BtfType + ?Sized>(&self, r#type: &T) -> Result<String> {
        let offset = r#type.get_name_offset()?;

        if offset == 0 && !r#type.can_be_anon() {
            return Err(Error::InvalidString(0));
        }
        self.str_cache
            .get(&offset)
            .cloned()
            .ok_or(Error::InvalidString(offset))
    }

    /// Types can have a reference to another one, e.g. `Ptr -> Int`. This
    /// helper resolve a Type referenced in an other one. It is the main helper
    /// to traverse the Type tree.
    pub(super) fn resolve_chained_type<T: BtfType + ?Sized>(&self, r#type: &T) -> Result<Type> {
        let id = r#type.get_type_id()?;
        self.resolve_type_by_id(id).ok_or(Error::InvalidType(id))
    }
}
