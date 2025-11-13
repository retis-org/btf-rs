use std::{
    collections::HashMap,
    ffi::CStr,
    io::{BufRead, Seek, SeekFrom},
    ops::Deref,
    sync::Arc,
};

use crate::{btf::*, cbtf, Error, Result};

/// Main internal representation of a parsed BTF object.
pub(super) struct BtfObj(Box<dyn BtfBackend + Send + Sync>);

// Allow using `BtfBackend` helpers on `BtfObj`.
impl Deref for BtfObj {
    type Target = dyn BtfBackend;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl BtfObj {
    /// Parse a BTF object from a Reader. The BTF data is cached in memory.
    pub(super) fn from_reader<R: Seek + BufRead>(
        reader: &mut R,
        base: Option<Arc<BtfObj>>,
    ) -> Result<Self> {
        Ok(Self(Box::new(CachedBtfObj::new(reader, base)?)))
    }

    /// Find a list of BTF types using their name as a key.
    pub(super) fn resolve_types_by_name(&self, name: &str) -> Result<Vec<Type>> {
        let mut types = Vec::new();
        self.resolve_ids_by_name(name)?
            .iter()
            .try_for_each(|id| -> Result<()> {
                types.push(
                    self.resolve_type_by_id(*id)?
                        .ok_or(Error::InvalidType(*id))?,
                );
                Ok(())
            })?;
        Ok(types)
    }

    /// Resolve a name referenced by a Type which is defined in the current BTF
    /// object.
    pub(super) fn resolve_name(&self, r#type: &dyn BtfType) -> Result<String> {
        let offset = r#type
            .get_name_offset()
            .ok_or(Error::OpNotSupp("No name offset in type".to_string()))?;
        self.resolve_name_by_offset(offset)
            .ok_or(Error::InvalidString(offset))
    }

    /// Find a list of BTF types using a regex describing their name as a key.
    #[cfg(feature = "regex")]
    pub(super) fn resolve_types_by_regex(&self, re: &regex::Regex) -> Result<Vec<Type>> {
        let mut types = Vec::new();
        self.resolve_ids_by_regex(re)?
            .iter()
            .try_for_each(|id| -> Result<()> {
                types.push(
                    self.resolve_type_by_id(*id)?
                        .ok_or(Error::InvalidType(*id))?,
                );
                Ok(())
            })?;
        Ok(types)
    }
}

/// Helpers implemented by BTF backends to allow querying the BTF definitions
/// (types, names, etc).
pub(super) trait BtfBackend {
    /// Access the BTF header as a reference.
    fn header(&self) -> &cbtf::btf_header;
    /// Return the number of types in the object.
    fn types(&self) -> usize;
    /// Find a list of BTF ids using their name as a key.
    fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>>;
    /// Find a BTF type using its id as a key.
    fn resolve_type_by_id(&self, id: u32) -> Result<Option<Type>>;
    /// Resolve a name using its offset.
    fn resolve_name_by_offset(&self, offset: u32) -> Option<String>;
    /// Find a list of BTF ids whose names match a regex.
    #[cfg(feature = "regex")]
    fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<u32>>;
}

/// Backend for a parsed BTF object with all its types and strings cached in
/// memory. This provides faster API performances at the cost of slower
/// initialization and increase in memory footprint.
struct CachedBtfObj {
    header: cbtf::btf_header,
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
}

impl CachedBtfObj {
    fn new<R: Seek + BufRead>(reader: &mut R, base: Option<Arc<BtfObj>>) -> Result<Self> {
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
            Some(ref base) => (base.types() as u32, base.header().str_len),
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
        }

        let end_type_section = offset as u64 + header.type_len as u64;
        while reader.stream_position()? < end_type_section {
            let bt = cbtf::btf_type::from_reader(reader, &endianness)?;
            let r#type = Type::from_reader(reader, &endianness, bt)?;

            if let Some(name_off) = bt.name_offset() {
                // Look for the name in our own cache, and if not found try
                // looking into the base one (if any).
                let name = str_cache.get(&name_off).cloned().or_else(|| {
                    base.as_ref()
                        .and_then(|base| base.resolve_name_by_offset(name_off))
                });

                match name {
                    Some(ref name) => match strings.get_mut(name) {
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

        Ok(Self {
            header,
            str_cache,
            strings,
            types,
        })
    }
}

impl BtfBackend for CachedBtfObj {
    fn header(&self) -> &cbtf::btf_header {
        &self.header
    }

    fn types(&self) -> usize {
        self.types.len()
    }

    fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>> {
        Ok(self.strings.get(name).cloned().unwrap_or_default())
    }

    fn resolve_type_by_id(&self, id: u32) -> Result<Option<Type>> {
        Ok(self.types.get(&id).cloned())
    }

    fn resolve_name_by_offset(&self, offset: u32) -> Option<String> {
        self.str_cache.get(&offset).cloned()
    }

    #[cfg(feature = "regex")]
    fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<u32>> {
        Ok(self
            .strings
            .iter()
            .filter_map(|(name, ids)| match re.is_match(name) {
                true => Some(ids.clone()),
                false => None,
            })
            .flatten()
            .collect::<Vec<_>>())
    }
}
