use std::{
    collections::HashMap,
    ffi::CStr,
    io::{BufRead, Cursor, Seek, SeekFrom},
    mem,
    ops::Deref,
    sync::Arc,
};

use memmap2::Mmap;

use crate::{btf::*, cbtf, Error, Result};

// Main internal representation of a parsed BTF object.
pub(super) struct BtfObj(Box<dyn BtfBackend + Send + Sync>);

// Allow using `BtfBackend` helpers on `BtfObj`.
impl Deref for BtfObj {
    type Target = dyn BtfBackend;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl BtfObj {
    // Parse a BTF object from a mmaped file. This takes the `Mmap` ownership to
    // allow reading the BTF data on-demand. This provides a faster
    // initialization and a lower memory footprint than `Self::from_reader`.
    pub(super) fn from_mmap(mmap: Mmap, base: Option<Arc<BtfObj>>) -> Result<Self> {
        Ok(Self(Box::new(MmapBtfObj::new(mmap, base)?)))
    }

    // Parse a BTF object from a Reader. The BTF data is cached in memory. This
    // provides faster API access than `Self::from_mmap`.
    pub(super) fn from_reader<R: Seek + BufRead>(
        reader: &mut R,
        base: Option<Arc<BtfObj>>,
    ) -> Result<Self> {
        Ok(Self(Box::new(CachedBtfObj::new(reader, base)?)))
    }

    // Find a list of BTF types using their name as a key.
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

    // Resolve a name referenced by a Type which is defined in the current BTF
    // object.
    pub(super) fn resolve_name(&self, r#type: &dyn BtfType) -> Result<String> {
        let offset = r#type
            .get_name_offset()
            .ok_or(Error::OpNotSupp("No name offset in type".to_string()))?;
        self.resolve_name_by_offset(offset)
            .ok_or(Error::InvalidString(offset))
    }

    // Find a list of BTF types using a regex describing their name as a key.
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

// Helpers implemented by BTF backends to allow querying the BTF definitions
// (types, names, etc).
pub(super) trait BtfBackend {
    // Access the BTF header as a reference.
    fn header(&self) -> &cbtf::btf_header;
    // Return the number of types in the object.
    fn types(&self) -> usize;
    // Find a list of BTF ids using their name as a key.
    fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>>;
    // Find a BTF type using its id as a key.
    fn resolve_type_by_id(&self, id: u32) -> Result<Option<Type>>;
    // Resolve a name using its offset.
    fn resolve_name_by_offset(&self, offset: u32) -> Option<String>;
    // Find a list of BTF ids whose names match a regex.
    #[cfg(feature = "regex")]
    fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<u32>>;
}

// Backend for a parsed BTF object with all its types and strings cached in
// memory. This provides faster API performances at the cost of slower
// initialization and increase in memory footprint.
struct CachedBtfObj {
    header: cbtf::btf_header,
    // Type id offset from the base, 0 if not.
    type_offset: u32,
    // Map from str offsets to the strings. For internal use (name resolution)
    // only.
    str_cache: HashMap<u32, String>,
    // Map from symbol names to their type id, used for retrieving a type by its
    // name.
    strings: HashMap<String, Vec<u32>>,
    // Vector of all the types parsed from the BTF info. The vector makes the
    // retrieval by their id implicit as the id is incremental in the BTF file;
    // but that is really the goal here.
    types: Vec<Type>,
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
        let (est_str, est_ty) = header.estimates();

        // Cache the str section for later use (name resolution).
        let offset = header.hdr_len + header.str_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut str_cache = HashMap::with_capacity(est_str);
        let mut offset: u32 = 0;

        // For split BTFs both ids and string offsets are logically consecutive.
        let (mut id, start_str_off) = match base {
            None => (1, 0),
            Some(ref base) => (base.types() as u32, base.header().str_len),
        };

        while offset < header.str_len {
            let mut raw = Vec::new();
            let bytes = reader.read_until(b'\0', &mut raw)? as u32;

            let s = bytes_to_str(&raw)?;
            str_cache.insert(start_str_off + offset, String::from(s));

            offset += bytes;
        }

        // Finally build our representation of the BTF types.
        let offset = header.hdr_len + header.type_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut strings: HashMap<String, Vec<u32>> = HashMap::with_capacity(est_str);
        let mut types = Vec::with_capacity(est_ty);

        if base.is_none() {
            // Add special type Void with ID 0 (not described in type section)
            // only on base BTF.
            types.push(Type::Void);
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

            types.push(r#type);
            id += 1;
        }

        // Sanity check
        if reader.stream_position()? != end_type_section {
            return Err(Error::Format("Invalid type section".to_string()));
        }

        Ok(Self {
            header,
            type_offset: match base {
                Some(base) => base.types() as u32,
                None => 0,
            },
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
        Ok(self
            .types
            .get(
                id.checked_sub(self.type_offset)
                    .ok_or(Error::InvalidType(id))? as usize,
            )
            .cloned())
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

// Backend for a parsed BTF object keeping the input data memory-mapped. This
// provides a faster initialization and lower memory footprint at the cost of
// slower API performances.
struct MmapBtfObj {
    endianness: cbtf::Endianness,
    header: cbtf::btf_header,
    // String offset from the base, 0 if not.
    str_offset: u32,
    // Type id offset from the base, 0 if not.
    type_offset: u32,
    // Number of types defined in the object.
    types: usize,
    // Memory-mapped reader.
    mmap: Mmap,
    // Map from type ids to their offsets in the mmaped BTF.
    type_offsets: Vec<usize>,
}

impl MmapBtfObj {
    fn new(mmap: Mmap, base: Option<Arc<BtfObj>>) -> Result<Self> {
        let len = mmap.len();
        let mut reader = Cursor::new(mmap);

        // First parse the BTF header, retrieve the endianness & perform sanity
        // checks.
        let (header, endianness) = cbtf::btf_header::from_reader(&mut reader)?;
        if header.version != 1 {
            return Err(Error::Format(format!(
                "Unsupported BTF version: {}",
                header.version
            )));
        }
        let (_, est_ty) = header.estimates();

        // Then sanity check the string section.
        if len < (header.str_len + header.str_off) as usize {
            return Err(Error::Format(
                "String section is missing or incomplete".to_string(),
            ));
        }

        // Finally build our representation of the BTF types.
        let offset = header.hdr_len + header.type_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut offsets = Vec::with_capacity(est_ty);
        let mut types = 0;

        let end_type_section = (offset + header.type_len) as u64;
        while reader.stream_position()? < end_type_section {
            offsets.push(reader.stream_position()? as usize);
            cbtf::btf_skip_type(&mut reader, &endianness)?;
            types += 1;
        }

        // Sanity check
        if reader.stream_position()? != end_type_section {
            return Err(Error::Format("Invalid type section".to_string()));
        }

        let (str_offset, type_offset) = match base {
            Some(base) => (base.header().str_len, base.types() as u32),
            None => (0, 0),
        };

        Ok(Self {
            endianness,
            header,
            str_offset,
            type_offset,
            types,
            mmap: reader.into_inner(),
            type_offsets: offsets,
        })
    }

    // Iterate over the type names, calling a function on them (providing the
    // type id and name bytes buffer).
    fn iter_over_names<F>(&self, mut f: F) -> Result<()>
    where
        F: FnMut(u32, &[u8]) -> Result<()>,
    {
        let mmap = &self.mmap;

        for (id, offset) in self.type_offsets.iter().enumerate() {
            let bt = cbtf::btf_type::from_bytes(&mmap[*offset..], &self.endianness)?;
            let name_off = match bt.name_offset() {
                Some(offset) => offset,
                None => continue,
            };

            if name_off < self.header.str_len {
                let start = (self.header.hdr_len + self.header.str_off + name_off) as usize;

                f(id as u32 + 1 + self.type_offset, &mmap[start..])?;
            }
        }

        Ok(())
    }
}

impl BtfBackend for MmapBtfObj {
    fn header(&self) -> &cbtf::btf_header {
        &self.header
    }

    fn types(&self) -> usize {
        // Take `Type::Void` into account for base objects.
        (if self.type_offset != 0 { 0 } else { 1 }) + self.types
    }

    fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>> {
        let len = name.len();
        let mut ids = Vec::new();

        self.iter_over_names(|id, buf| {
            // If len == buf.len(), the NULL char isn't there.
            if len < buf.len() && buf[len] == b'\0' && name.as_bytes() == &buf[..len] {
                ids.push(id);
            }
            Ok(())
        })?;

        Ok(ids)
    }

    fn resolve_type_by_id(&self, id: u32) -> Result<Option<Type>> {
        let id = id
            .checked_sub(self.type_offset)
            .ok_or(Error::InvalidType(id))? as usize;
        if id == 0 {
            return Ok(Some(Type::Void));
        }

        Ok(match self.type_offsets.get(id - 1) {
            Some(offset) => {
                let bt = cbtf::btf_type::from_bytes(&self.mmap[*offset..], &self.endianness)?;
                Some(Type::from_bytes(
                    &self.mmap[(*offset + mem::size_of::<cbtf::btf_type>())..],
                    &self.endianness,
                    bt,
                )?)
            }
            None => None,
        })
    }

    fn resolve_name_by_offset(&self, offset: u32) -> Option<String> {
        let offset = match offset.checked_sub(self.str_offset) {
            Some(id) if id <= self.header.str_len => id,
            _ => return None,
        };

        let start = (self.header.hdr_len + self.header.str_off + offset) as usize;
        bytes_to_str(&self.mmap[start..])
            .ok()
            .map(|s| s.to_string())
    }

    #[cfg(feature = "regex")]
    fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<u32>> {
        let mut ids = Vec::new();
        self.iter_over_names(|id, buf| {
            if let Ok(s) = bytes_to_str(buf) {
                if re.is_match(s) {
                    ids.push(id);
                }
            }
            Ok(())
        })?;
        Ok(ids)
    }
}

// Converts a bytes array to an str representation, without copy.
fn bytes_to_str(buf: &[u8]) -> Result<&str> {
    CStr::from_bytes_until_nul(buf)
        .map_err(|e| Error::Format(format!("Could not parse string: {e}")))?
        .to_str()
        .map_err(|e| Error::Format(format!("Invalid UTF-8 string: {e}")))
}
