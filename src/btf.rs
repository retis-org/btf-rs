#![allow(dead_code)]

use std::{
    collections::HashMap,
    ffi::CStr,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
};

use anyhow::{anyhow, bail, Result};

use crate::cbtf;

/// Main representation of a parsed BTF object. Provides helpers to resolve
/// types and their associated names and maintains a symbol to type map for
/// symbol resolution.
pub struct Btf {
    endianness: cbtf::Endianness,
    // Map from str offsets to the strings. For internal use (name resolution)
    // only.
    str_cache: HashMap<u32, String>,
    // Map from symbol names to their type id, used for retrieving a type by its
    // name.
    strings: HashMap<String, u32>,
    // Vector of all the types parsed from the BTF info. The vector makes the
    // retrieval by their id implicit as the id is incremental in the BTF file;
    // but that is really the goal here.
    types: HashMap<u32, Type>,
}

impl Btf {
    /// Parse a BTF object file and construct a Rust representation for later
    /// use.
    pub fn from_file(path: &str) -> Result<Btf> {
        Self::from_reader(&mut BufReader::new(File::open(path)?))
    }

    fn from_reader<R: Seek + BufRead>(reader: &mut R) -> Result<Btf> {
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

        while offset < header.str_len {
            let mut raw = Vec::new();
            let bytes = reader.read_until(b'\0', &mut raw)? as u32;

            let s = CStr::from_bytes_with_nul(&raw)
                .map_err(|e| anyhow!("Could not parse string: {}", e))?
                .to_str()?;
            str_cache.insert(offset, String::from(s));

            offset += bytes;
        }

        // Finally build our representation of the BTF types.
        let offset = header.hdr_len + header.type_off;
        reader.seek(SeekFrom::Start(offset as u64))?;

        let mut strings = HashMap::new();
        let mut types = HashMap::new();
        let mut id = 0;

        // The first type is reserved for void and not described in the type
        // section.
        types.insert(id, Type::Void);
        id += 1;

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
                let name = str_cache
                    .get(&name_off)
                    .ok_or_else(|| {
                        anyhow!(
                            "Couldn't get string at offset {} defined in kind {}",
                            name_off,
                            bt.kind()
                        )
                    })?
                    .clone();

                strings.insert(name, id);
            }

            id += 1;
        }

        // Sanity check
        if reader.stream_position()? != end_type_section {
            bail!("Invalid type section");
        }

        Ok(Btf {
            endianness,
            str_cache,
            strings,
            types,
        })
    }

    /// Find a BTF type using its id as a key.
    pub fn resolve_type_by_id(&self, id: u32) -> Result<Type> {
        match self.types.get(&id) {
            Some(t) => Ok(t.clone()),
            None => bail!("No type with id {}", id),
        }
    }

    /// Find a BTF type using its name as a key.
    pub fn resolve_type_by_name(&self, name: &str) -> Result<Type> {
        let id = match self.strings.get(&name.to_string()) {
            Some(id) => *id,
            None => bail!("No type with name {}", name),
        };

        self.resolve_type_by_id(id)
    }

    /// Resolve a name referenced by a Type which is defined in the current BTF
    /// object.
    pub fn resolve_name<T: BtfType>(&self, r#type: &T) -> Result<String> {
        let offset = r#type.get_name_offset()?;

        match self.str_cache.get(&offset) {
            Some(s) => Ok(s.clone()),
            None => bail!("No string at offset {}", offset),
        }
    }

    /// Types can have a reference to another one, e.g. `Ptr -> Int`. This
    /// helper resolve a Type referenced in an other one. It is the main helper
    /// to traverse the Type tree.
    pub fn resolve_chained_type<T: BtfType>(&self, r#type: &T) -> Result<Type> {
        self.resolve_type_by_id(r#type.get_type_id()?)
    }
}

/// Rust representation of BTF types. Each type then contains its own specific
/// data and provides helpers to access it.
#[derive(Clone)]
pub enum Type {
    Void,
    Int(Int),
    Ptr(Ptr),
    Array(Array),
    Struct(Struct),
    Union(Struct),
    Enum(Enum),
    Fwd(Fwd),
    Typedef(Typedef),
    Volatile(Volatile),
    Const(Volatile),
    Restrict(Volatile),
    Func(Func),
    FuncProto(FuncProto),
    Var(Var),
    Datasec(Datasec),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(Typedef),
    Enum64(Enum64),
}

impl Type {
    pub fn name(&self) -> &'static str {
        match &self {
            Type::Void => "void",
            Type::Int(_) => "int",
            Type::Ptr(_) => "ptr",
            Type::Array(_) => "array",
            Type::Struct(_) => "struct",
            Type::Union(_) => "union",
            Type::Enum(_) => "enum",
            Type::Fwd(_) => "fwd",
            Type::Typedef(_) => "typedef",
            Type::Volatile(_) => "volatile",
            Type::Const(_) => "const",
            Type::Restrict(_) => "restrict",
            Type::Func(_) => "func",
            Type::FuncProto(_) => "func-proto",
            Type::Var(_) => "var",
            Type::Datasec(_) => "datasec",
            Type::Float(_) => "float",
            Type::DeclTag(_) => "decl-tag",
            Type::TypeTag(_) => "type-tag",
            Type::Enum64(_) => "enum64",
        }
    }
}

pub trait BtfType {
    fn get_name_offset(&self) -> Result<u32> {
        bail!("No name offset in type");
    }

    fn get_type_id(&self) -> Result<u32> {
        bail!("No type offset in type");
    }
}

#[derive(Clone)]
pub struct Int {
    btf_type: cbtf::btf_type,
    btf_int: cbtf::btf_int,
}

impl Int {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Int> {
        Ok(Int {
            btf_type,
            btf_int: cbtf::btf_int::from_reader(reader, endianness)?,
        })
    }

    pub fn is_signed(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_SIGNED == cbtf::BTF_INT_SIGNED
    }

    pub fn is_char(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_CHAR == cbtf::BTF_INT_CHAR
    }

    pub fn is_bool(&self) -> bool {
        self.btf_int.encoding() & cbtf::BTF_INT_BOOL == cbtf::BTF_INT_BOOL
    }

    pub fn size(&self) -> usize {
        self.btf_type.size()
    }
}

impl BtfType for Int {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct Ptr {
    btf_type: cbtf::btf_type,
}

impl Ptr {
    fn new(btf_type: cbtf::btf_type) -> Ptr {
        Ptr { btf_type }
    }
}

impl BtfType for Ptr {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Array {
    btf_type: cbtf::btf_type,
    btf_array: cbtf::btf_array,
}

impl Array {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Array> {
        Ok(Array {
            btf_type,
            btf_array: cbtf::btf_array::from_reader(reader, endianness)?,
        })
    }
}

impl BtfType for Array {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Struct {
    btf_type: cbtf::btf_type,
    pub members: Vec<Member>,
}

impl Struct {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Struct> {
        let mut members = Vec::new();

        for _ in 0..btf_type.vlen() {
            members.push(Member::from_reader(
                reader,
                endianness,
                btf_type.kind_flag(),
            )?);
        }

        Ok(Struct { btf_type, members })
    }

    pub fn size(&self) -> usize {
        self.btf_type.size()
    }
}

impl BtfType for Struct {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct Member {
    kind_flag: u32,
    btf_member: cbtf::btf_member,
}

impl Member {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        kind_flag: u32,
    ) -> Result<Member> {
        Ok(Member {
            kind_flag,
            btf_member: cbtf::btf_member::from_reader(reader, endianness)?,
        })
    }

    pub fn bit_offset(&self) -> u32 {
        match self.kind_flag {
            1 => self.btf_member.offset & 0xffffff,
            _ => self.btf_member.offset,
        }
    }

    pub fn bitfield_size(&self) -> Option<u32> {
        match self.kind_flag {
            1 => Some(self.btf_member.offset >> 24),
            _ => None,
        }
    }
}

impl BtfType for Member {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_member.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_member.r#type)
    }
}

#[derive(Clone)]
pub struct Enum {
    btf_type: cbtf::btf_type,
    pub members: Vec<EnumMember>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Enum> {
        let mut members = Vec::new();

        for _ in 0..btf_type.vlen() {
            members.push(EnumMember::from_reader(reader, endianness)?);
        }

        Ok(Enum { btf_type, members })
    }

    pub fn is_signed(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }

    pub fn len(&self) -> usize {
        self.btf_type.vlen() as usize
    }

    pub fn size(&self) -> usize {
        self.btf_type.size()
    }
}

impl BtfType for Enum {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct EnumMember {
    btf_enum: cbtf::btf_enum,
}

impl EnumMember {
    fn from_reader<R: Read>(reader: &mut R, endianness: &cbtf::Endianness) -> Result<EnumMember> {
        Ok(EnumMember {
            btf_enum: cbtf::btf_enum::from_reader(reader, endianness)?,
        })
    }

    pub fn val(&self) -> i32 {
        self.btf_enum.val
    }
}

impl BtfType for EnumMember {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_enum.name_off)
    }
}

#[derive(Clone)]
pub struct Fwd {
    btf_type: cbtf::btf_type,
}

impl Fwd {
    fn new(btf_type: cbtf::btf_type) -> Fwd {
        Fwd { btf_type }
    }
}

impl BtfType for Fwd {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct Typedef {
    btf_type: cbtf::btf_type,
}

impl Typedef {
    fn new(btf_type: cbtf::btf_type) -> Typedef {
        Typedef { btf_type }
    }
}

impl BtfType for Typedef {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Volatile {
    btf_type: cbtf::btf_type,
}

impl Volatile {
    fn new(btf_type: cbtf::btf_type) -> Volatile {
        Volatile { btf_type }
    }
}

impl BtfType for Volatile {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Func {
    btf_type: cbtf::btf_type,
}

impl Func {
    fn new(btf_type: cbtf::btf_type) -> Func {
        Func { btf_type }
    }

    pub fn is_static(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_STATIC
    }

    pub fn is_global(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_GLOBAL
    }

    pub fn is_extern(&self) -> bool {
        self.btf_type.vlen() == cbtf::BTF_FUNC_EXTERN
    }
}

impl BtfType for Func {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct FuncProto {
    btf_type: cbtf::btf_type,
    pub parameters: Vec<Parameter>,
}

impl FuncProto {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<FuncProto> {
        let mut parameters = Vec::new();

        for _ in 0..btf_type.vlen() {
            parameters.push(Parameter::from_reader(reader, endianness)?);
        }

        Ok(FuncProto {
            btf_type,
            parameters,
        })
    }

    pub fn return_type_id(&self) -> u32 {
        self.btf_type.r#type()
    }
}

#[derive(Clone)]
pub struct Parameter {
    btf_param: cbtf::btf_param,
}

impl Parameter {
    fn from_reader<R: Read>(reader: &mut R, endianness: &cbtf::Endianness) -> Result<Parameter> {
        Ok(Parameter {
            btf_param: cbtf::btf_param::from_reader(reader, endianness)?,
        })
    }

    pub fn is_variadic(&self) -> bool {
        self.btf_param.name_off == 0 && self.btf_param.r#type == 0
    }
}

impl BtfType for Parameter {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_param.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_param.r#type)
    }
}

#[derive(Clone)]
pub struct Var {
    btf_type: cbtf::btf_type,
    btf_var: cbtf::btf_var,
}

impl Var {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Var> {
        Ok(Var {
            btf_type,
            btf_var: cbtf::btf_var::from_reader(reader, endianness)?,
        })
    }

    pub fn is_static(&self) -> bool {
        self.btf_var.linkage == 0
    }

    pub fn is_global(&self) -> bool {
        self.btf_var.linkage == 1
    }
}

impl BtfType for Var {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Datasec {
    btf_type: cbtf::btf_type,
    pub variables: Vec<VarSecinfo>,
}

impl Datasec {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Datasec> {
        let mut variables = Vec::new();

        for _ in 0..btf_type.vlen() {
            variables.push(VarSecinfo::from_reader(reader, endianness)?);
        }

        Ok(Datasec {
            btf_type,
            variables,
        })
    }
}

impl BtfType for Datasec {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct VarSecinfo {
    btf_var_secinfo: cbtf::btf_var_secinfo,
}

impl VarSecinfo {
    fn from_reader<R: Read>(reader: &mut R, endianness: &cbtf::Endianness) -> Result<VarSecinfo> {
        Ok(VarSecinfo {
            btf_var_secinfo: cbtf::btf_var_secinfo::from_reader(reader, endianness)?,
        })
    }

    pub fn offset(&self) -> u32 {
        self.btf_var_secinfo.offset
    }

    pub fn size(&self) -> usize {
        self.btf_var_secinfo.size as usize
    }
}

impl BtfType for VarSecinfo {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_var_secinfo.r#type)
    }
}

#[derive(Clone)]
pub struct Float {
    btf_type: cbtf::btf_type,
}

impl Float {
    fn new(btf_type: cbtf::btf_type) -> Float {
        Float { btf_type }
    }

    pub fn size(&self) -> usize {
        self.btf_type.size()
    }
}

impl BtfType for Float {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct DeclTag {
    btf_type: cbtf::btf_type,
    btf_decl_tag: cbtf::btf_decl_tag,
}

impl DeclTag {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<DeclTag> {
        Ok(DeclTag {
            btf_type,
            btf_decl_tag: cbtf::btf_decl_tag::from_reader(reader, endianness)?,
        })
    }

    pub fn component_index(&self) -> Option<u32> {
        let component_idx = self.btf_decl_tag.component_idx;
        match component_idx {
            x if x < 0 => None,
            x => Some(x as u32),
        }
    }
}

impl BtfType for DeclTag {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }

    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

#[derive(Clone)]
pub struct Enum64 {
    btf_type: cbtf::btf_type,
    pub members: Vec<Enum64Member>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum64 {
    fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Enum64> {
        let mut members = Vec::new();

        for _ in 0..btf_type.vlen() {
            members.push(Enum64Member::from_reader(reader, endianness)?);
        }

        Ok(Enum64 { btf_type, members })
    }

    pub fn is_signed(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }

    pub fn len(&self) -> usize {
        self.btf_type.vlen() as usize
    }

    pub fn size(&self) -> usize {
        self.btf_type.size()
    }
}

impl BtfType for Enum64 {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

#[derive(Clone)]
pub struct Enum64Member {
    btf_enum64: cbtf::btf_enum64,
}

impl Enum64Member {
    fn from_reader<R: Read>(reader: &mut R, endianness: &cbtf::Endianness) -> Result<Enum64Member> {
        Ok(Enum64Member {
            btf_enum64: cbtf::btf_enum64::from_reader(reader, endianness)?,
        })
    }

    pub fn val(&self) -> u64 {
        (self.btf_enum64.val_hi32 as u64) << 32 | self.btf_enum64.val_lo32 as u64
    }
}

impl BtfType for Enum64Member {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_enum64.name_off)
    }
}
