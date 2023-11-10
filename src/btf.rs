#![allow(dead_code)]

use std::{
    convert::AsRef,
    fs::File,
    io::{BufReader, Cursor, Read},
    path::Path,
    sync::Arc,
};

use anyhow::{bail, Result};

use crate::cbtf;
use crate::obj::BtfObj;

/// Main representation of a parsed BTF object. Provides helpers to resolve
/// types and their associated names.
pub struct Btf {
    obj: Arc<BtfObj>,
    base: Option<Arc<BtfObj>>,
}

impl Btf {
    /// Parse a stand-alone BTF object file and construct a Rust representation for later
    /// use. Trying to open split BTF files using this function will fail. For split BTF
    /// files use `Btf::from_split_file()`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Btf> {
        Ok(Btf {
            obj: Arc::new(BtfObj::from_reader(
                &mut BufReader::new(File::open(path)?),
                None,
            )?),
            base: None,
        })
    }

    /// Parse a split BTF object file and construct a Rust representation for later
    /// use. A base Btf object must be provided.
    pub fn from_split_file<P: AsRef<Path>>(path: P, base: &Btf) -> Result<Btf> {
        if !path.as_ref().is_file() {
            bail!("Invalid BTF file {}", path.as_ref().display());
        }

        Ok(Btf {
            obj: Arc::new(BtfObj::from_reader(
                &mut BufReader::new(File::open(path)?),
                Some(base.obj.clone()),
            )?),
            base: Some(base.obj.clone()),
        })
    }

    /// Performs the same actions as from_file(), but fed with a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Btf> {
        Ok(Btf {
            obj: Arc::new(BtfObj::from_reader(&mut Cursor::new(bytes), None)?),
            base: None,
        })
    }

    /// Performs the same actions as from_split_file(), but fed with a byte slice.
    pub fn from_split_bytes(bytes: &[u8], base: &Btf) -> Result<Btf> {
        let base = base.obj.clone();
        Ok(Btf {
            obj: Arc::new(BtfObj::from_reader(
                &mut Cursor::new(bytes),
                Some(base.clone()),
            )?),
            base: Some(base),
        })
    }

    /// Find a list of BTF ids using their name as a key.
    pub fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<u32>> {
        let mut ids = Vec::new();

        if let Some(base) = &self.base {
            if let Ok(mut ids_base) = base.resolve_ids_by_name(name) {
                ids.append(&mut ids_base);
            }
        }
        if let Ok(mut ids_obj) = self.obj.resolve_ids_by_name(name) {
            ids.append(&mut ids_obj);
        }

        if ids.is_empty() {
            bail!("No id linked to name {name}");
        }
        Ok(ids)
    }

    /// Find a BTF type using its id as a key.
    pub fn resolve_type_by_id(&self, id: u32) -> Result<Type> {
        match &self.base {
            Some(base) => base
                .resolve_type_by_id(id)
                .or_else(|_| self.obj.resolve_type_by_id(id)),
            None => self.obj.resolve_type_by_id(id),
        }
    }

    /// Find a list of BTF types using their name as a key.
    pub fn resolve_types_by_name(&self, name: &str) -> Result<Vec<Type>> {
        let mut types = Vec::new();

        if let Some(base) = &self.base {
            if let Ok(mut types_base) = base.resolve_types_by_name(name) {
                types.append(&mut types_base);
            }
        }
        if let Ok(mut types_obj) = self.obj.resolve_types_by_name(name) {
            types.append(&mut types_obj);
        }

        if types.is_empty() {
            // Keep "id" and not "type" below to be consitent with
            // BtfObj::resolve_types_by_name.
            bail!("No id linked to name {name}");
        }
        Ok(types)
    }

    /// Resolve a name referenced by a Type which is defined in the current BTF
    /// object.
    pub fn resolve_name<T: BtfType + ?Sized>(&self, r#type: &T) -> Result<String> {
        match &self.base {
            Some(base) => base
                .resolve_name(r#type)
                .or_else(|_| self.obj.resolve_name(r#type)),
            None => self.obj.resolve_name(r#type),
        }
    }

    /// Types can have a reference to another one, e.g. `Ptr -> Int`. This
    /// helper resolve a Type referenced in an other one. It is the main helper
    /// to traverse the Type tree.
    pub fn resolve_chained_type<T: BtfType + ?Sized>(&self, r#type: &T) -> Result<Type> {
        self.resolve_type_by_id(r#type.get_type_id()?)
    }

    /// This helper returns an iterator that allow to resolve a Type
    /// referenced in another one all the way down to the chain.
    /// The helper makes use of `Btf::resolve_chained_type()`.
    pub fn type_iter<'a, T: BtfType + ?Sized>(&'a self, r#type: &'a T) -> TypeIter {
        let ty = self.resolve_chained_type(r#type).ok();
        TypeIter {
            btf: self,
            r#type: ty,
        }
    }
}

/// Iterator type returned by `Btf::type_iter()`.
pub struct TypeIter<'a> {
    btf: &'a Btf,
    r#type: Option<Type>,
}

/// Iterator for `Btf::TypeIter`.
impl<'a> Iterator for TypeIter<'a> {
    type Item = Type;

    fn next(&mut self) -> Option<Self::Item> {
        match self.r#type.clone() {
            None => None,
            Some(ty) => {
                self.r#type = match ty.as_btf_type() {
                    Some(x) => self.btf.resolve_chained_type(x).ok(),
                    // We might have encountered Void or other
                    // non-BtfType types.
                    None => None,
                };
                Some(ty)
            }
        }
    }
}

/// Rust representation of BTF types. Each type then contains its own specific
/// data and provides helpers to access it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Type {
    Void,
    Int(Int),
    Ptr(Ptr),
    Array(Array),
    Struct(Struct),
    Union(Union),
    Enum(Enum),
    Fwd(Fwd),
    Typedef(Typedef),
    Volatile(Volatile),
    Const(Const),
    Restrict(Restrict),
    Func(Func),
    FuncProto(FuncProto),
    Var(Var),
    Datasec(Datasec),
    Float(Float),
    DeclTag(DeclTag),
    TypeTag(TypeTag),
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

    pub fn as_btf_type(&self) -> Option<&dyn BtfType> {
        match self {
            Type::Int(i) => Some(i),
            Type::Ptr(p) => Some(p),
            Type::Array(a) => Some(a),
            Type::Struct(s) => Some(s),
            Type::Union(u) => Some(u),
            Type::Enum(e) => Some(e),
            Type::Fwd(f) => Some(f),
            Type::Typedef(td) => Some(td),
            Type::Volatile(v) => Some(v),
            Type::Const(c) => Some(c),
            Type::Restrict(r) => Some(r),
            Type::Func(fu) => Some(fu),
            Type::Var(v) => Some(v),
            Type::Datasec(ds) => Some(ds),
            Type::Float(f) => Some(f),
            Type::DeclTag(dt) => Some(dt),
            Type::TypeTag(tt) => Some(tt),
            Type::Enum64(e64) => Some(e64),
            _ => None,
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

/// Rust representation for BTF type `BTF_KIND_INT`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Int {
    btf_type: cbtf::btf_type,
    btf_int: cbtf::btf_int,
}

impl Int {
    pub(super) fn from_reader<R: Read>(
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

/// Rust representation for BTF type `BTF_KIND_PTR`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ptr {
    btf_type: cbtf::btf_type,
}

impl Ptr {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Ptr {
        Ptr { btf_type }
    }
}

impl BtfType for Ptr {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

/// Rust representation for BTF type `BTF_KIND_ARRAY`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Array {
    btf_type: cbtf::btf_type,
    btf_array: cbtf::btf_array,
}

#[allow(clippy::len_without_is_empty)]
impl Array {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
        btf_type: cbtf::btf_type,
    ) -> Result<Array> {
        Ok(Array {
            btf_type,
            btf_array: cbtf::btf_array::from_reader(reader, endianness)?,
        })
    }

    pub fn len(&self) -> usize {
        self.btf_array.nelems as usize
    }
}

impl BtfType for Array {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_array.r#type)
    }
}

/// Rust representation for BTF type `BTF_KIND_STRUCT`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Struct {
    btf_type: cbtf::btf_type,
    pub members: Vec<Member>,
}

impl Struct {
    pub(super) fn from_reader<R: Read>(
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

/// Rust representation for BTF type `BTF_KIND_UNION`.
pub type Union = Struct;

/// Represents a [`Struct`] member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Member {
    kind_flag: u32,
    btf_member: cbtf::btf_member,
}

impl Member {
    pub(super) fn from_reader<R: Read>(
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

/// Rust representation for BTF type `BTF_KIND_ENUM`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enum {
    btf_type: cbtf::btf_type,
    pub members: Vec<EnumMember>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum {
    pub(super) fn from_reader<R: Read>(
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

/// Represents an [`Enum`] member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumMember {
    btf_enum: cbtf::btf_enum,
}

impl EnumMember {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
    ) -> Result<EnumMember> {
        Ok(EnumMember {
            btf_enum: cbtf::btf_enum::from_reader(reader, endianness)?,
        })
    }

    pub fn val(&self) -> u32 {
        self.btf_enum.val
    }
}

impl BtfType for EnumMember {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_enum.name_off)
    }
}

/// Rust representation for BTF type `BTF_KIND_FWD`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fwd {
    btf_type: cbtf::btf_type,
}

impl Fwd {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Fwd {
        Fwd { btf_type }
    }

    /// Tests if the forward declaration is for a struct type.
    pub fn is_struct(&self) -> bool {
        self.btf_type.kind_flag() == 0
    }

    /// Tests if the forward declaration is for a union type.
    pub fn is_union(&self) -> bool {
        self.btf_type.kind_flag() == 1
    }
}

impl BtfType for Fwd {
    fn get_name_offset(&self) -> Result<u32> {
        Ok(self.btf_type.name_off)
    }
}

/// Rust representation for BTF type `BTF_KIND_TYPEDEF`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Typedef {
    btf_type: cbtf::btf_type,
}

impl Typedef {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Typedef {
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

/// Rust representation for BTF type `BTF_KIND_TYPE_TAG`.
pub type TypeTag = Typedef;

/// Rust representation for BTF type `BTF_KIND_VOLATILE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Volatile {
    btf_type: cbtf::btf_type,
}

impl Volatile {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Volatile {
        Volatile { btf_type }
    }
}

impl BtfType for Volatile {
    fn get_type_id(&self) -> Result<u32> {
        Ok(self.btf_type.r#type())
    }
}

/// Rust representation for BTF type `BTF_KIND_CONST`.
pub type Const = Volatile;

/// Rust representation for BTF type `BTF_KIND_RESTRICT`.
pub type Restrict = Volatile;

/// Rust representation for BTF type `BTF_KIND_FUNC`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Func {
    btf_type: cbtf::btf_type,
}

impl Func {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Func {
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

/// Rust representation for BTF type `BTF_KIND_FUNC_PROTO`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuncProto {
    btf_type: cbtf::btf_type,
    pub parameters: Vec<Parameter>,
}

impl FuncProto {
    pub(super) fn from_reader<R: Read>(
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

/// Represents a [`FuncProto`] parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameter {
    btf_param: cbtf::btf_param,
}

impl Parameter {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
    ) -> Result<Parameter> {
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

/// Rust representation for BTF type `BTF_KIND_VAR`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Var {
    btf_type: cbtf::btf_type,
    btf_var: cbtf::btf_var,
}

impl Var {
    pub(super) fn from_reader<R: Read>(
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

/// Rust representation for BTF type `BTF_KIND_DATASEC`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Datasec {
    btf_type: cbtf::btf_type,
    pub variables: Vec<VarSecinfo>,
}

impl Datasec {
    pub(super) fn from_reader<R: Read>(
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

/// Represents a [`Datasec`] variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VarSecinfo {
    btf_var_secinfo: cbtf::btf_var_secinfo,
}

impl VarSecinfo {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
    ) -> Result<VarSecinfo> {
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

/// Rust representation for BTF type `BTF_KIND_FLOAT`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Float {
    btf_type: cbtf::btf_type,
}

impl Float {
    pub(super) fn new(btf_type: cbtf::btf_type) -> Float {
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

/// Rust representation for BTF type `BTF_KIND_DECL_TAG`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclTag {
    btf_type: cbtf::btf_type,
    btf_decl_tag: cbtf::btf_decl_tag,
}

impl DeclTag {
    pub(super) fn from_reader<R: Read>(
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

/// Rust representation for BTF type `BTF_KIND_ENUM64`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enum64 {
    btf_type: cbtf::btf_type,
    pub members: Vec<Enum64Member>,
}

#[allow(clippy::len_without_is_empty)]
impl Enum64 {
    pub(super) fn from_reader<R: Read>(
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

/// Represents an [`Enum64`] member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enum64Member {
    btf_enum64: cbtf::btf_enum64,
}

impl Enum64Member {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &cbtf::Endianness,
    ) -> Result<Enum64Member> {
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
