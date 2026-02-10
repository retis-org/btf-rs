//! Parsing logic for the C representation of the BTF data. See,
//! <https://www.kernel.org/doc/html/latest/bpf/btf.html>
//!
//! Please use a packed C representation so mem::size_of can be used.

#![allow(non_camel_case_types, dead_code)]

use std::{
    io::{Read, Seek, SeekFrom},
    mem,
};

use btf_rs_derive::cbtf_type;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};

use crate::{Error, Result};

pub(super) enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn u16_from_bytes(&self, buf: &[u8]) -> Result<u16> {
        if buf.len() < 2 {
            return Err(Error::OpNotSupp("Not enough bytes in buffer".to_string()));
        }

        Ok(match &self {
            Endianness::Little => LittleEndian::read_u16(buf),
            Endianness::Big => BigEndian::read_u16(buf),
        })
    }

    fn u32_from_bytes(&self, buf: &[u8]) -> Result<u32> {
        if buf.len() < 4 {
            return Err(Error::OpNotSupp("Not enough bytes in buffer".to_string()));
        }

        Ok(match &self {
            Endianness::Little => LittleEndian::read_u32(buf),
            Endianness::Big => BigEndian::read_u32(buf),
        })
    }

    fn i32_from_bytes(&self, buf: &[u8]) -> Result<i32> {
        if buf.len() < 4 {
            return Err(Error::OpNotSupp("Not enough bytes in buffer".to_string()));
        }

        Ok(match &self {
            Endianness::Little => LittleEndian::read_i32(buf),
            Endianness::Big => BigEndian::read_i32(buf),
        })
    }

    fn u16_from_reader<R: Read>(&self, reader: &mut R) -> Result<u16> {
        Ok(match &self {
            Endianness::Little => reader.read_u16::<LittleEndian>()?,
            Endianness::Big => reader.read_u16::<BigEndian>()?,
        })
    }

    fn u32_from_reader<R: Read>(&self, reader: &mut R) -> Result<u32> {
        Ok(match &self {
            Endianness::Little => reader.read_u32::<LittleEndian>()?,
            Endianness::Big => reader.read_u32::<BigEndian>()?,
        })
    }

    fn i32_from_reader<R: Read>(&self, reader: &mut R) -> Result<i32> {
        Ok(match &self {
            Endianness::Little => reader.read_i32::<LittleEndian>()?,
            Endianness::Big => reader.read_i32::<BigEndian>()?,
        })
    }
}

// BTF kind, from include/uapi/linux/btf.h.
pub(super) enum BtfKind {
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKind {
    // Construct a `BtfKind` from its id.
    pub(super) fn from_id(id: u32) -> Result<Self> {
        use BtfKind::*;
        Ok(match id {
            1 => Int,
            2 => Ptr,
            3 => Array,
            4 => Struct,
            5 => Union,
            6 => Enum,
            7 => Fwd,
            8 => Typedef,
            9 => Volatile,
            10 => Const,
            11 => Restrict,
            12 => Func,
            13 => FuncProto,
            14 => Var,
            15 => Datasec,
            16 => Float,
            17 => DeclTag,
            18 => TypeTag,
            19 => Enum64,
            x => return Err(Error::Format(format!("Unsupported BTF type {x}"))),
        })
    }

    // Returns the size a given type takes while stored in memory.
    fn size(&self, vlen: usize) -> usize {
        use BtfKind::*;
        mem::size_of::<btf_type>()
            + match self {
                Ptr | Fwd | Typedef | Volatile | Const | Restrict | Func | Float | TypeTag => 0,
                Int => mem::size_of::<btf_int>(),
                Array => mem::size_of::<btf_array>(),
                Struct | Union => vlen * mem::size_of::<btf_member>(),
                Enum => vlen * mem::size_of::<btf_enum>(),
                FuncProto => vlen * mem::size_of::<btf_param>(),
                Var => mem::size_of::<btf_var>(),
                Datasec => vlen * mem::size_of::<btf_var_secinfo>(),
                DeclTag => mem::size_of::<btf_decl_tag>(),
                Enum64 => vlen * mem::size_of::<btf_enum64>(),
            }
    }

    // Returns true if the type is allowed to be anonymous, aka. a valid name
    // offset of 0. Those can be recognized in the BTF documentation when the
    // name offset is "0 or offset to a valid C identifier".
    fn has_anon_name(&self) -> bool {
        use BtfKind::*;
        matches!(self, Struct | Union | Enum | Enum64)
    }

    // Returns true if the type is using the size/type field as size.
    fn has_size(&self) -> bool {
        use BtfKind::*;
        matches!(self, Int | Struct | Union | Enum | Datasec | Float | Enum64)
    }

    // Returns true if the type is using the size/type field as type.
    fn has_type(&self) -> bool {
        use BtfKind::*;
        matches!(
            self,
            Ptr | Typedef
                | Volatile
                | Const
                | Restrict
                | Func
                | FuncProto
                | Var
                | DeclTag
                | TypeTag
        )
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub(super) struct btf_header {
    pub(super) magic: u16,
    pub(super) version: u8,
    pub(super) flags: u8,
    pub(super) hdr_len: u32,
    pub(super) type_off: u32,
    pub(super) type_len: u32,
    pub(super) str_off: u32,
    pub(super) str_len: u32,
}

impl btf_header {
    pub(super) fn from_reader<R: Read>(reader: &mut R) -> Result<(btf_header, Endianness)> {
        let magic = reader.read_u16::<LittleEndian>()?;
        #[allow(clippy::mixed_case_hex_literals)]
        let endianness = match magic {
            0xeB9F => Endianness::Little,
            0x9FeB => Endianness::Big,
            magic => return Err(Error::Format(format!("Invalid BTF magic: {magic:#x}"))),
        };

        Ok((
            btf_header {
                magic,
                version: reader.read_u8()?,
                flags: reader.read_u8()?,
                hdr_len: endianness.u32_from_reader(reader)?,
                type_off: endianness.u32_from_reader(reader)?,
                type_len: endianness.u32_from_reader(reader)?,
                str_off: endianness.u32_from_reader(reader)?,
                str_len: endianness.u32_from_reader(reader)?,
            },
            endianness,
        ))
    }

    // Estimates the number of strings and types defined in the BTF object.
    pub(super) fn estimates(&self) -> (usize, usize) {
        let strings = self.str_len as usize / 15;
        let types = self.type_len as usize / 22;
        (strings, types)
    }
}

// Skip a BTF type defined in the provided seekable reader.
pub(super) fn btf_skip_type<R: Read + Seek>(reader: &mut R, endianness: &Endianness) -> Result<()> {
    // Skip header::name_off.
    reader.seek(SeekFrom::Current(4))?;

    // Read header::info.
    let info = endianness.u32_from_reader(reader)?;

    // Skip the BTF type size (we already skip 4 bytes + read 4 bytes).
    let id = (info >> 24) & 0x1f;
    let vlen = (info & 0xffff) as usize;
    reader.seek(SeekFrom::Current(
        (BtfKind::from_id(id)?.size(vlen) - 2 * mem::size_of::<u32>()) as i64,
    ))?;

    Ok(())
}

#[cbtf_type]
pub(super) struct btf_type {
    name_off: u32,
    // bits 0-15:  vlen
    // bits 16-23: unused
    // bits 24-28: kind
    // bits 39-30: unused
    // bit  31:    kind_flag
    info: u32,
    // union {
    //         _u32 size;
    //         _u32 type;
    // };
    size_type: u32,
}

impl btf_type {
    pub(super) fn name_offset(&self) -> Option<u32> {
        let offset = self.name_off;
        if offset > 0 {
            return Some(offset);
        }

        if let Ok(kind) = BtfKind::from_id(self.kind()) {
            if kind.has_anon_name() {
                return Some(0);
            }
        }

        None
    }

    pub(super) fn vlen(&self) -> u32 {
        self.info & 0xffff
    }

    pub(super) fn kind(&self) -> u32 {
        (self.info >> 24) & 0x1f
    }

    pub(super) fn kind_flag(&self) -> u32 {
        (self.info >> 31) & 0x1
    }

    pub(super) fn size(&self) -> Option<usize> {
        if let Ok(kind) = BtfKind::from_id(self.kind()) {
            if kind.has_size() {
                return Some(self.size_type as usize);
            }
        }
        None
    }

    pub(super) fn r#type(&self) -> Option<u32> {
        if let Ok(kind) = BtfKind::from_id(self.kind()) {
            if kind.has_type() {
                return Some(self.size_type);
            }
        }
        None
    }
}

#[cbtf_type]
pub(super) struct btf_int {
    data: u32,
}

impl btf_int {
    pub(super) fn encoding(&self) -> u32 {
        (self.data & 0x0f000000) >> 24
    }

    pub(super) fn offset(&self) -> u32 {
        (self.data & 0x00ff0000) >> 16
    }

    pub(super) fn bits(&self) -> u32 {
        self.data & 0x000000ff
    }
}

pub(super) const BTF_INT_SIGNED: u32 = 1 << 0;
pub(super) const BTF_INT_CHAR: u32 = 1 << 1;
pub(super) const BTF_INT_BOOL: u32 = 1 << 2;

#[cbtf_type]
pub(super) struct btf_array {
    pub(super) r#type: u32,
    pub(super) index_type: u32,
    pub(super) nelems: u32,
}

#[cbtf_type]
pub(super) struct btf_member {
    pub(super) name_off: u32,
    pub(super) r#type: u32,
    pub(super) offset: u32,
}

#[cbtf_type]
pub(super) struct btf_enum {
    pub(super) name_off: u32,
    pub(super) val: u32,
}

pub(super) const BTF_FUNC_STATIC: u32 = 0;
pub(super) const BTF_FUNC_GLOBAL: u32 = 1;
pub(super) const BTF_FUNC_EXTERN: u32 = 2;

#[cbtf_type]
pub(super) struct btf_param {
    pub(super) name_off: u32,
    pub(super) r#type: u32,
}

#[cbtf_type]
pub(super) struct btf_var {
    pub(super) linkage: u32,
}

pub(super) const BTF_VAR_STATIC: u32 = 0;
pub(super) const BTF_VAR_GLOBAL_ALLOCATED: u32 = 1;
pub(super) const BTF_VAR_GLOBAL_EXTERN: u32 = 2;

#[cbtf_type]
pub(super) struct btf_var_secinfo {
    pub(super) r#type: u32,
    pub(super) offset: u32,
    pub(super) size: u32,
}

#[cbtf_type]
pub(super) struct btf_decl_tag {
    pub(super) component_idx: i32,
}

#[cbtf_type]
pub(super) struct btf_enum64 {
    pub(super) name_off: u32,
    pub(super) val_lo32: u32,
    pub(super) val_hi32: u32,
}
