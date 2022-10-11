//! Parsing logic for the C representation of the BTF data. See,
//! https://www.kernel.org/doc/html/latest/bpf/btf.html
//!
//! Please use a packed C representation so mem::size_of can be used.

#![allow(non_camel_case_types, dead_code)]

use std::io::Read;

use anyhow::{bail, Result};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

pub(super) enum Endianness {
    Little,
    Big,
}

impl Endianness {
    fn u16_from_reader<R: Read>(&self, reader: &mut R) -> Result<u16, std::io::Error> {
        match &self {
            Endianness::Little => reader.read_u16::<LittleEndian>(),
            Endianness::Big => reader.read_u16::<BigEndian>(),
        }
    }

    fn u32_from_reader<R: Read>(&self, reader: &mut R) -> Result<u32, std::io::Error> {
        match &self {
            Endianness::Little => reader.read_u32::<LittleEndian>(),
            Endianness::Big => reader.read_u32::<BigEndian>(),
        }
    }

    fn i32_from_reader<R: Read>(&self, reader: &mut R) -> Result<i32, std::io::Error> {
        match &self {
            Endianness::Little => reader.read_i32::<LittleEndian>(),
            Endianness::Big => reader.read_i32::<BigEndian>(),
        }
    }
}

#[derive(Clone, Copy)]
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
        let endianness = match magic {
            0xeB9F => Endianness::Little,
            0x9FeB => Endianness::Big,
            magic => bail!("Invalid BTF magic: {:#x}", magic),
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
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_type {
    pub(super) name_off: u32,
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
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_type> {
        Ok(btf_type {
            name_off: endianness.u32_from_reader(reader)?,
            info: endianness.u32_from_reader(reader)?,
            size_type: endianness.u32_from_reader(reader)?,
        })
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

    pub(super) fn size(&self) -> usize {
        self.size_type as usize
    }

    pub(super) fn r#type(&self) -> u32 {
        self.size_type
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_int {
    data: u32,
}

impl btf_int {
    pub(super) fn from_reader<R: Read>(reader: &mut R, endianness: &Endianness) -> Result<btf_int> {
        Ok(btf_int {
            data: endianness.u32_from_reader(reader)?,
        })
    }

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

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_array {
    pub(super) r#type: u32,
    pub(super) index_type: u32,
    pub(super) nelems: u32,
}

impl btf_array {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_array> {
        Ok(btf_array {
            r#type: endianness.u32_from_reader(reader)?,
            index_type: endianness.u32_from_reader(reader)?,
            nelems: endianness.u32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_member {
    pub(super) name_off: u32,
    pub(super) r#type: u32,
    pub(super) offset: u32,
}

impl btf_member {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_member> {
        Ok(btf_member {
            name_off: endianness.u32_from_reader(reader)?,
            r#type: endianness.u32_from_reader(reader)?,
            offset: endianness.u32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_enum {
    pub(super) name_off: u32,
    pub(super) val: i32,
}

impl btf_enum {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_enum> {
        Ok(btf_enum {
            name_off: endianness.u32_from_reader(reader)?,
            val: endianness.i32_from_reader(reader)?,
        })
    }
}

pub(super) const BTF_FUNC_STATIC: u32 = 0;
pub(super) const BTF_FUNC_GLOBAL: u32 = 1;
pub(super) const BTF_FUNC_EXTERN: u32 = 2;

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_param {
    pub(super) name_off: u32,
    pub(super) r#type: u32,
}

impl btf_param {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_param> {
        Ok(btf_param {
            name_off: endianness.u32_from_reader(reader)?,
            r#type: endianness.u32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_var {
    pub(super) linkage: u32,
}

impl btf_var {
    pub(super) fn from_reader<R: Read>(reader: &mut R, endianness: &Endianness) -> Result<btf_var> {
        Ok(btf_var {
            linkage: endianness.u32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_var_secinfo {
    pub(super) r#type: u32,
    pub(super) offset: u32,
    pub(super) size: u32,
}

impl btf_var_secinfo {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_var_secinfo> {
        Ok(btf_var_secinfo {
            r#type: endianness.u32_from_reader(reader)?,
            offset: endianness.u32_from_reader(reader)?,
            size: endianness.u32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_decl_tag {
    pub(super) component_idx: i32,
}

impl btf_decl_tag {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_decl_tag> {
        Ok(btf_decl_tag {
            component_idx: endianness.i32_from_reader(reader)?,
        })
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub(super) struct btf_enum64 {
    pub(super) name_off: u32,
    pub(super) val_lo32: u32,
    pub(super) val_hi32: u32,
}

// FIXME for signed values.
impl btf_enum64 {
    pub(super) fn from_reader<R: Read>(
        reader: &mut R,
        endianness: &Endianness,
    ) -> Result<btf_enum64> {
        Ok(btf_enum64 {
            name_off: endianness.u32_from_reader(reader)?,
            val_lo32: endianness.u32_from_reader(reader)?,
            val_hi32: endianness.u32_from_reader(reader)?,
        })
    }
}
