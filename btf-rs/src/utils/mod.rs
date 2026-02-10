//! Utilities built on top of the `btf_rs` library to ease the development for
//! common use cases.

pub mod collection;
#[cfg(feature = "elf")]
pub mod elf;
