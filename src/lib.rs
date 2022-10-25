//! Parsing library to extract information (type info, function signatures, etc)
//! from BTF files. This can be used to dynamically know what a given software,
//! including the kernel, exposes.
//!
//! The over design is as follow: a Btf object represents BTF information parsed
//! from a single source. It contains a list of strings allowing to resolve a
//! type using its name as the entrypoint. Then types are represented using a
//! Rust and a C part, e.g. for integers we have Int and cbtf::btf_int. The
//! former can be used by the user and should expose the information, the later
//! usually stores the information itself and stays private. This add some
//! indirection and duplication but overall it seemed more sane and easier to
//! work with and consume.
//!
//! Example:
//!
//! ```
//! use btf_rs::{Btf, Type};
//!
//! let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
//!
//! if let Type::Func(func) = btf.resolve_type_by_name("dev_get_by_name").unwrap() {
//!     if let Type::FuncProto(proto) = btf.resolve_chained_type(&func).unwrap() {
//!         for parameter in proto.parameters {
//!             println!("{}", btf.resolve_name(&parameter).unwrap());
//!         }
//!     }
//! }
//!
//! if let Type::Struct(r#struct) = btf.resolve_type_by_name("sk_buff").unwrap() {
//!     println!("{}", r#struct.size());
//!     println!("{}", r#struct.members.len());
//!
//!     for member in &r#struct.members {
//!         println!("{}", btf.resolve_name(member).unwrap());
//!     }
//!
//!     if let Type::Int(arg) = btf.resolve_chained_type(&r#struct.members[25]).unwrap() {
//!         println!("{}", arg.is_signed());
//!         println!("{}", arg.is_char());
//!         println!("{}", arg.is_bool());
//!     }
//! }
//! ```

pub mod btf;
mod cbtf;

pub use crate::btf::*;
