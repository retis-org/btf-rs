//! Library for the [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html).
//! The BPF Type Format is a metadata format encoding debugging information such
//! as types, function prototypes, structure layouts, etc. and is often used,
//! but not limited, to deal with [eBPF](https://ebpf.io) programs.
//!
//! The [integration tests](https://github.com/retis-org/btf-rs/blob/main/btf-rs/tests/integration_test.rs)
//! give good examples on how to use this library. We recommend reading the
//! [official BTF documentation](https://www.kernel.org/doc/html/latest/bpf/btf.html)
//! as this library is offering a low-level API.
//!
//! ### Parsing BTF
//!
//! The main object this library offers is [`Btf`], which represents a parsed
//! BTF object. It offers helpers to resolve ids ([`u32`]), names ([`String`])
//! and types / chained types ([`Type`]).
//!
//! [`Btf`] can be constructed using a BTF file or a split BTF one. BTF files
//! hold self-contained information, while split BTF files are built upon a base
//! BTF file and extend it. For example, in a standard Linux environment BTF
//! files and split files can be found under `/sys/kernel/btf`,
//! `/sys/kernel/btf/vmlinux` being the BTF file for the kernel and other files
//! matching `/sys/kernel/btf/<module-name>` being BTF split files for its
//! modules.
//!
//! ```no_run
//! use btf_rs::Btf;
//!
//! let base = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
//!
//! let ovs = Btf::from_split_file("/sys/kernel/btf/openvswitch", &base).unwrap();
//! let bbr = Btf::from_split_file("/sys/kernel/btf/tcp_bbr", &base).unwrap();
//! ```
//!
//! *Btf-rs* also supports constructing [`Btf`] using byte slices.
//!
//! ```no_run
//! use std::fs;
//! use btf_rs::Btf;
//!
//! let base = Btf::from_bytes(&fs::read("/sys/kernel/btf/vmlinux").unwrap()).unwrap();
//!
//! let ovs = Btf::from_split_bytes(&fs::read("/sys/kernel/btf/openvswitch").unwrap(), &base)
//!           .unwrap();
//! let bbr = Btf::from_split_bytes(&fs::read("/sys/kernel/btf/bbr").unwrap(), &base).unwrap();
//! ```
//!
//! ### Resolving types
//!
//! Types can be resolved using a [`Btf`] object. The following is an
//! example of how a function can be inspected to retrieve information about its
//! first parameter. Here the function `kfree_skb_reason` is taking a `struct
//! sk_buff *` as its first argument.
//!
//! ```no_run
//! use btf_rs::*;
//!
//! let btf = Btf::from_file("/sys/kernel/btf/vmlinux").unwrap();
//!
//! let func = match btf
//!     .resolve_types_by_name("kfree_skb_reason")
//!     .unwrap()
//!     .pop()
//!     .unwrap()
//! {
//!     Type::Func(func) => func,
//!     _ => panic!("Resolved type is not a function"),
//! };
//!
//! let proto = match btf.resolve_chained_type(&func).unwrap() {
//!     Type::FuncProto(proto) => proto,
//!     _ => panic!("Resolved type is not a function proto"),
//! };
//!
//! assert!(proto.parameters.len() > 1);
//!
//! // The following prints "skb".
//! println!("{}", btf.resolve_name(&proto.parameters[0]).unwrap());
//!
//! let ptr = match btf.resolve_chained_type(&proto.parameters[0]).unwrap() {
//!     Type::Ptr(ptr) => ptr,
//!     _ => panic!("Resolved type is not a pointer"),
//! };
//!
//! let r#struct = match btf.resolve_chained_type(&ptr).unwrap() {
//!     Type::Struct(r#struct) => r#struct,
//!     _ => panic!("Resolved type is not a struct"),
//! };
//!
//! // The following prints "sk_buff".
//! println!("{}", btf.resolve_name(&r#struct).unwrap());
//! ```
//!
//! Other information such as function scope and return value, structure size
//! and members, etc. can be retrieved. For all those see the [`Type`] and its
//! associated structures documentation.
//!
//! ### Additional objects
//!
//! Additional objects and helpers built on top of the ones described here can
//! be found in the [`utils`] sub-module. Those are aimed at easing BTF
//! consumption in common cases, such as parsing all BTF files of a running
//! Linux kernel and its modules or dealing with .BTF ELF sections.
//!
//! ### Feature flags
//!
//! - `elf`: Enable helpers parsing the .BTF section of ELF files in
//!   [`utils::elf`].
//! - `elf-compression`: Enable handling of compressed ELF files (e.g.
//!   compressed kernel modules) in [`utils::elf`]. The Bzip2, Gzip, Xz and Zstd
//!   compression algorithms are currently supported.
//! - `regex`: Enable name resolutions by regex ([`regex::Regex`]).
//!
//! ### `Btf` backends
//!
//! The [`Btf`] object supports different internal backends ([`Backend`]),
//! optimized for different uses: [`Backend::Cache`] and [`Backend::Mmap`]. The
//! former provides a faster API at the cost of slower initialization and
//! increase in memory footprint. The latter provides a fast initialization time
//! and lower memory footprint at the cast of slower API performances.
//!
//! [`Backend::Cache`] is used by default. The backend can also be explicitly
//! selected using dedicated constructors (see `from_*_with_backend` helpers).
//! All BTF data read from bytes use [`Backend::Cache`] (this includes all `elf`
//! feature helpers) and [`Backend::Mmap`] is only supported for base BTF files.
//!
//! A [benchmark utility](https://github.com/retis-org/btf-rs/blob/main/btf-rs/examples/benchmark.rs)
//! is provided to gather actual numbers. It should be run on the *target*
//! machine, to investigate how *btf-rs* would perform. E.g.
//!
//! ```shell
//! $ cargo build --release -F regex --example benchmark
//! $ ./target/release/examples/benchmark --help
//! [...]
//! $ ./target/release/examples/benchmark -i 100 \
//!     --id 77378 --name __kfree_skb --regex "^[[:alnum:]]+_drop_reason$" \
//!     --backend cache
//! [...]
//! ```
//!
//! A few parameters are required to configure the type id and name to use for
//! querying the BTF data. Those can be selected by first inspecting the BTF data
//! using `bpftool` (`bpftool btf dump file /sys/kernel/btf/vmlinux`).
//
// ### Internal design
//
// From low to higher levels.
//
// - `cbtf` operates at the BTF metadata level. It allows to handle the format
//   and provides an API enforcing the format rules. It strictly follows the
//   format definition.
// - `obj` handles our representation of the BTF data and allow converting
//   `cbtf` representation into `btf` ones.
// - `btf` provides our representation of the BTF data in Rust and a unified API
//   on top of the BTF metadata representations. Additional logic is allowed,
//   e.g. the `Btf` object handles split files and anonymous types.
// - `utils` provides higher levels representation built on top of the `Btf`
//   object.

pub mod btf;
pub mod error;
pub mod utils;

mod cbtf;
mod obj;

#[doc(inline)]
pub use btf::*;
pub use error::*;
