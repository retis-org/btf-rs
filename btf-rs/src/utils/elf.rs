//! # ELF helpers
//!
//! ELF helpers are provided to parse BTF data from .BTF ELF sections. This is
//! especially useful for parsing BTF data from kernel modules (e.g.
//! `/usr/lib/modules/`).
//!
//! ELF helpers are under the `elf` feature. Additional support for compressed
//! ELF files can be enabled with the `elf-compression` feature.

use std::{fs, path::Path};

use elf::{endian::AnyEndian, ElfBytes};

use crate::{utils::collection::BtfCollection, Error, Result};

/// Extract raw BTF data from the .BTF ELF section of the given file. Output can
/// be used to fed [`crate::Btf::from_bytes`] and
/// [`crate::Btf::from_split_bytes`].
pub fn extract_btf_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    #[cfg_attr(not(feature = "elf-compression"), allow(unused_mut))]
    let mut file = fs::read(&path)?;

    // If the file does not look like an ELF, try to decompress it.
    #[cfg(feature = "elf-compression")]
    if file.len() >= 4 && file[..4] != [0x7f, b'E', b'L', b'F'] {
        file = compression::try_decompress(file)?;
    }

    let elf = ElfBytes::<AnyEndian>::minimal_parse(&file)
        .map_err(|e| Error::Format(format!("Could not parse ELF file: {e}")))?;

    let btf_hdr = match elf
        .section_header_by_name(".BTF")
        .map_err(|e| Error::Format(format!("Could not get ELF section header for .BTF: {e}")))?
    {
        Some(hdr) => hdr,
        None => {
            return Err(Error::Format(format!(
                "No BTF section in {}",
                path.as_ref().display()
            )))
        }
    };

    let (btf, chdr) = elf
        .section_data(&btf_hdr)
        .map_err(|e| Error::Format(format!("Could not get ELF section data: {e}")))?;
    if chdr.is_some() {
        return Err(Error::Format(format!(
            "Compressed BTF sections are not supported ({})",
            path.as_ref().display()
        )));
    }

    Ok(btf.to_vec())
}

/// Given a directory containing a `vmlinux` ELF file in its root and optional
/// `*.ko` ELF modules in the root or any sub-directory (this maps well to a
/// Linux build directory or `/usr/lib/modules/`), initialize a
/// [`BtfCollection`] extracting BTF data from the .BTF ELF section of those
/// files.
pub fn collection_from_kernel_dir<P: AsRef<Path>>(path: P) -> Result<BtfCollection> {
    let path = path.as_ref();
    if !path.is_dir() {
        return Err(Error::Format(format!(
            "Can't initialize a BTF collection from {}: not a directory",
            path.display()
        )));
    }

    // Find the base BTF file and initialize the collection.
    let vmlinux = path.join("vmlinux");
    let mut collection = BtfCollection::from_bytes("vmlinux", &extract_btf_from_file(vmlinux)?)?;

    // Traverse the directory looking for modules.
    fn visit_dir<P: AsRef<Path>>(dir: P, collection: &mut BtfCollection) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let filename = path
                .file_name()
                .ok_or_else(|| Error::Format("Could not get module file name".to_string()))?
                .to_str()
                .ok_or_else(|| Error::Format("Could not convert module name to str".to_string()))?;

            if path.is_dir() {
                visit_dir(path, collection)?;
            } else if is_module_ext(filename) {
                collection.add_split_btf_from_bytes(
                    match filename.split_once('.') {
                        Some((name, _)) => name,
                        // Should not happen as we already filtered on extensions.
                        None => return Err(Error::Format("Invalid module file name".to_string())),
                    },
                    &extract_btf_from_file(&path)?,
                )?;
            }
        }
        Ok(())
    }
    visit_dir(path, &mut collection)?;

    Ok(collection)
}

// Check if a file is a Linux kernel module looking at its extension.
fn is_module_ext(filename: &str) -> bool {
    #[cfg(feature = "elf-compression")]
    if compression::is_compressed_module_ext(filename) {
        return true;
    }

    filename.ends_with(".ko")
}

#[cfg(feature = "elf-compression")]
mod compression {
    use std::{fmt, io};

    use crate::{Error, Result};

    enum CompressionAlg {
        Bzip2,
        Gzip,
        Lz4,
        Lzma,
        Lzop,
        Xz,
        Zstd,
    }

    impl CompressionAlg {
        fn try_from_magic(bytes: &[u8]) -> Option<Self> {
            Some(match bytes {
                x if x.len() >= 3 && x[..3] == [0x42, 0x5a, 0x68] => Self::Bzip2,
                x if x.len() >= 3 && x[..3] == [0x1f, 0x8b, 0x08] => Self::Gzip,
                x if x.len() >= 4 && x[..4] == [0x02, 0x21, 0x4c, 0x18] => Self::Lz4,
                x if x.len() >= 4 && x[..4] == [0x5d, 0x00, 0x00, 0x00] => Self::Lzma,
                x if x.len() >= 3 && x[..3] == [0x89, 0x4c, 0x5a] => Self::Lzop,
                x if x.len() >= 6 && x[..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] => Self::Xz,
                x if x.len() >= 4 && x[..4] == [0x28, 0xb5, 0x2f, 0xfd] => Self::Zstd,
                _ => return None,
            })
        }
    }

    impl fmt::Display for CompressionAlg {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{}",
                match self {
                    Self::Bzip2 => "bzip2",
                    Self::Gzip => "gzip",
                    Self::Lz4 => "lz4",
                    Self::Lzma => "lzma",
                    Self::Lzop => "lzop",
                    Self::Xz => "xz",
                    Self::Zstd => "zstd",
                }
            )
        }
    }

    pub(super) fn is_compressed_module_ext(filename: &str) -> bool {
        filename.ends_with(".ko.gz")
            || filename.ends_with(".ko.xz")
            || filename.ends_with(".ko.zst")
    }

    pub(super) fn try_decompress(file: Vec<u8>) -> Result<Vec<u8>> {
        // The only reliable way of decoding the ELF from a kernel image is just
        // to try and see as the format is quite complex[1]. See
        // `extract-vmlinux`. This should work with regular compressed files too.
        //
        // [1] https://www.kernel.org/doc/html/latest/arch/x86/boot.html#memory-layout
        for i in 0..file.len() {
            let input = &file[i..];
            if let Some(alg) = CompressionAlg::try_from_magic(input) {
                let mut output = Vec::new();
                match alg {
                    CompressionAlg::Bzip2 => {
                        let mut dec = bzip2::read::BzDecoder::new(input);
                        if io::copy(&mut dec, &mut output).is_err() {
                            continue;
                        }
                    }
                    CompressionAlg::Gzip => {
                        let mut dec = flate2::read::GzDecoder::new(input);
                        if io::copy(&mut dec, &mut output).is_err() {
                            continue;
                        }
                    }
                    CompressionAlg::Xz => {
                        if liblzma::copy_decode(input, &mut output).is_err() {
                            continue;
                        }
                    }
                    CompressionAlg::Zstd => {
                        let mut dec = match zstd::stream::Decoder::new(input) {
                            Ok(dec) => dec.single_frame(),
                            Err(_) => continue,
                        };
                        if io::copy(&mut dec, &mut output).is_err() {
                            continue;
                        }
                    }
                    // We do not support lzma, lz4 & lzop.
                    CompressionAlg::Lzma | CompressionAlg::Lz4 | CompressionAlg::Lzop => {
                        continue;
                    }
                }

                if output.len() < 4 || output[..4] != [0x7f, b'E', b'L', b'F'] {
                    continue;
                }

                return Ok(output);
            }
        }

        // No valid compression header found.
        Err(Error::OpNotSupp(
            "Could not decompress ELF data".to_string(),
        ))
    }
}
