use std::{
    fs::{self, File},
    path::Path,
};

use elf::{endian::AnyEndian, ElfStream};

use crate::{utils::collection::BtfCollection, Error, Result};

/// Extract raw BTF data from the .BTF elf section of the given file. Output can
/// be used to fed `from_bytes` constructors in this library.
pub fn extract_btf_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let file = File::open(&path)?;
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(file)
        .map_err(|e| Error::Format(format!("Could not parse ELF file: {e}")))?;

    let btf_hdr = match elf
        .section_header_by_name(".BTF")
        .map_err(|e| Error::Format(format!("Could not get ELF section header for .BTF: {e}")))?
    {
        Some(hdr) => *hdr,
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

/// Given a directory containing a 'vmlinux' ELF file in its root and optional
/// '*.ko' ELF modules in the root or any sub-directory (this maps well to a
/// Linux build directory or /usr/lib/modules/), initialize a BtfCollection
/// extracting BTF data from the .BTF section of those files.
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
            } else if filename.ends_with(".ko") {
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
