use std::{
    fs::{self, File},
    path::Path,
};

use anyhow::{anyhow, bail, Result};
use elf::{endian::AnyEndian, ElfStream};

/// Extract raw BTF data from the .BTF elf section of the given file. Output can
/// be used to fed `from_bytes` constructors in this library.
pub fn extract_btf_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let file = File::open(&path)
        .map_err(|e| anyhow!("Could not open {}: {e}", path.as_ref().display()))?;
    let mut elf = ElfStream::<AnyEndian, _>::open_stream(file)?;

    let btf_hdr = match elf.section_header_by_name(".BTF")? {
        Some(hdr) => *hdr,
        None => bail!("No BTF section in {}", path.as_ref().display()),
    };

    let (btf, chdr) = elf.section_data(&btf_hdr)?;
    if chdr.is_some() {
        bail!(
            "Compressed BTF sections are not supported ({})",
            path.as_ref().display()
        );
    }

    Ok(btf.to_vec())
}
