//! # Collection of one base BTF and its split BTF (e.g. full system)
//!
//! The [`BtfCollection`] object is provided to allow parsing a collection of
//! one base BTF and 0 or more split BTFs. For example, it can be used to
//! describe a kernel and all its modules.
//!
//! ```no_run
//! use btf_rs::utils::collection::BtfCollection;
//!
//! let btfc_sys = BtfCollection::from_dir("/sys/kernel/btf", "vmlinux").unwrap();
//!
//! let mut btfc = BtfCollection::from_file("/sys/kernel/btf/vmlinux").unwrap();
//! btfc.add_split_btf_from_file("/sys/kernel/btf/openvswitch").unwrap();
//! btfc.add_split_btf_from_file("/sys/kernel/btf/nf_tables").unwrap();
//! ```
//!
//! [`BtfCollection`] also supports being constructed from byte slices.
//!
//! Due to how split BTF are constructed, [`BtfCollection`] does not provide
//! helpers returning a single match but instead return lists of matches
//! containing a [`NamedBtf`] reference. This new [`NamedBtf`] type embed
//! both the [`crate::Btf`] representation and a name to uniquely identify it.
//! Subsequent lookups for the type or id returned must be done using the
//! [`crate::Btf`] representation returned in the [`NamedBtf`] reference. See
//! [`BtfCollection::resolve_ids_by_name`] and
//! [`BtfCollection::resolve_types_by_name`].
use std::{fs, ops::Deref, path::Path};

use crate::{Backend, Btf, Error, Result, Type};

/// BtfCollection provides a full system BTF view, by combining a base BTF
/// information with multiple split BTFs.
///
/// Provides resolve by name helpers (looking up by id cannot work as ids are
/// reused in different split BTF), which behave similarly to the ones in
/// [`Btf`] but returning an additional named reference to the [`Btf`] object
/// where the resolution was done. This is important as further lookups for the
/// returned value must be done using the [`Btf`] object returned.
///
/// The base BTF lookups are prioritized over the split BTF ones.
pub struct BtfCollection {
    /// Main BTF object for the kernel.
    base: NamedBtf,
    /// Split BTF information.
    split: Vec<NamedBtf>,
}

/// Struct embedding a [`Btf`] object alongside a name to uniquely identify it.
/// Used to manipulate [`Btf`] objects when there could be multiple matches.
pub struct NamedBtf {
    /// Name of the [`Btf`] object.
    pub name: String,
    /// The [`Btf`] object.
    pub btf: Btf,
}

/// Allow dereferencing [`NamedBtf`] into [`Btf`] for ease of use.
impl Deref for NamedBtf {
    type Target = Btf;

    fn deref(&self) -> &Self::Target {
        &self.btf
    }
}

impl BtfCollection {
    /// Construct a [`BtfCollection`] object from a base BTF file only. See
    /// [`Btf::from_file`] for documentation on which [`Backend`] is used by
    /// default.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<BtfCollection> {
        Ok(BtfCollection {
            base: NamedBtf {
                name: Self::file_name(path.as_ref())?,
                btf: Btf::from_file(path)?,
            },
            split: Vec::new(),
        })
    }

    /// Same as [`BtfCollection::from_file`] but forcing a given [`Backend`] to
    /// be used. This allows selecting the desired behavior and balance, but can
    /// fail if a given [`Backend`] isn't supported by the underlying system.
    pub fn from_file_with_backend<P: AsRef<Path>>(
        path: P,
        backend: Backend,
    ) -> Result<BtfCollection> {
        Ok(BtfCollection {
            base: NamedBtf {
                name: Self::file_name(path.as_ref())?,
                btf: Btf::from_file_with_backend(path, backend)?,
            },
            split: Vec::new(),
        })
    }

    /// Construct a [`BtfCollection`] object from a base BTF file only.
    pub fn from_bytes(name: &str, bytes: &[u8]) -> Result<BtfCollection> {
        Ok(BtfCollection {
            base: NamedBtf {
                name: name.to_string(),
                btf: Btf::from_bytes(bytes)?,
            },
            split: Vec::new(),
        })
    }

    /// Add a split BTF in the current [`BtfCollection`] representation, reading
    /// a file.
    pub fn add_split_btf_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<&mut Self> {
        let name = Self::file_name(path.as_ref())?;

        if self.split.iter().any(|m| m.name == name) {
            return Err(Error::Format(format!(
                "Split BTF with name {name} already present"
            )));
        }

        self.split.push(NamedBtf {
            name,
            btf: Btf::from_split_file(path, &self.base.btf)?,
        });
        Ok(self)
    }

    /// Add a split BTF in the current [`BtfCollection`] representation, reading
    /// a byte slice.
    pub fn add_split_btf_from_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<&mut Self> {
        let name = name.to_string();
        if self.split.iter().any(|m| m.name == name) {
            return Err(Error::Format(format!(
                "Split BTF with name {name} already present"
            )));
        }

        self.split.push(NamedBtf {
            name,
            btf: Btf::from_split_bytes(bytes, &self.base.btf)?,
        });
        Ok(self)
    }

    /// Parse BTF objects stored in a directory and construct a
    /// [`BtfCollection`] object, given a path to the directory and the filename
    /// of the base BTF file. This is helpful for parsing `/sys/kernel/btf`
    /// files.
    pub fn from_dir<P: AsRef<Path>>(dir: P, base: &str) -> Result<BtfCollection> {
        let mut sys_btf = BtfCollection::from_file(format!("{}/{base}", dir.as_ref().display()))?;
        sys_btf.add_split_from_dir(dir, base)?;
        Ok(sys_btf)
    }

    /// Same as [`BtfCollection::from_dir`] but forcing a given [`Backend`] to
    /// be used. This allows selecting the desired behavior and balance, but can
    /// fail if a given [`Backend`] isn't supported by the underlying system.
    pub fn from_dir_with_backend<P: AsRef<Path>>(
        dir: P,
        base: &str,
        backend: Backend,
    ) -> Result<BtfCollection> {
        let mut sys_btf =
            Self::from_file_with_backend(format!("{}/{base}", dir.as_ref().display()), backend)?;
        sys_btf.add_split_from_dir(dir, base)?;
        Ok(sys_btf)
    }

    fn add_split_from_dir<P: AsRef<Path>>(&mut self, dir: P, base: &str) -> Result<()> {
        for file in fs::read_dir(dir.as_ref())? {
            match file {
                Ok(file) => {
                    if file.file_name() == base {
                        continue;
                    }
                    if let Ok(ft) = file.file_type() {
                        if !ft.is_dir() {
                            self.add_split_btf_from_file(file.path())?;
                        }
                    }
                }
                Err(e) => return Err(Error::IO(e)),
            }
        }
        Ok(())
    }

    /// Get a reference to a [`NamedBtf`] given a module name. This [`NamedBtf`]
    /// can then be used to perform scoped lookups.
    pub fn get_named_btf(&self, name: &str) -> Option<&NamedBtf> {
        self.split.iter().find(|m| m.name == name)
    }

    /// Find a list of BTF ids with a given name.
    ///
    /// Matching ids can be found in multiple underlying BTF, thus this function
    /// returns a list of tuples containing each a reference to [`NamedBtf`]
    /// (representing the BTF where a match was found) and the id. Further
    /// lookups must be done using the [`Btf`] object contained in the linked
    /// [`NamedBtf`] one.
    pub fn resolve_ids_by_name(&self, name: &str) -> Result<Vec<(&NamedBtf, u32)>> {
        let mut ids = self
            .base
            .btf
            .resolve_ids_by_name(name)?
            .drain(..)
            .map(|i| (&self.base, i))
            .collect::<Vec<_>>();

        for btf in self.split.iter() {
            if let Some(split) = btf.split() {
                split
                    .resolve_ids_by_name(name)?
                    .drain(..)
                    .for_each(|i| ids.push((btf, i)));
            }
        }

        Ok(ids)
    }

    /// Find a list of BTF ids whose names match a regex.
    ///
    /// Matching ids can be found in multiple underlying BTF, thus this function
    /// returns a list of tuples containing each a reference to [`NamedBtf`]
    /// (representing the BTF where a match was found) and the id. Further
    /// lookups must be done using the [`Btf`] object contained in the linked
    /// [`NamedBtf`] one.
    #[cfg(feature = "regex")]
    pub fn resolve_ids_by_regex(&self, re: &regex::Regex) -> Result<Vec<(&NamedBtf, u32)>> {
        let mut ids = self
            .base
            .btf
            .resolve_ids_by_regex(re)?
            .drain(..)
            .map(|i| (&self.base, i))
            .collect::<Vec<_>>();

        for btf in self.split.iter() {
            if let Some(split) = btf.split() {
                split
                    .resolve_ids_by_regex(re)?
                    .drain(..)
                    .for_each(|i| ids.push((btf, i)));
            }
        }

        Ok(ids)
    }

    /// Find a list of BTF types with a given name.
    ///
    /// Matching types can be found in multiple underlying BTF, thus this
    /// function returns a list of tuples containing each a reference to
    /// [`NamedBtf`] (representing the BTF where a match was found) and the
    /// type. Further lookups must be done using the [`Btf`] object contained in
    /// the linked [`NamedBtf`] one.
    pub fn resolve_types_by_name(&self, name: &str) -> Result<Vec<(&NamedBtf, Type)>> {
        let mut types = self
            .base
            .btf
            .resolve_types_by_name(name)?
            .drain(..)
            .map(|t| (&self.base, t))
            .collect::<Vec<_>>();

        for btf in self.split.iter() {
            if let Some(split) = btf.split() {
                split
                    .resolve_types_by_name(name)?
                    .drain(..)
                    .for_each(|t| types.push((btf, t)));
            }
        }

        Ok(types)
    }

    /// Find a list of BTF types whose names match a regex.
    ///
    /// Matching types can be found in multiple underlying BTF, thus this
    /// function returns a list of tuples containing each a reference to
    /// [`NamedBtf`] (representing the BTF where a match was found) and the
    /// type. Further lookups must be done using the `Btf` object contained in
    /// the linked [`NamedBtf`] one.
    #[cfg(feature = "regex")]
    pub fn resolve_types_by_regex(&self, re: &regex::Regex) -> Result<Vec<(&NamedBtf, Type)>> {
        let mut types = self
            .base
            .btf
            .resolve_types_by_regex(re)?
            .drain(..)
            .map(|t| (&self.base, t))
            .collect::<Vec<_>>();

        for btf in self.split.iter() {
            if let Some(split) = btf.split() {
                split
                    .resolve_types_by_regex(re)?
                    .drain(..)
                    .for_each(|t| types.push((btf, t)));
            }
        }

        Ok(types)
    }

    // Internal helper to extract a file name as a String from a Path.
    fn file_name(path: &Path) -> Result<String> {
        Ok(match path.file_name() {
            Some(name) => match name.to_str() {
                Some(s) => s.to_string(),
                None => return Err(Error::Format(format!("Invalid file name {name:?}"))),
            },
            None => {
                return Err(Error::Format(format!(
                    "Could not get file name from path {}",
                    path.display()
                )))
            }
        })
    }
}
