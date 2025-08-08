use thiserror;

pub type Result<T> = std::result::Result<T, Error>;

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// I/O error, from `std::io::Error`.
    #[error("i/o error: {0}")]
    IO(#[from] std::io::Error),
    /// Format error: invalid input file or directory, wrongly formatted file,
    /// invalid BTF format.
    #[error("{0}")]
    Format(String),
    /// Operation not supported.
    #[error("operation not supported: {0}")]
    OpNotSupp(String),
    /// Invalid type.
    #[error("no type with id {0}")]
    InvalidType(u32),
    /// Invalid string reference.
    #[error("no string at offset {0}")]
    InvalidString(u32),
}
