use scroll;
use core::fmt;
use std::error;
use goblin;

#[derive(Debug)]
/// A custom error
pub enum Error {
    /// No Optional Header in PE
    OptionalHeader,
    /// No Data Directories in PE
    DataDir,
    /// Error finding offset
    Offset(usize),
    /// An error emanating from reading and interpreting bytes
    Scroll(scroll::Error),
    /// Goblin error
    Goblin(goblin::error::Error),
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Scroll(ref scroll) => Some(scroll),
            Error::Goblin(ref goblin) => Some(goblin),
            Error::Offset(_) => None,
            Error::DataDir => None,
            Error::OptionalHeader => None,
        }
    }
}

impl From<scroll::Error> for Error {
    fn from(err: scroll::Error) -> Error {
        Error::Scroll(err)
    }
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Error {
        Error::Goblin(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Scroll(ref err) => write!(fmt, "{}", err),
            Error::Goblin(ref err) => write!(fmt, "{}", err),
            Error::Offset(rva) => write!(fmt, "Error finding offset at: {}", rva),
            Error::DataDir => write!(fmt, "No Data Directories"),
            Error::OptionalHeader => write!(fmt, "No Optional Header in PE"),
        }
    }
}