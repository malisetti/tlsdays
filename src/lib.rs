#![forbid(unsafe_code)]

pub mod check;
pub mod error;
pub mod output;

pub use check::{check_host, CertInfo, HostTarget};
pub use error::TlsdaysError;
pub use output::{FormatKind, Formatter, HostRecord, JsonlFormatter, TableFormatter, TextFormatter};
