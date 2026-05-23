use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsdaysError {
    #[error("failed to resolve host {host}: {source}")]
    Resolve {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error("tcp connection to {host}:{port} failed: {source}")]
    Tcp {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },

    #[error("tls handshake with {host}:{port} failed: {message}")]
    Tls {
        host: String,
        port: u16,
        message: String,
    },

    #[error("failed to parse certificate from {host}:{port}: {message}")]
    CertParse {
        host: String,
        port: u16,
        message: String,
    },

    #[error("invalid argument: {0}")]
    Argument(String),
}
