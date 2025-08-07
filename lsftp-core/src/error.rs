//! Error types for LSFTP protocol implementation

use thiserror::Error;

/// Result type for LSFTP operations
pub type Result<T> = std::result::Result<T, Error>;

/// LSFTP-specific error types
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Hardware authentication failed
    #[error("Hardware authentication failed: {0}")]
    HardwareAuth(String),

    /// Protocol violation or invalid message
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Network transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// Authentication or authorization error
    #[error("Authentication error: {0}")]
    Auth(String),

    /// File operation error
    #[error("File operation error: {0}")]
    File(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Audit/logging error
    #[error("Audit error: {0}")]
    Audit(String),

    /// System resource error
    #[error("System resource error: {0}")]
    System(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Invalid input or parameter
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Transport(err.to_string())
    }
}

impl From<ring::error::Unspecified> for Error {
    fn from(_err: ring::error::Unspecified) -> Self {
        Error::Crypto("Ring cryptographic error".to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Protocol(format!("Serialization error: {}", err))
    }
}

impl From<postcard::Error> for Error {
    fn from(err: postcard::Error) -> Self {
        Error::Protocol(format!("Serialization error: {}", err))
    }
}

impl From<ring::error::KeyRejected> for Error {
    fn from(err: ring::error::KeyRejected) -> Self {
        Error::Crypto(format!("Key rejected: {}", err))
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::Config(format!("TOML parsing error: {}", err))
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(err: std::time::SystemTimeError) -> Self {
        Error::System(format!("System time error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversions() {
        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test");
        let lsftp_error: Error = io_error.into();
        assert!(matches!(lsftp_error, Error::Transport(_)));

        let json_error = serde_json::from_str::<serde_json::Value>("invalid json");
        let lsftp_error: Error = json_error.unwrap_err().into();
        assert!(matches!(lsftp_error, Error::Protocol(_)));
    }
}
