//! LSFTP Core - Secure File Transfer Protocol with Post-Quantum Cryptography
//! 
//! This module provides the core implementation of the LSFTP protocol,
//! including cryptographic primitives, hardware authentication, and
//! the wire protocol implementation.

pub mod crypto;
pub mod protocol;
pub mod auth;
pub mod transport;
pub mod audit;
pub mod error;

// Re-export commonly used types
pub use error::{Error, Result};
pub use protocol::{Message, MessageType, Frame};
pub use auth::{HardwareAuth, AuthResult, HardwareType};
pub use crypto::{CryptoSuite, KeyExchange, Signature};
pub use transport::{TransportConfig, QuicTransport, QuicServerTransport};
pub use audit::{AuditEvent, AuditLogger, SecurityLogger};

/// LSFTP Protocol Version
pub const PROTOCOL_VERSION: u8 = 1;

/// Default chunk size for file transfers (1MB)
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Default QUIC port for LSFTP
pub const DEFAULT_PORT: u16 = 8443;

/// Maximum file size supported (100GB)
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Session timeout in seconds
pub const SESSION_TIMEOUT_SECS: u64 = 3600;

/// Key rotation interval in seconds
pub const KEY_ROTATION_INTERVAL_SECS: u64 = 300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(DEFAULT_CHUNK_SIZE, 1024 * 1024);
        assert_eq!(DEFAULT_PORT, 8443);
        assert_eq!(MAX_FILE_SIZE, 100 * 1024 * 1024 * 1024);
    }
}
