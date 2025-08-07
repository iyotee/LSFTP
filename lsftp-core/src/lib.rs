//! LSFTP Core - Linux Secure File Transfer Protocol with Post-Quantum Cryptography
//! 
//! This module provides the core implementation of the LSFTP protocol,
//! including cryptographic primitives, hardware authentication, and
//! the wire protocol implementation for Linux systems only.

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

/// LSFTP Protocol Version (V1.0 as specified)
pub const PROTOCOL_VERSION: u8 = 1;

/// Default chunk size for file transfers (1MB as per specification)
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Default QUIC port for LSFTP (8443 as specified)
pub const DEFAULT_PORT: u16 = 8443;

/// Maximum file size supported (100GB as per specification)
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Session timeout in seconds (1 hour as per specification)
pub const SESSION_TIMEOUT_SECS: u64 = 3600;

/// Key rotation interval in seconds (5 minutes for perfect forward secrecy)
pub const KEY_ROTATION_INTERVAL_SECS: u64 = 300;

/// Hardware authentication timeout in seconds
pub const HARDWARE_AUTH_TIMEOUT_SECS: u64 = 30;

/// Maximum concurrent connections per server
pub const MAX_CONCURRENT_CONNECTIONS: u32 = 1000;

/// Maximum file transfer rate in bytes per second (10Gbps)
pub const MAX_TRANSFER_RATE: u64 = 10 * 1024 * 1024 * 1024;

/// Audit log retention period in days
pub const AUDIT_LOG_RETENTION_DAYS: u32 = 2555; // 7 years

/// TPM device path for Linux systems
pub const TPM_DEVICE_PATH: &str = "/dev/tpmrm0";

/// YubiKey device path pattern
pub const YUBIKEY_DEVICE_PATTERN: &str = "/dev/hidraw*";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(DEFAULT_CHUNK_SIZE, 1024 * 1024);
        assert_eq!(DEFAULT_PORT, 8443);
        assert_eq!(MAX_FILE_SIZE, 100 * 1024 * 1024 * 1024);
        assert_eq!(SESSION_TIMEOUT_SECS, 3600);
        assert_eq!(KEY_ROTATION_INTERVAL_SECS, 300);
    }

    #[test]
    fn test_linux_specific_constants() {
        assert_eq!(TPM_DEVICE_PATH, "/dev/tpmrm0");
        assert_eq!(YUBIKEY_DEVICE_PATTERN, "/dev/hidraw*");
        assert_eq!(MAX_CONCURRENT_CONNECTIONS, 1000);
        assert_eq!(MAX_TRANSFER_RATE, 10 * 1024 * 1024 * 1024);
    }
}
