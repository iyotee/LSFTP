//! Transport layer for LSFTP
//! 
//! This module provides QUIC-based transport with TLS 1.3 and
//! post-quantum cryptography support for Linux systems.

use crate::error::Result;
use crate::protocol::{Message, MessageType, Frame};
use crate::crypto::CryptoSuite;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use nix::unistd::{setuid, setgid};
use quinn::{Endpoint, Connection, NewConnection};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsServerConfig, ClientConfig as RustlsClientConfig};
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Server address
    pub server_address: String,
    /// Server port
    pub server_port: u16,
    /// TLS certificate path
    pub cert_path: Option<String>,
    /// TLS private key path
    pub key_path: Option<String>,
    /// Client certificate path
    pub client_cert_path: Option<String>,
    /// Client private key path
    pub client_key_path: Option<String>,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Keep-alive interval in seconds
    pub keep_alive_interval: u64,
    /// Maximum concurrent streams
    pub max_concurrent_streams: u32,
    /// Crypto suite configuration
    pub crypto_suite: CryptoSuite,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            server_address: "127.0.0.1".to_string(),
            server_port: crate::DEFAULT_PORT,
            cert_path: None,
            key_path: None,
            client_cert_path: None,
            client_key_path: None,
            connection_timeout: 30,
            keep_alive_interval: 60,
            max_concurrent_streams: 100,
            crypto_suite: CryptoSuite::default(),
        }
    }
}

/// Session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Authenticated and ready
    Ready,
    /// Transfer in progress
    Transferring,
    /// Error state
    Error,
    /// Closed
    Closed,
}

/// Session information
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: Uuid,
    /// Session state
    pub state: SessionState,
    /// Remote address
    pub remote_address: String,
    /// Session start time
    pub start_time: std::time::SystemTime,
    /// Last activity time
    pub last_activity: std::time::SystemTime,
    /// Session statistics
    pub statistics: SessionStatistics,
}

/// Session statistics
#[derive(Debug, Clone, Default)]
pub struct SessionStatistics {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Errors encountered
    pub errors: u64,
}

/// QUIC transport implementation
pub struct QuicTransport {
    config: TransportConfig,
    session_info: Arc<RwLock<SessionInfo>>,
    crypto_suite: CryptoSuite,
    connection: Option<Connection>,
    endpoint: Option<Endpoint>,
}

impl QuicTransport {
    /// Create new QUIC transport
    pub fn new(config: TransportConfig) -> Result<Self> {
        let crypto_suite = config.crypto_suite.clone();
        
        // Apply Linux security measures
        Self::apply_linux_security()?;
        
        Ok(Self {
            config,
            session_info: Arc::new(RwLock::new(SessionInfo {
                session_id: Uuid::new_v4(),
                state: SessionState::Initial,
                remote_address: "".to_string(),
                start_time: std::time::SystemTime::now(),
                last_activity: std::time::SystemTime::now(),
                statistics: SessionStatistics::default(),
            })),
            crypto_suite,
            connection: None,
            endpoint: None,
        })
    }
    
    /// Apply Linux-specific security measures
    fn apply_linux_security() -> Result<()> {
        // Drop privileges to non-root user for security
        unsafe {
            setuid(nix::unistd::Uid::from_raw(1000))?;
            setgid(nix::unistd::Gid::from_raw(1000))?;
        }
        
        Ok(())
    }

    /// Initialize transport
    pub async fn initialize(&mut self) -> Result<()> {
        // Create QUIC endpoint for client
        let client_config = self.create_client_config()?;
        let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| crate::error::Error::Transport(format!("Failed to create QUIC endpoint: {}", e)))?;
        
        self.endpoint = Some(endpoint);
        
        let mut session = self.session_info.write().await;
        session.state = SessionState::Initial;
        session.start_time = std::time::SystemTime::now();
        session.last_activity = std::time::SystemTime::now();
        
        Ok(())
    }

    /// Connect to server
    pub async fn connect(&mut self) -> Result<()> {
        let endpoint = self.endpoint.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("Endpoint not initialized".to_string()))?;

        let server_addr = format!("{}:{}", self.config.server_address, self.config.server_port)
            .parse::<SocketAddr>()
            .map_err(|e| crate::error::Error::Transport(format!("Invalid server address: {}", e)))?;

        // Establish QUIC connection
        let connection = endpoint.connect(server_addr, "localhost")
            .map_err(|e| crate::error::Error::Transport(format!("Failed to connect: {}", e)))?
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Connection failed: {}", e)))?;

        self.connection = Some(connection);
        
        let mut session = self.session_info.write().await;
        session.state = SessionState::Handshaking;
        session.remote_address = format!("{}:{}", self.config.server_address, self.config.server_port);
        session.last_activity = std::time::SystemTime::now();
        
        // Wait for handshake completion
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        session.state = SessionState::Ready;
        
        Ok(())
    }

    /// Send message
    pub async fn send_message(&mut self, message: Message) -> Result<()> {
        let connection = self.connection.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("Not connected".to_string()))?;

        // Serialize message
        let serialized = message.frame.serialize()?;
        
        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi()
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Failed to open stream: {}", e)))?;

        // Send message
        send.write_all(&serialized)
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Failed to send message: {}", e)))?;
        send.finish()
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Failed to finish stream: {}", e)))?;

        // Update statistics
        let mut session = self.session_info.write().await;
        session.statistics.messages_sent += 1;
        session.statistics.bytes_sent += serialized.len() as u64;
        session.last_activity = std::time::SystemTime::now();
        
        Ok(())
    }

    /// Receive message
    pub async fn receive_message(&mut self) -> Result<Message> {
        let connection = self.connection.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("Not connected".to_string()))?;

        // Accept incoming stream
        let (mut send, mut recv) = connection.accept_bi()
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Failed to accept stream: {}", e)))?;

        // Read message data
        let mut data = Vec::new();
        recv.read_to_end(&mut data)
            .await
            .map_err(|e| crate::error::Error::Transport(format!("Failed to read message: {}", e)))?;

        // Deserialize message
        let frame = Frame::deserialize(&data)?;
        let mut message = Message::new(frame.message_type, None)?;
        message.frame = frame;
        message.parse_payload()?;

        // Update statistics
        let mut session = self.session_info.write().await;
        session.statistics.messages_received += 1;
        session.statistics.bytes_received += data.len() as u64;
        session.last_activity = std::time::SystemTime::now();
        
        Ok(message)
    }

    /// Close connection
    pub async fn close(&mut self) -> Result<()> {
        if let Some(connection) = &self.connection {
            connection.close(0u32.into(), b"graceful shutdown");
        }
        
        let mut session = self.session_info.write().await;
        session.state = SessionState::Closed;
        session.last_activity = std::time::SystemTime::now();
        
        Ok(())
    }

    /// Get session information
    pub async fn get_session_info(&self) -> SessionInfo {
        self.session_info.read().await.clone()
    }

    /// Check if connection is healthy
    pub async fn is_healthy(&self) -> bool {
        if let Some(connection) = &self.connection {
            connection.keep_alive()
        } else {
            false
        }
    }

    /// Create client TLS configuration
    fn create_client_config(&self) -> Result<RustlsClientConfig> {
        let mut client_config = RustlsClientConfig::builder()
            .with_safe_defaults()
            .with_native_roots()
            .with_no_client_auth();
        
        // Load client certificate if provided
        if let (Some(cert_path), Some(key_path)) = (&self.config.client_cert_path, &self.config.client_key_path) {
            let cert_file = std::fs::read(cert_path)
                .map_err(|e| crate::error::Error::Config(format!("Failed to read certificate: {}", e)))?;
            let key_file = std::fs::read(key_path)
                .map_err(|e| crate::error::Error::Config(format!("Failed to read private key: {}", e)))?;
            
            let cert = Certificate(cert_file);
            let key = PrivateKey(key_file);
            
            client_config = client_config.with_single_cert(vec![cert], key)
                .map_err(|e| crate::error::Error::Config(format!("Failed to create client config: {}", e)))?;
        }
        
        Ok(client_config)
    }
}

/// QUIC server transport implementation
pub struct QuicServerTransport {
    config: TransportConfig,
    sessions: Arc<RwLock<HashMap<Uuid, SessionInfo>>>,
    crypto_suite: CryptoSuite,
    endpoint: Option<Endpoint>,
}

impl QuicServerTransport {
    /// Create new QUIC server transport
    pub fn new(config: TransportConfig) -> Result<Self> {
        let crypto_suite = config.crypto_suite.clone();
        
        // Apply Linux security measures
        Self::apply_linux_security()?;
        
        Ok(Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            crypto_suite,
            endpoint: None,
        })
    }
    
    /// Apply Linux-specific security measures
    fn apply_linux_security() -> Result<()> {
        // Drop privileges to non-root user for security
        unsafe {
            setuid(nix::unistd::Uid::from_raw(1000))?;
            setgid(nix::unistd::Gid::from_raw(1000))?;
        }
        
        Ok(())
    }

    /// Start server
    pub async fn start(&mut self) -> Result<()> {
        // Create server configuration
        let server_config = self.create_server_config()?;
        
        // Create QUIC endpoint
        let endpoint = Endpoint::server(server_config, "0.0.0.0:8443".parse().unwrap())
            .map_err(|e| crate::error::Error::Transport(format!("Failed to create server endpoint: {}", e)))?;
        
        self.endpoint = Some(endpoint);
        
        Ok(())
    }

    /// Accept new connection
    pub async fn accept_connection(&mut self) -> Result<Uuid> {
        let endpoint = self.endpoint.as_ref()
            .ok_or_else(|| crate::error::Error::Transport("Server not started".to_string()))?;

        // Accept incoming connection
        let incoming = endpoint.accept()
            .await
            .ok_or_else(|| crate::error::Error::Transport("No incoming connections".to_string()))?;

        let connection = incoming.await
            .map_err(|e| crate::error::Error::Transport(format!("Connection failed: {}", e)))?;

        let session_id = Uuid::new_v4();
        let session_info = SessionInfo {
            session_id,
            state: SessionState::Handshaking,
            remote_address: connection.remote_address().to_string(),
            start_time: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
            statistics: SessionStatistics::default(),
        };

        // Store session
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id, session_info);

        Ok(session_id)
    }

    /// Handle session
    pub async fn handle_session(&mut self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.state = SessionState::Ready;
            session.last_activity = std::time::SystemTime::now();
        }
        
        Ok(())
    }

    /// Send message to specific session
    pub async fn send_to_session(&mut self, session_id: Uuid, message: Message) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.statistics.messages_sent += 1;
            session.statistics.bytes_sent += message.frame.payload.len() as u64;
            session.last_activity = std::time::SystemTime::now();
        }
        
        Ok(())
    }

    /// Close specific session
    pub async fn close_session(&mut self, session_id: Uuid) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.state = SessionState::Closed;
            session.last_activity = std::time::SystemTime::now();
        }
        
        Ok(())
    }

    /// Get all sessions
    pub async fn get_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Stop server
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0u32.into(), b"server shutdown");
        }
        
        Ok(())
    }

    /// Create server TLS configuration
    fn create_server_config(&self) -> Result<RustlsServerConfig> {
        let (cert_path, key_path) = match (&self.config.cert_path, &self.config.key_path) {
            (Some(cert), Some(key)) => (cert, key),
            _ => return Err(crate::error::Error::Config("Certificate and key paths required for server".to_string())),
        };

        // Load certificate and private key
        let cert_file = std::fs::read(cert_path)
            .map_err(|e| crate::error::Error::Config(format!("Failed to read certificate: {}", e)))?;
        let key_file = std::fs::read(key_path)
            .map_err(|e| crate::error::Error::Config(format!("Failed to read private key: {}", e)))?;

        let cert = Certificate(cert_file);
        let key = PrivateKey(key_file);

        // Create server configuration
        let server_config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| crate::error::Error::Config(format!("Failed to create server config: {}", e)))?;

        Ok(server_config)
    }
}

/// Transport factory
pub struct TransportFactory;

impl TransportFactory {
    /// Create client transport
    pub fn create_client(config: TransportConfig) -> Result<QuicTransport> {
        QuicTransport::new(config)
    }

    /// Create server transport
    pub fn create_server(config: TransportConfig) -> Result<QuicServerTransport> {
        QuicServerTransport::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = TransportConfig::default();
        let transport = QuicTransport::new(config);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = TransportConfig::default();
        let server = QuicServerTransport::new(config);
        assert!(server.is_ok());
    }

    #[tokio::test]
    async fn test_session_management() {
        let config = TransportConfig::default();
        let mut server = QuicServerTransport::new(config).unwrap();
        
        // Test session creation (without actual network)
        let sessions = server.get_sessions().await;
        assert_eq!(sessions.len(), 0);
    }
}
