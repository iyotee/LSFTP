use clap::Parser;
use lsftp_core::{TransportConfig, QuicServerTransport, Result, Message, MessageType, protocol::{Frame, FileOpenPayload, FileDataPayload, FileClosePayload, MessagePayload}};
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use blake3::Hasher;
use tracing::{info, warn, error};

/// LSFTP Server - Secure File Transfer Protocol
#[derive(Parser)]
#[command(name = "lsftp-server")]
#[command(about = "LSFTP server for secure file transfer")]
#[command(version)]
pub struct Cli {
    /// Configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Server address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub address: String,

    /// Server port
    #[arg(short, long, default_value = "8443")]
    pub port: u16,

    /// Certificate path
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Private key path
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Root directory for file storage
    #[arg(long, default_value = "/var/lsftp")]
    pub root_dir: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Maximum file size in bytes
    #[arg(long, default_value = "1073741824")] // 1GB
    pub max_file_size: u64,

    /// Enable hardware authentication
    #[arg(long)]
    pub require_hardware_auth: bool,
}

/// File transfer session
#[derive(Debug)]
struct FileSession {
    file_id: Uuid,
    file_path: String,
    file_size: u64,
    chunks_received: u32,
    total_bytes: u64,
    hasher: Hasher,
    file_handle: Option<File>,
}

impl FileSession {
    fn new(file_id: Uuid, file_path: String, file_size: u64) -> Self {
        Self {
            file_id,
            file_path,
            file_size,
            chunks_received: 0,
            total_bytes: 0,
            hasher: Hasher::new(),
            file_handle: None,
        }
    }
}

/// LSFTP Server implementation
struct LsftpServer {
    config: TransportConfig,
    server: QuicServerTransport,
    file_sessions: Arc<RwLock<HashMap<Uuid, FileSession>>>,
    cli: Cli,
}

impl LsftpServer {
    /// Create new server
    fn new(cli: Cli) -> Result<Self> {
        let config = TransportConfig {
            server_address: cli.address.clone(),
            server_port: cli.port,
            cert_path: cli.cert.as_ref().map(|p| p.to_string_lossy().to_string()),
            key_path: cli.key.as_ref().map(|p| p.to_string_lossy().to_string()),
            ..Default::default()
        };

        let server = QuicServerTransport::new(config)?;

        Ok(Self {
            config,
            server,
            file_sessions: Arc::new(RwLock::new(HashMap::new())),
            cli,
        })
    }

    /// Start server
    async fn start(&mut self) -> Result<()> {
        // Create root directory if it doesn't exist
        tokio::fs::create_dir_all(&self.cli.root_dir).await
            .map_err(|e| lsftp_core::error::Error::Config(format!("Failed to create root directory: {}", e)))?;

        info!("Starting LSFTP server on {}:{}", self.cli.address, self.cli.port);
        info!("Root directory: {:?}", self.cli.root_dir);
        info!("Max file size: {} bytes", self.cli.max_file_size);

        // Start QUIC server
        self.server.start().await?;
        info!("LSFTP server started successfully");

        // Main server loop
        loop {
            match self.server.accept_connection().await {
                Ok(session_id) => {
                    info!("New connection accepted: {}", session_id);
                    
                    // Handle session in separate task
                    let server_clone = self.server.clone();
                    let file_sessions = self.file_sessions.clone();
                    let cli = self.cli.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_session(server_clone, session_id, file_sessions, cli).await {
                            error!("Session {} error: {}", session_id, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Failed to accept connection: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handle client session
    async fn handle_session(
        mut server: QuicServerTransport,
        session_id: Uuid,
        file_sessions: Arc<RwLock<HashMap<Uuid, FileSession>>>,
        cli: Cli,
    ) -> Result<()> {
        info!("Handling session: {}", session_id);

        loop {
            // Receive message from client
            let message = server.receive_message().await?;
            
            match message.payload {
                Some(MessagePayload::FileOpen(payload)) => {
                    Self::handle_file_open(&server, session_id, payload, &file_sessions, &cli).await?;
                }
                Some(MessagePayload::FileData(payload)) => {
                    Self::handle_file_data(&server, session_id, payload, &file_sessions, &cli).await?;
                }
                Some(MessagePayload::FileClose(payload)) => {
                    Self::handle_file_close(&server, session_id, payload, &file_sessions, &cli).await?;
                }
                _ => {
                    warn!("Unknown message type: {:?}", message.frame.message_type);
                }
            }
        }
    }

    /// Handle file open request
    async fn handle_file_open(
        server: &QuicServerTransport,
        session_id: Uuid,
        payload: FileOpenPayload,
        file_sessions: &Arc<RwLock<HashMap<Uuid, FileSession>>>,
        cli: &Cli,
    ) -> Result<()> {
        info!("File open request: {} ({} bytes)", payload.path, payload.size);

        // Validate file size
        if payload.size > cli.max_file_size {
            let error_msg = format!("File size {} exceeds maximum allowed size {}", 
                payload.size, cli.max_file_size);
            error!("{}", error_msg);
            return Err(lsftp_core::error::Error::File(error_msg));
        }

        // Create file path
        let file_path = cli.root_dir.join(&payload.path);
        
        // Ensure path is within root directory (security check)
        if !file_path.starts_with(&cli.root_dir) {
            return Err(lsftp_core::error::Error::File("Path traversal attack detected".to_string()));
        }

        // Create parent directories
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| lsftp_core::error::Error::File(format!("Failed to create directory: {}", e)))?;
        }

        // Create file session
        let file_session = FileSession::new(
            Uuid::new_v4(),
            payload.path.clone(),
            payload.size,
        );

        // Store file session
        let mut sessions = file_sessions.write().await;
        sessions.insert(file_session.file_id, file_session);

        info!("File session created: {} for {}", file_session.file_id, payload.path);

        // Send acknowledgment
        let ack_message = Message::new(MessageType::FileOpen, Some(
            MessagePayload::FileOpen(FileOpenPayload {
                path: payload.path,
                size: payload.size,
                hash: [0u8; 32],
                permissions: payload.permissions,
                metadata: payload.metadata,
            })
        ))?;

        server.send_to_session(session_id, ack_message).await?;

        Ok(())
    }

    /// Handle file data
    async fn handle_file_data(
        server: &QuicServerTransport,
        session_id: Uuid,
        payload: FileDataPayload,
        file_sessions: &Arc<RwLock<HashMap<Uuid, FileSession>>>,
        cli: &Cli,
    ) -> Result<()> {
        let mut sessions = file_sessions.write().await;
        
        let file_session = sessions.get_mut(&payload.file_id)
            .ok_or_else(|| lsftp_core::error::Error::File("File session not found".to_string()))?;

        // Open file if not already open
        if file_session.file_handle.is_none() {
            let file_path = cli.root_dir.join(&file_session.file_path);
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(&file_path).await
                .map_err(|e| lsftp_core::error::Error::File(format!("Failed to open file: {}", e)))?;
            
            file_session.file_handle = Some(file);
        }

        // Write chunk to file
        if let Some(file) = &mut file_session.file_handle {
            file.write_all(&payload.data).await
                .map_err(|e| lsftp_core::error::Error::File(format!("Failed to write file: {}", e)))?;
        }

        // Update session statistics
        file_session.chunks_received += 1;
        file_session.total_bytes += payload.data.len() as u64;
        file_session.hasher.update(&payload.data);

        if cli.verbose && file_session.chunks_received % 10 == 0 {
            info!("File {}: {} chunks, {} bytes", 
                file_session.file_path, file_session.chunks_received, file_session.total_bytes);
        }

        // Send acknowledgment
        let ack_message = Message::new(MessageType::FileData, Some(
            MessagePayload::FileData(FileDataPayload {
                file_id: payload.file_id,
                chunk_index: payload.chunk_index,
                data: vec![], // Empty for acknowledgment
                chunk_hash: payload.chunk_hash,
                chunk_signature: vec![], // Will be signed
            })
        ))?;

        server.send_to_session(session_id, ack_message).await?;

        Ok(())
    }

    /// Handle file close
    async fn handle_file_close(
        server: &QuicServerTransport,
        session_id: Uuid,
        payload: FileClosePayload,
        file_sessions: &Arc<RwLock<HashMap<Uuid, FileSession>>>,
        cli: &Cli,
    ) -> Result<()> {
        let mut sessions = file_sessions.write().await;
        
        let file_session = sessions.remove(&payload.file_id)
            .ok_or_else(|| lsftp_core::error::Error::File("File session not found".to_string()))?;

        // Close file handle
        if let Some(mut file) = file_session.file_handle {
            file.flush().await
                .map_err(|e| lsftp_core::error::Error::File(format!("Failed to flush file: {}", e)))?;
        }

        // Verify final hash
        let final_hash = file_session.hasher.finalize();
        if final_hash.as_bytes() != &payload.final_hash {
            return Err(lsftp_core::error::Error::File("File integrity check failed".to_string()));
        }

        info!("File transfer completed: {} ({} bytes, {} chunks)", 
            file_session.file_path, file_session.total_bytes, file_session.chunks_received);

        // Send final acknowledgment
        let final_message = Message::new(MessageType::FileClose, Some(
            MessagePayload::FileClose(FileClosePayload {
                file_id: payload.file_id,
                final_hash: payload.final_hash,
                global_signature: vec![], // Will be signed
                statistics: lsftp_core::protocol::TransferStatistics {
                    bytes_transferred: file_session.total_bytes,
                    duration_ms: 0, // Will be calculated
                    throughput_bps: 0, // Will be calculated
                    chunks_count: file_session.chunks_received,
                    retries_count: 0,
                },
            })
        ))?;

        server.send_to_session(session_id, final_message).await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("lsftp_server=debug")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter("lsftp_server=info")
            .init();
    }

    info!("LSFTP Server starting...");
    info!("Version: 1.0");
    info!("Author: Jérémy Noverraz - 1988");

    // Create and start server
    let mut server = LsftpServer::new(cli)?;
    server.start().await?;

    Ok(())
}
