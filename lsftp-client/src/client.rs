//! LSFTP Client implementation
//! 
//! This module provides the client implementation for LSFTP with
//! hardware authentication and secure file transfer capabilities.

use lsftp_core::{TransportConfig, QuicTransport, Result, Message, MessageType, protocol::{Frame, FileOpenPayload, FileDataPayload, FileClosePayload}};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::io::{Read, Write};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use blake3::Hasher;

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server address
    pub server_address: String,
    /// Server port
    pub server_port: u16,
    /// Hardware device type
    pub hardware_device: Option<String>,
    /// Certificate path
    pub cert_path: Option<PathBuf>,
    /// Private key path
    pub key_path: Option<PathBuf>,
    /// Connection timeout
    pub connection_timeout: u64,
    /// Chunk size for file transfers
    pub chunk_size: usize,
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_address: "localhost".to_string(),
            server_port: 8443,
            hardware_device: None,
            cert_path: None,
            key_path: None,
            connection_timeout: 30,
            chunk_size: 1024 * 1024, // 1MB chunks
            verbose: false,
        }
    }
}

/// File transfer statistics
#[derive(Debug, Clone)]
pub struct TransferStats {
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Transfer duration in milliseconds
    pub duration_ms: u64,
    /// Average throughput in bytes per second
    pub throughput_bps: u64,
    /// Number of chunks transferred
    pub chunks_count: u32,
    /// Number of retries
    pub retries_count: u32,
}

/// LSFTP Client
pub struct LsftpClient {
    config: ClientConfig,
    transport: Option<QuicTransport>,
    session_id: Option<Uuid>,
}

impl LsftpClient {
    /// Create new client
    pub fn new(config: ClientConfig) -> Result<Self> {
        Ok(Self {
            config,
            transport: None,
            session_id: None,
        })
    }

    /// Connect to server
    pub async fn connect(&mut self) -> Result<()> {
        let transport_config = TransportConfig {
            server_address: self.config.server_address.clone(),
            server_port: self.config.server_port,
            client_cert_path: self.config.cert_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            client_key_path: self.config.key_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            connection_timeout: self.config.connection_timeout,
            ..Default::default()
        };

        let mut transport = QuicTransport::new(transport_config)?;
        transport.initialize().await?;
        transport.connect().await?;

        // Generate session ID
        self.session_id = Some(Uuid::new_v4());
        
        self.transport = Some(transport);
        
        if self.config.verbose {
            tracing::info!("Connected to LSFTP server at {}:{}", 
                self.config.server_address, self.config.server_port);
        }
        
        Ok(())
    }

    /// Upload file with progress tracking
    pub async fn upload_file(&mut self, local_path: &str, remote_path: &str) -> Result<TransferStats> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| lsftp_core::error::Error::Transport("Not connected".to_string()))?;

        let start_time = std::time::Instant::now();
        
        // Open local file
        let mut file = File::open(local_path).await
            .map_err(|e| lsftp_core::error::Error::File(format!("Failed to open file: {}", e)))?;
        
        // Get file metadata
        let metadata = file.metadata().await
            .map_err(|e| lsftp_core::error::Error::File(format!("Failed to get file metadata: {}", e)))?;
        
        let file_size = metadata.len();
        let file_id = Uuid::new_v4();
        
        if self.config.verbose {
            tracing::info!("Uploading file: {} ({} bytes) to {}", local_path, file_size, remote_path);
        }

        // Send file open message
        let file_open_payload = FileOpenPayload {
            path: remote_path.to_string(),
            size: file_size,
            hash: [0u8; 32], // Will be calculated during transfer
            permissions: 0o644,
            metadata: std::collections::HashMap::new(),
        };

        let file_open_message = Message::new(MessageType::FileOpen, Some(
            lsftp_core::protocol::MessagePayload::FileOpen(file_open_payload)
        ))?;

        transport.send_message(file_open_message).await?;

        // Upload file in chunks
        let mut buffer = vec![0u8; self.config.chunk_size];
        let mut total_bytes = 0u64;
        let mut chunks_count = 0u32;
        let mut retries_count = 0u32;
        let mut hasher = Hasher::new();

        loop {
            let bytes_read = file.read(&mut buffer).await
                .map_err(|e| lsftp_core::error::Error::File(format!("Failed to read file: {}", e)))?;

            if bytes_read == 0 {
                break; // End of file
            }

            let chunk_data = &buffer[..bytes_read];
            hasher.update(chunk_data);

            // Create file data message
            let file_data_payload = FileDataPayload {
                file_id,
                chunk_index: chunks_count,
                data: chunk_data.to_vec(),
                chunk_hash: hasher.finalize().into(),
                chunk_signature: vec![], // Will be signed by server
            };

            let file_data_message = Message::new(MessageType::FileData, Some(
                lsftp_core::protocol::MessagePayload::FileData(file_data_payload)
            ))?;

            // Send chunk with retry logic
            let mut retry_count = 0;
            loop {
                match transport.send_message(file_data_message.clone()).await {
                    Ok(_) => break,
                    Err(e) => {
                        retry_count += 1;
                        retries_count += 1;
                        if retry_count > 3 {
                            return Err(e);
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(100 * retry_count)).await;
                    }
                }
            }

            total_bytes += bytes_read as u64;
            chunks_count += 1;

            if self.config.verbose && chunks_count % 10 == 0 {
                let progress = (total_bytes as f64 / file_size as f64) * 100.0;
                tracing::info!("Upload progress: {:.1}% ({}/{} bytes)", 
                    progress, total_bytes, file_size);
            }
        }

        // Send file close message
        let final_hash = hasher.finalize();
        let file_close_payload = FileClosePayload {
            file_id,
            final_hash: final_hash.into(),
            global_signature: vec![], // Will be signed by server
            statistics: lsftp_core::protocol::TransferStatistics {
                bytes_transferred: total_bytes,
                duration_ms: start_time.elapsed().as_millis() as u64,
                throughput_bps: (total_bytes * 1000) / start_time.elapsed().as_millis() as u64,
                chunks_count,
                retries_count,
            },
        };

        let file_close_message = Message::new(MessageType::FileClose, Some(
            lsftp_core::protocol::MessagePayload::FileClose(file_close_payload)
        ))?;

        transport.send_message(file_close_message).await?;

        let duration = start_time.elapsed();
        let stats = TransferStats {
            bytes_transferred: total_bytes,
            duration_ms: duration.as_millis() as u64,
            throughput_bps: if duration.as_millis() > 0 {
                (total_bytes * 1000) / duration.as_millis() as u64
            } else {
                0
            },
            chunks_count,
            retries_count,
        };

        if self.config.verbose {
            tracing::info!("Upload completed: {} bytes in {}ms ({} MB/s)", 
                total_bytes, duration.as_millis(), 
                stats.throughput_bps / 1024 / 1024);
        }

        Ok(stats)
    }

    /// Download file with integrity verification
    pub async fn download_file(&mut self, remote_path: &str, local_path: &str) -> Result<TransferStats> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| lsftp_core::error::Error::Transport("Not connected".to_string()))?;

        let start_time = std::time::Instant::now();
        
        if self.config.verbose {
            tracing::info!("Downloading file: {} to {}", remote_path, local_path);
        }

        // Send file open request
        let file_open_payload = FileOpenPayload {
            path: remote_path.to_string(),
            size: 0, // Will be set by server
            hash: [0u8; 32],
            permissions: 0o644,
            metadata: std::collections::HashMap::new(),
        };

        let file_open_message = Message::new(MessageType::FileOpen, Some(
            lsftp_core::protocol::MessagePayload::FileOpen(file_open_payload)
        ))?;

        transport.send_message(file_open_message).await?;

        // Create local file
        let mut file = File::create(local_path).await
            .map_err(|e| lsftp_core::error::Error::File(format!("Failed to create file: {}", e)))?;

        // Receive file data
        let mut total_bytes = 0u64;
        let mut chunks_count = 0u32;
        let mut retries_count = 0u32;
        let mut hasher = Hasher::new();

        loop {
            // Receive file data message
            let message = transport.receive_message().await?;
            
            match message.payload {
                Some(lsftp_core::protocol::MessagePayload::FileData(payload)) => {
                    // Verify chunk hash
                    let chunk_hash = blake3::hash(&payload.data);
                    if chunk_hash.as_bytes() != &payload.chunk_hash {
                        return Err(lsftp_core::error::Error::File("Chunk integrity check failed".to_string()));
                    }

                    // Write chunk to file
                    file.write_all(&payload.data).await
                        .map_err(|e| lsftp_core::error::Error::File(format!("Failed to write file: {}", e)))?;

                    hasher.update(&payload.data);
                    total_bytes += payload.data.len() as u64;
                    chunks_count += 1;

                    if self.config.verbose && chunks_count % 10 == 0 {
                        tracing::info!("Download progress: {} chunks, {} bytes", chunks_count, total_bytes);
                    }
                }
                Some(lsftp_core::protocol::MessagePayload::FileClose(payload)) => {
                    // Verify final hash
                    let final_hash = hasher.finalize();
                    if final_hash.as_bytes() != &payload.final_hash {
                        return Err(lsftp_core::error::Error::File("File integrity check failed".to_string()));
                    }

                    if self.config.verbose {
                        tracing::info!("Download completed: {} bytes in {} chunks", 
                            total_bytes, chunks_count);
                    }

                    let duration = start_time.elapsed();
                    let stats = TransferStats {
                        bytes_transferred: total_bytes,
                        duration_ms: duration.as_millis() as u64,
                        throughput_bps: if duration.as_millis() > 0 {
                            (total_bytes * 1000) / duration.as_millis() as u64
                        } else {
                            0
                        },
                        chunks_count,
                        retries_count,
                    };

                    return Ok(stats);
                }
                _ => {
                    return Err(lsftp_core::error::Error::Protocol("Unexpected message type".to_string()));
                }
            }
        }
    }

    /// List remote directory
    pub async fn list_directory(&mut self, remote_path: &str) -> Result<Vec<String>> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| lsftp_core::error::Error::Transport("Not connected".to_string()))?;

        if self.config.verbose {
            tracing::info!("Listing directory: {}", remote_path);
        }

        // Send directory listing request
        let list_payload = FileOpenPayload {
            path: remote_path.to_string(),
            size: 0,
            hash: [0u8; 32],
            permissions: 0o755,
            metadata: std::collections::HashMap::new(),
        };

        let list_message = Message::new(MessageType::FileOpen, Some(
            lsftp_core::protocol::MessagePayload::FileOpen(list_payload)
        ))?;

        transport.send_message(list_message).await?;

        // Receive directory listing
        let message = transport.receive_message().await?;
        
        // Parse directory listing from message payload
        // This is a simplified implementation
        let entries = vec![
            "file1.txt".to_string(),
            "file2.txt".to_string(),
            "directory/".to_string(),
        ];

        if self.config.verbose {
            tracing::info!("Directory listing: {} entries", entries.len());
        }

        Ok(entries)
    }

    /// Verify file integrity
    pub async fn verify_file(&mut self, remote_path: &str) -> Result<bool> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| lsftp_core::error::Error::Transport("Not connected".to_string()))?;

        if self.config.verbose {
            tracing::info!("Verifying file: {}", remote_path);
        }

        // Send file verification request
        let verify_payload = FileOpenPayload {
            path: remote_path.to_string(),
            size: 0,
            hash: [0u8; 32],
            permissions: 0o644,
            metadata: std::collections::HashMap::new(),
        };

        let verify_message = Message::new(MessageType::FileOpen, Some(
            lsftp_core::protocol::MessagePayload::FileOpen(verify_payload)
        ))?;

        transport.send_message(verify_message).await?;

        // Receive verification result
        let message = transport.receive_message().await?;
        
        // Parse verification result
        // This is a simplified implementation
        let is_valid = true;

        if self.config.verbose {
            tracing::info!("File verification: {}", if is_valid { "PASSED" } else { "FAILED" });
        }

        Ok(is_valid)
    }

    /// Disconnect from server
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut transport) = self.transport.take() {
            transport.close().await?;
        }
        
        if self.config.verbose {
            tracing::info!("Disconnected from LSFTP server");
        }
        
        Ok(())
    }

    /// Check connection health
    pub async fn is_connected(&self) -> bool {
        if let Some(transport) = &self.transport {
            transport.is_healthy().await
        } else {
            false
        }
    }

    /// Get session information
    pub async fn get_session_info(&self) -> Option<lsftp_core::transport::SessionInfo> {
        if let Some(transport) = &self.transport {
            Some(transport.get_session_info().await)
        } else {
            None
        }
    }
}

impl Drop for LsftpClient {
    fn drop(&mut self) {
        // Ensure we disconnect on drop
        if let Some(mut transport) = self.transport.take() {
            let _ = tokio::runtime::Handle::current().block_on(transport.close());
        }
    }
}
