//! Audit and logging for LSFTP
//! 
//! This module provides structured logging, audit trails, and
//! compliance features for LSFTP operations.

use crate::error::Result;
use crate::crypto::CryptoOperations;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Debug information
    Debug = 0,
    /// Informational message
    Info = 1,
    /// Warning message
    Warning = 2,
    /// Error condition
    Error = 3,
    /// Critical error
    Critical = 4,
}

/// Audit action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditAction {
    /// User authentication
    Authentication,
    /// File upload
    FileUpload,
    /// File download
    FileDownload,
    /// File deletion
    FileDelete,
    /// Policy change
    PolicyChange,
    /// Session start
    SessionStart,
    /// Session end
    SessionEnd,
    /// Configuration change
    ConfigChange,
    /// Security event
    SecurityEvent,
    /// System event
    SystemEvent,
}

/// Audit result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// Operation successful
    Success,
    /// Operation failed
    Failure,
    /// Operation denied
    Denied,
    /// Operation in progress
    InProgress,
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event ID
    pub event_id: Uuid,
    /// User ID
    pub user_id: Option<String>,
    /// Hardware device ID
    pub hardware_id: Option<String>,
    /// Action performed
    pub action: AuditAction,
    /// File path (if applicable)
    pub file_path: Option<String>,
    /// File hash (if applicable)
    pub file_hash: Option<[u8; 32]>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Session ID
    pub session_id: Option<Uuid>,
    /// Bytes transferred (if applicable)
    pub bytes_transferred: Option<u64>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
    /// Result of operation
    pub result: AuditResult,
    /// Error code (if applicable)
    pub error_code: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Event signature for non-repudiation
    pub signature: Option<Vec<u8>>,
}

impl AuditEvent {
    /// Create new audit event
    pub fn new(action: AuditAction, result: AuditResult) -> Self {
        Self {
            timestamp: SystemTime::now(),
            event_id: Uuid::new_v4(),
            user_id: None,
            hardware_id: None,
            action,
            file_path: None,
            file_hash: None,
            source_ip: None,
            session_id: None,
            bytes_transferred: None,
            duration_ms: None,
            result,
            error_code: None,
            metadata: HashMap::new(),
            signature: None,
        }
    }

    /// Set user ID
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set hardware ID
    pub fn with_hardware_id(mut self, hardware_id: String) -> Self {
        self.hardware_id = Some(hardware_id);
        self
    }

    /// Set file path
    pub fn with_file_path(mut self, file_path: String) -> Self {
        self.file_path = Some(file_path);
        self
    }

    /// Set file hash
    pub fn with_file_hash(mut self, file_hash: [u8; 32]) -> Self {
        self.file_hash = Some(file_hash);
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, source_ip: String) -> Self {
        self.source_ip = Some(source_ip);
        self
    }

    /// Set session ID
    pub fn with_session_id(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set bytes transferred
    pub fn with_bytes_transferred(mut self, bytes: u64) -> Self {
        self.bytes_transferred = Some(bytes);
        self
    }

    /// Set duration
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Set error code
    pub fn with_error_code(mut self, error_code: String) -> Self {
        self.error_code = Some(error_code);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
}

/// Audit logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Log level
    pub log_level: Severity,
    /// Log format (json, text)
    pub log_format: String,
    /// Log destinations
    pub log_destinations: Vec<String>,
    /// Syslog server
    pub syslog_server: Option<String>,
    /// Syslog protocol
    pub syslog_protocol: String,
    /// Syslog certificate verification
    pub syslog_cert_verify: bool,
    /// Audit log path
    pub audit_log_path: String,
    /// Audit log rotation
    pub audit_log_rotation: String,
    /// Audit log encryption
    pub audit_log_encryption: bool,
    /// Audit log signing
    pub audit_log_signing: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_level: Severity::Info,
            log_format: "json".to_string(),
            log_destinations: vec!["stdout".to_string(), "audit_file".to_string()],
            syslog_server: None,
            syslog_protocol: "tls".to_string(),
            syslog_cert_verify: true,
            audit_log_path: "/var/log/lsftp/audit.json".to_string(),
            audit_log_rotation: "daily".to_string(),
            audit_log_encryption: true,
            audit_log_signing: true,
        }
    }
}

/// Audit logger implementation
pub struct AuditLogger {
    config: AuditConfig,
    crypto_suite: crate::crypto::CryptoSuite,
}

impl AuditLogger {
    /// Create new audit logger
    pub fn new(config: AuditConfig, crypto_suite: crate::crypto::CryptoSuite) -> Result<Self> {
        Ok(Self {
            config,
            crypto_suite,
        })
    }

    /// Log audit event
    pub async fn log_event(&self, event: AuditEvent) -> Result<()> {
        // Create structured log entry
        let log_entry = self.create_log_entry(&event)?;

        // Log to different destinations
        for destination in &self.config.log_destinations {
            match destination.as_str() {
                "stdout" => {
                    println!("{}", serde_json::to_string(&log_entry)?);
                }
                "audit_file" => {
                    self.write_to_audit_file(&log_entry).await?;
                }
                "syslog" => {
                    self.send_to_syslog(&log_entry).await?;
                }
                _ => {
                    tracing::warn!("Unknown log destination: {}", destination);
                }
            }
        }

        // Real-time SIEM push for critical events
        if event.result == AuditResult::Failure || event.action == AuditAction::SecurityEvent {
            self.push_to_siem(log_entry).await?;
        }

        Ok(())
    }

    /// Create structured log entry
    fn create_log_entry(&self, event: &AuditEvent) -> Result<serde_json::Value> {
        let timestamp = event.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_entry = serde_json::json!({
            "timestamp": timestamp,
            "event_id": event.event_id.to_string(),
            "source": "lsftp-server",
            "event_type": format!("{:?}", event.action),
            "severity": format!("{:?}", self.get_severity(event)),
            "user_id": event.user_id,
            "source_ip": event.source_ip,
            "hardware_id": event.hardware_id,
            "file_path": event.file_path,
            "bytes_transferred": event.bytes_transferred,
            "duration_ms": event.duration_ms,
            "result": format!("{:?}", event.result),
            "error_code": event.error_code,
            "session_id": event.session_id.map(|id| id.to_string()),
            "metadata": event.metadata,
            // CEF (Common Event Format) compatibility
            "cef_version": "CEF:0",
            "device_vendor": "LSFTP",
            "device_product": "Secure File Transfer",
            "device_version": env!("CARGO_PKG_VERSION"),
        });

        Ok(log_entry)
    }

    /// Get severity level for event
    fn get_severity(&self, event: &AuditEvent) -> Severity {
        match event.result {
            AuditResult::Success => {
                match event.action {
                    AuditAction::SecurityEvent => Severity::Warning,
                    AuditAction::Authentication => Severity::Info,
                    _ => Severity::Debug,
                }
            }
            AuditResult::Failure => {
                match event.action {
                    AuditAction::SecurityEvent => Severity::Critical,
                    AuditAction::Authentication => Severity::Error,
                    _ => Severity::Warning,
                }
            }
            AuditResult::Denied => Severity::Warning,
            AuditResult::InProgress => Severity::Info,
        }
    }

    /// Write to audit file
    async fn write_to_audit_file(&self, _log_entry: &serde_json::Value) -> Result<()> {
        // TODO: Implement actual file writing with rotation and encryption
        // This would involve:
        // 1. Creating audit file directory if needed
        // 2. Writing log entry to file
        // 3. Implementing log rotation
        // 4. Encrypting log entries if enabled
        // 5. Signing log entries if enabled
        
        tracing::debug!("Writing audit entry to file: {}", self.config.audit_log_path);
        Ok(())
    }

    /// Send to syslog
    async fn send_to_syslog(&self, _log_entry: &serde_json::Value) -> Result<()> {
        // TODO: Implement actual syslog sending
        // This would involve:
        // 1. Connecting to syslog server
        // 2. Sending log entry via TLS
        // 3. Handling connection errors
        
        if let Some(server) = &self.config.syslog_server {
            tracing::debug!("Sending to syslog server: {}", server);
        }
        
        Ok(())
    }

    /// Push to SIEM
    async fn push_to_siem(&self, _log_entry: serde_json::Value) -> Result<()> {
        // TODO: Implement actual SIEM push
        // This would involve:
        // 1. Connecting to SIEM endpoint
        // 2. Sending log entry via API
        // 3. Handling authentication
        // 4. Managing rate limits
        
        tracing::info!("Pushing critical event to SIEM");
        Ok(())
    }

    /// Sign audit event
    pub async fn sign_event(&self, event: &mut AuditEvent) -> Result<()> {
        if !self.config.audit_log_signing {
            return Ok(());
        }

        // Create signature data
        let signature_data = self.create_signature_data(event)?;
        
        // Sign with crypto suite
        let signature = self.crypto_suite.hash(&signature_data)?;
        event.signature = Some(signature);
        
        Ok(())
    }

    /// Create signature data for event
    fn create_signature_data(&self, event: &AuditEvent) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        
        // Include all critical fields in signature
        data.extend_from_slice(&event.timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_be_bytes());
        
        data.extend_from_slice(event.event_id.as_bytes());
        
        if let Some(ref user_id) = event.user_id {
            data.extend_from_slice(user_id.as_bytes());
        }
        
        if let Some(ref hardware_id) = event.hardware_id {
            data.extend_from_slice(hardware_id.as_bytes());
        }
        
        data.push(event.action as u8);
        data.push(event.result as u8);
        
        if let Some(ref file_path) = event.file_path {
            data.extend_from_slice(file_path.as_bytes());
        }
        
        if let Some(file_hash) = event.file_hash {
            data.extend_from_slice(&file_hash);
        }
        
        Ok(data)
    }

    /// Verify audit event signature
    pub async fn verify_event_signature(&self, event: &AuditEvent) -> Result<bool> {
        if event.signature.is_none() {
            return Ok(false);
        }

        let signature_data = self.create_signature_data(event)?;
        let expected_signature = self.crypto_suite.hash(&signature_data)?;
        let actual_signature = event.signature.as_ref().unwrap();
        
        Ok(expected_signature == *actual_signature)
    }
}

/// Security event logger
pub struct SecurityLogger {
    audit_logger: AuditLogger,
}

impl SecurityLogger {
    /// Create new security logger
    pub fn new(audit_logger: AuditLogger) -> Self {
        Self { audit_logger }
    }

    /// Log security event
    pub async fn log_security_event(&self, event: AuditEvent) -> Result<()> {
        // Log with security-specific formatting
        let mut security_event = event;
        security_event.metadata.insert("security_event".to_string(), "true".to_string());
        
        self.audit_logger.log_event(security_event).await
    }

    /// Log authentication attempt
    pub async fn log_auth_attempt(
        &self,
        user_id: Option<String>,
        hardware_id: Option<String>,
        source_ip: Option<String>,
        success: bool,
        error_code: Option<String>,
    ) -> Result<()> {
        let event = AuditEvent::new(
            AuditAction::Authentication,
            if success { AuditResult::Success } else { AuditResult::Failure }
        )
        .with_user_id(user_id.unwrap_or_else(|| "unknown".to_string()))
        .with_hardware_id(hardware_id.unwrap_or_else(|| "unknown".to_string()))
        .with_source_ip(source_ip.unwrap_or_else(|| "unknown".to_string()))
        .with_error_code(error_code.unwrap_or_else(|| "none".to_string()));

        self.audit_logger.log_event(event).await
    }

    /// Log file transfer
    pub async fn log_file_transfer(
        &self,
        user_id: Option<String>,
        file_path: Option<String>,
        file_hash: Option<[u8; 32]>,
        bytes_transferred: u64,
        duration_ms: u64,
        action: AuditAction,
        success: bool,
    ) -> Result<()> {
        let event = AuditEvent::new(
            action,
            if success { AuditResult::Success } else { AuditResult::Failure }
        )
        .with_user_id(user_id.unwrap_or_else(|| "unknown".to_string()))
        .with_file_path(file_path.unwrap_or_else(|| "unknown".to_string()))
        .with_bytes_transferred(bytes_transferred)
        .with_duration(duration_ms);

        if let Some(hash) = file_hash {
            let event = event.with_file_hash(hash);
            self.audit_logger.log_event(event).await
        } else {
            self.audit_logger.log_event(event).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(AuditAction::Authentication, AuditResult::Success)
            .with_user_id("test_user".to_string())
            .with_hardware_id("test_hardware".to_string())
            .with_source_ip("127.0.0.1".to_string());

        assert_eq!(event.user_id, Some("test_user".to_string()));
        assert_eq!(event.hardware_id, Some("test_hardware".to_string()));
        assert_eq!(event.source_ip, Some("127.0.0.1".to_string()));
        assert_eq!(event.action, AuditAction::Authentication);
        assert_eq!(event.result, AuditResult::Success);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let config = AuditConfig::default();
        let crypto_suite = crate::crypto::CryptoSuite::default();
        let logger = AuditLogger::new(config, crypto_suite);
        assert!(logger.is_ok());
    }
}
