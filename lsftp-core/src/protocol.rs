//! LSFTP Protocol implementation
//! 
//! This module defines the wire protocol format, message types,
//! and protocol state machine for LSFTP.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// LSFTP Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake and authentication
    Handshake = 0x01,
    /// File open request with metadata
    FileOpen = 0x02,
    /// File data chunk
    FileData = 0x03,
    /// File close with final signature
    FileClose = 0x04,
    /// Keep-alive and health check
    Heartbeat = 0x05,
    /// Policy update in real-time
    PolicyUpdate = 0x06,
    /// Emergency stop and revocation
    EmergencyStop = 0x07,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::Handshake),
            0x02 => Ok(MessageType::FileOpen),
            0x03 => Ok(MessageType::FileData),
            0x04 => Ok(MessageType::FileClose),
            0x05 => Ok(MessageType::Heartbeat),
            0x06 => Ok(MessageType::PolicyUpdate),
            0x07 => Ok(MessageType::EmergencyStop),
            _ => Err(Error::Protocol(format!("Unknown message type: 0x{:02x}", value))),
        }
    }
}

/// Protocol flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flags {
    /// End of message
    pub eom: bool,
    /// Compressed payload
    pub compressed: bool,
    /// Encrypted payload
    pub encrypted: bool,
    /// Requires acknowledgment
    pub requires_ack: bool,
    /// High priority
    pub high_priority: bool,
}

impl Default for Flags {
    fn default() -> Self {
        Self {
            eom: false,
            compressed: false,
            encrypted: true, // Default to encrypted
            requires_ack: false,
            high_priority: false,
        }
    }
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Self {
            eom: (value & 0x01) != 0,
            compressed: (value & 0x02) != 0,
            encrypted: (value & 0x04) != 0,
            requires_ack: (value & 0x08) != 0,
            high_priority: (value & 0x10) != 0,
        }
    }
}

impl From<Flags> for u16 {
    fn from(flags: Flags) -> Self {
        let mut value = 0u16;
        if flags.eom { value |= 0x01; }
        if flags.compressed { value |= 0x02; }
        if flags.encrypted { value |= 0x04; }
        if flags.requires_ack { value |= 0x08; }
        if flags.high_priority { value |= 0x10; }
        value
    }
}

/// LSFTP Frame Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Protocol version
    pub version: u8,
    /// Message type
    pub message_type: MessageType,
    /// Protocol flags
    pub flags: Flags,
    /// Payload length
    pub length: u32,
    /// Sequence number
    pub sequence: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Payload data
    pub payload: Vec<u8>,
    /// HMAC signature
    pub hmac: [u8; 32],
}

impl Frame {
    /// Create a new frame
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: crate::PROTOCOL_VERSION,
            message_type,
            flags: Flags::default(),
            length: payload.len() as u32,
            sequence: 0, // Will be set by transport layer
            timestamp,
            payload,
            hmac: [0u8; 32], // Will be computed by transport layer
        }
    }

    /// Serialize frame to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        
        // Header (16 bytes)
        buffer.push(self.version);
        buffer.push(self.message_type as u8);
        buffer.extend_from_slice(&u16::from(self.flags).to_be_bytes());
        buffer.extend_from_slice(&self.length.to_be_bytes());
        
        // Sequence and timestamp (16 bytes)
        buffer.extend_from_slice(&self.sequence.to_be_bytes());
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());
        
        // Payload
        buffer.extend_from_slice(&self.payload);
        
        // HMAC (32 bytes)
        buffer.extend_from_slice(&self.hmac);
        
        Ok(buffer)
    }

    /// Deserialize frame from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 48 { // Minimum frame size
            return Err(Error::Protocol("Frame too short".to_string()));
        }

        let version = data[0];
        let message_type = MessageType::try_from(data[1])?;
        let flags = Flags::from(u16::from_be_bytes([data[2], data[3]]));
        let length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let sequence = u64::from_be_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15]
        ]);
        let timestamp = u64::from_be_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23]
        ]);

        let payload_start = 24;
        let payload_end = payload_start + length as usize;
        let hmac_start = payload_end;

        if data.len() < hmac_start + 32 {
            return Err(Error::Protocol("Frame incomplete".to_string()));
        }

        let payload = data[payload_start..payload_end].to_vec();
        let hmac = data[hmac_start..hmac_start + 32].try_into()
            .map_err(|_| Error::Protocol("Invalid HMAC".to_string()))?;

        Ok(Self {
            version,
            message_type,
            flags,
            length,
            sequence,
            timestamp,
            payload,
            hmac,
        })
    }
}

/// Handshake message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    /// Client random
    pub client_random: [u8; 32],
    /// Server random
    pub server_random: [u8; 32],
    /// Supported crypto suites
    pub crypto_suites: Vec<crate::crypto::CryptoSuite>,
    /// Hardware attestation data
    pub hardware_attestation: Option<Vec<u8>>,
    /// Certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
}

/// File open message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOpenPayload {
    /// File path
    pub path: String,
    /// File size
    pub size: u64,
    /// File hash
    pub hash: [u8; 32],
    /// File permissions
    pub permissions: u32,
    /// File metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// File data message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDataPayload {
    /// File ID
    pub file_id: uuid::Uuid,
    /// Chunk index
    pub chunk_index: u32,
    /// Chunk data
    pub data: Vec<u8>,
    /// Chunk hash
    pub chunk_hash: [u8; 32],
    /// Chunk signature
    pub chunk_signature: Vec<u8>,
}

/// File close message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileClosePayload {
    /// File ID
    pub file_id: uuid::Uuid,
    /// Final file hash
    pub final_hash: [u8; 32],
    /// Global signature
    pub global_signature: Vec<u8>,
    /// Transfer statistics
    pub statistics: TransferStatistics,
}

/// Transfer statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStatistics {
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Transfer duration in milliseconds
    pub duration_ms: u64,
    /// Average throughput in bytes per second
    pub throughput_bps: u64,
    /// Number of chunks
    pub chunks_count: u32,
    /// Number of retries
    pub retries_count: u32,
}

/// Heartbeat message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    /// Session ID
    pub session_id: uuid::Uuid,
    /// Health status
    pub health_status: HealthStatus,
    /// Current timestamp
    pub timestamp: u64,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Healthy
    Healthy = 0,
    /// Warning
    Warning = 1,
    /// Critical
    Critical = 2,
    /// Unknown
    Unknown = 3,
}

/// Policy update message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdatePayload {
    /// Policy ID
    pub policy_id: uuid::Uuid,
    /// Policy version
    pub version: u32,
    /// Policy rules
    pub rules: Vec<PolicyRule>,
    /// Effective timestamp
    pub effective_at: u64,
}

/// Policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule ID
    pub id: String,
    /// Rule type
    pub rule_type: PolicyRuleType,
    /// Rule parameters
    pub parameters: std::collections::HashMap<String, String>,
}

/// Policy rule type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyRuleType {
    /// Access control
    AccessControl,
    /// Rate limiting
    RateLimit,
    /// File size limit
    FileSizeLimit,
    /// Encryption requirement
    EncryptionRequirement,
    /// Audit requirement
    AuditRequirement,
}

/// Emergency stop message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyStopPayload {
    /// Session ID to stop
    pub session_id: uuid::Uuid,
    /// Reason for emergency stop
    pub reason: String,
    /// Stop timestamp
    pub timestamp: u64,
    /// Stop signature
    pub signature: Vec<u8>,
}

/// LSFTP Message wrapper
#[derive(Debug, Clone)]
pub struct Message {
    /// Message frame
    pub frame: Frame,
    /// Parsed payload (if applicable)
    pub payload: Option<MessagePayload>,
}

/// Message payload types
#[derive(Debug, Clone)]
pub enum MessagePayload {
    /// Handshake payload
    Handshake(HandshakePayload),
    /// File open payload
    FileOpen(FileOpenPayload),
    /// File data payload
    FileData(FileDataPayload),
    /// File close payload
    FileClose(FileClosePayload),
    /// Heartbeat payload
    Heartbeat(HeartbeatPayload),
    /// Policy update payload
    PolicyUpdate(PolicyUpdatePayload),
    /// Emergency stop payload
    EmergencyStop(EmergencyStopPayload),
}

impl Message {
    /// Create a new message
    pub fn new(message_type: MessageType, payload: Option<MessagePayload>) -> Result<Self> {
        let frame_payload = match &payload {
            Some(MessagePayload::Handshake(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::FileOpen(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::FileData(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::FileClose(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::Heartbeat(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::PolicyUpdate(p)) => postcard::to_allocvec(p)?,
            Some(MessagePayload::EmergencyStop(p)) => postcard::to_allocvec(p)?,
            None => Vec::new(),
        };

        let frame = Frame::new(message_type, frame_payload);
        
        Ok(Self {
            frame,
            payload,
        })
    }

    /// Parse payload from frame
    pub fn parse_payload(&mut self) -> Result<()> {
        if self.payload.is_some() {
            return Ok(());
        }

        self.payload = match self.frame.message_type {
            MessageType::Handshake => {
                let payload: HandshakePayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::Handshake(payload))
            }
            MessageType::FileOpen => {
                let payload: FileOpenPayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::FileOpen(payload))
            }
            MessageType::FileData => {
                let payload: FileDataPayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::FileData(payload))
            }
            MessageType::FileClose => {
                let payload: FileClosePayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::FileClose(payload))
            }
            MessageType::Heartbeat => {
                let payload: HeartbeatPayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::Heartbeat(payload))
            }
            MessageType::PolicyUpdate => {
                let payload: PolicyUpdatePayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::PolicyUpdate(payload))
            }
            MessageType::EmergencyStop => {
                let payload: EmergencyStopPayload = postcard::from_bytes(&self.frame.payload)?;
                Some(MessagePayload::EmergencyStop(payload))
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::Handshake as u8, 0x01);
        assert_eq!(MessageType::FileOpen as u8, 0x02);
        assert_eq!(MessageType::FileData as u8, 0x03);
        assert_eq!(MessageType::FileClose as u8, 0x04);
        assert_eq!(MessageType::Heartbeat as u8, 0x05);
        assert_eq!(MessageType::PolicyUpdate as u8, 0x06);
        assert_eq!(MessageType::EmergencyStop as u8, 0x07);
    }

    #[test]
    fn test_flags_conversion() {
        let flags = Flags {
            eom: true,
            compressed: false,
            encrypted: true,
            requires_ack: false,
            high_priority: true,
        };
        
        let value: u16 = flags.into();
        let flags_back: Flags = value.into();
        
        assert_eq!(flags.eom, flags_back.eom);
        assert_eq!(flags.compressed, flags_back.compressed);
        assert_eq!(flags.encrypted, flags_back.encrypted);
        assert_eq!(flags.requires_ack, flags_back.requires_ack);
        assert_eq!(flags.high_priority, flags_back.high_priority);
    }

    #[test]
    fn test_frame_serialization() {
        let frame = Frame::new(MessageType::Handshake, b"test payload".to_vec());
        let serialized = frame.serialize().unwrap();
        let deserialized = Frame::deserialize(&serialized).unwrap();
        
        assert_eq!(frame.version, deserialized.version);
        assert_eq!(frame.message_type, deserialized.message_type);
        assert_eq!(frame.length, deserialized.length);
        assert_eq!(frame.payload, deserialized.payload);
    }
}
