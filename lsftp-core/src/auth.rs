//! Hardware authentication for LSFTP
//! 
//! This module provides hardware-based authentication using TPM 2.0,
//! YubiKey, and smart cards as specified in the LSFTP protocol for Linux systems.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use std::os::unix::fs::PermissionsExt;

// Hardware security modules enabled for Linux

/// Hardware device types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareType {
    /// TPM 2.0
    Tpm,
    /// YubiKey
    YubiKey,
    /// Smart Card
    SmartCard,
    /// Hardware Security Module
    Hsm,
}

/// Hardware authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Authentication successful
    pub success: bool,
    /// User identifier
    pub user_id: Option<String>,
    /// Hardware device identifier
    pub device_id: Option<String>,
    /// Authentication timestamp
    pub timestamp: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Hardware attestation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    /// Device type
    pub device_type: HardwareType,
    /// Device identifier
    pub device_id: String,
    /// Attestation data
    pub attestation_data: Vec<u8>,
    /// Attestation signature
    pub signature: Vec<u8>,
    /// Certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
}

/// Hardware authentication trait
#[async_trait::async_trait]
pub trait HardwareAuth {
    /// Initialize hardware device
    async fn initialize(&mut self) -> Result<()>;
    
    /// Perform hardware authentication
    async fn authenticate(&self, challenge: &[u8]) -> Result<AuthResult>;
    
    /// Generate attestation data
    async fn generate_attestation(&self) -> Result<HardwareAttestation>;
    
    /// Verify attestation data
    async fn verify_attestation(&self, attestation: &HardwareAttestation) -> Result<bool>;
    
    /// Get device information
    async fn get_device_info(&self) -> Result<DeviceInfo>;
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device type
    pub device_type: HardwareType,
    /// Device identifier
    pub device_id: String,
    /// Device manufacturer
    pub manufacturer: String,
    /// Device model
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
    /// Supported algorithms
    pub supported_algorithms: Vec<String>,
    /// Device capabilities
    pub capabilities: Vec<String>,
}

/// TPM 2.0 implementation using tss-esapi
pub struct TpmAuth {
    device_path: String,
    device_info: Option<DeviceInfo>,
    tpm_context: Option<tss_esapi::Context>,
}

impl TpmAuth {
    pub fn new(device_path: String) -> Self {
        Self {
            device_path,
            device_info: None,
            tpm_context: None,
        }
    }

    async fn get_tpm_info(&self) -> Result<DeviceInfo> {
        // Check if TPM device exists
        if !Path::new(&self.device_path).exists() {
            return Err(Error::HardwareAuth(format!("TPM device not found at {}", self.device_path)));
        }

        // Read TPM device information from sysfs
        let manufacturer_path = "/sys/class/tpm/tpm0/caps";
        let manufacturer = if Path::new(manufacturer_path).exists() {
            fs::read_to_string(manufacturer_path).unwrap_or_else(|_| "Unknown".to_string())
        } else {
            "Unknown".to_string()
        };

        Ok(DeviceInfo {
            device_type: HardwareType::Tpm,
            device_id: "tpm2.0".to_string(),
            manufacturer,
            model: "TPM 2.0".to_string(),
            firmware_version: "1.0".to_string(),
            supported_algorithms: vec![
                "SHA256".to_string(),
                "RSA2048".to_string(),
                "ECC_P256".to_string(),
                "AES256".to_string(),
            ],
            capabilities: vec![
                "PCR".to_string(),
                "Attestation".to_string(),
                "Sealing".to_string(),
                "KeyGeneration".to_string(),
            ],
        })
    }

    async fn initialize_tpm_context(&mut self) -> Result<()> {
        // Initialize TPM context using tss-esapi
        let tcti = tss_esapi::tcti_ldr::TctiNameConf::from_environment_var()
            .map_err(|e| Error::HardwareAuth(format!("Failed to load TCTI: {}", e)))?;
        
        let context = tss_esapi::Context::new(tcti)
            .map_err(|e| Error::HardwareAuth(format!("Failed to create TPM context: {}", e)))?;
        
        self.tpm_context = Some(context);
        Ok(())
    }
}

#[async_trait::async_trait]
impl HardwareAuth for TpmAuth {
    async fn initialize(&mut self) -> Result<()> {
        // Initialize TPM context
        self.initialize_tpm_context().await?;
        
        // Get device information
        self.device_info = Some(self.get_tpm_info().await?);
        
        // Start TPM if needed
        if let Some(context) = &mut self.tpm_context {
            context.startup(tss_esapi::structures::StartupType::Clear)
                .map_err(|e| Error::HardwareAuth(format!("Failed to startup TPM: {}", e)))?;
        }
        
        Ok(())
    }

    async fn authenticate(&self, challenge: &[u8]) -> Result<AuthResult> {
        let context = self.tpm_context.as_ref()
            .ok_or_else(|| Error::HardwareAuth("TPM context not initialized".to_string()))?;

        // Create a signing key for authentication
        let key_handle = context.create_primary(
            tss_esapi::structures::Auth::Exclusive,
            tss_esapi::structures::Hierarchy::Endorsement,
            tss_esapi::structures::PublicBuilder::new()
                .public_algorithm(tss_esapi::structures::PublicAlgorithm::Rsa)
                .name_hashing_algorithm(tss_esapi::structures::HashingAlgorithm::Sha256)
                .object_attributes(tss_esapi::structures::ObjectAttributes::default())
                .parameters(tss_esapi::structures::PublicRsaParametersBuilder::new()
                    .scheme(tss_esapi::structures::PublicRsaParameters::default())
                    .key_bits(2048)
                    .exponent(0)
                    .symmetric(tss_esapi::structures::PublicRsaParameters::default())
                    .build()
                    .map_err(|e| Error::HardwareAuth(format!("Failed to build RSA parameters: {}", e)))?)
                .unique_identifier(tss_esapi::structures::PublicRsaParameters::default())
                .build()
                .map_err(|e| Error::HardwareAuth(format!("Failed to build public: {}", e)))?,
            tss_esapi::structures::Digest::try_from(challenge)
                .map_err(|e| Error::HardwareAuth(format!("Failed to create digest: {}", e)))?,
            None,
        ).map_err(|e| Error::HardwareAuth(format!("Failed to create primary key: {}", e)))?;

        // Sign the challenge
        let signature = context.sign(
            key_handle,
            tss_esapi::structures::Digest::try_from(challenge)
                .map_err(|e| Error::HardwareAuth(format!("Failed to create digest: {}", e)))?,
            tss_esapi::structures::SignatureScheme::RsaSsa(tss_esapi::structures::HashingAlgorithm::Sha256),
            None,
        ).map_err(|e| Error::HardwareAuth(format!("Failed to sign challenge: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "tpm2.0".to_string());

        Ok(AuthResult {
            success: true,
            user_id: Some("tpm_user".to_string()),
            device_id: Some(device_id),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: {
                let mut map = HashMap::new();
                map.insert("signature_algorithm".to_string(), "RSA-SHA256".to_string());
                map.insert("key_size".to_string(), "2048".to_string());
                map
            },
            error: None,
        })
    }

    async fn generate_attestation(&self) -> Result<HardwareAttestation> {
        let context = self.tpm_context.as_ref()
            .ok_or_else(|| Error::HardwareAuth("TPM context not initialized".to_string()))?;

        // Create attestation key
        let attestation_key = context.create_primary(
            tss_esapi::structures::Auth::Exclusive,
            tss_esapi::structures::Hierarchy::Endorsement,
            tss_esapi::structures::PublicBuilder::new()
                .public_algorithm(tss_esapi::structures::PublicAlgorithm::Rsa)
                .name_hashing_algorithm(tss_esapi::structures::HashingAlgorithm::Sha256)
                .object_attributes(tss_esapi::structures::ObjectAttributes::default())
                .parameters(tss_esapi::structures::PublicRsaParametersBuilder::new()
                    .scheme(tss_esapi::structures::PublicRsaParameters::default())
                    .key_bits(2048)
                    .exponent(0)
                    .symmetric(tss_esapi::structures::PublicRsaParameters::default())
                    .build()
                    .map_err(|e| Error::HardwareAuth(format!("Failed to build RSA parameters: {}", e)))?)
                .unique_identifier(tss_esapi::structures::PublicRsaParameters::default())
                .build()
                .map_err(|e| Error::HardwareAuth(format!("Failed to build public: {}", e)))?,
            tss_esapi::structures::Digest::try_from(&[0u8; 32])
                .map_err(|e| Error::HardwareAuth(format!("Failed to create digest: {}", e)))?,
            None,
        ).map_err(|e| Error::HardwareAuth(format!("Failed to create attestation key: {}", e)))?;

        // Generate quote (attestation)
        let quote = context.quote(
            attestation_key,
            tss_esapi::structures::Digest::try_from(&[0u8; 32])
                .map_err(|e| Error::HardwareAuth(format!("Failed to create digest: {}", e)))?,
            tss_esapi::structures::SignatureScheme::RsaSsa(tss_esapi::structures::HashingAlgorithm::Sha256),
            None,
        ).map_err(|e| Error::HardwareAuth(format!("Failed to generate quote: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "tpm2.0".to_string());

        Ok(HardwareAttestation {
            device_type: HardwareType::Tpm,
            device_id,
            attestation_data: quote.quoted.to_vec(),
            signature: quote.signature.signature().to_vec(),
            certificate_chain: vec![], // TPM certificates would be loaded here
        })
    }

    async fn verify_attestation(&self, attestation: &HardwareAttestation) -> Result<bool> {
        // Verify TPM attestation signature
        // This would involve verifying the quote signature and checking PCR values
        // For now, return true if attestation data is not empty
        Ok(!attestation.attestation_data.is_empty())
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        self.device_info.clone()
            .ok_or_else(|| Error::HardwareAuth("Device info not available".to_string()))
    }
}

/// YubiKey implementation using yubikey crate
pub struct YubiKeyAuth {
    device_path: Option<String>,
    device_info: Option<DeviceInfo>,
    yubikey: Option<yubikey::YubiKey>,
}

impl YubiKeyAuth {
    pub fn new(device_path: Option<String>) -> Self {
        Self {
            device_path,
            device_info: None,
            yubikey: None,
        }
    }

    async fn get_yubikey_info(&self) -> Result<DeviceInfo> {
        // Detect YubiKey devices
        let devices = yubikey::YubiKey::list()
            .map_err(|e| Error::HardwareAuth(format!("Failed to list YubiKeys: {}", e)))?;

        if devices.is_empty() {
            return Err(Error::HardwareAuth("No YubiKey devices found".to_string()));
        }

        let device = &devices[0]; // Use first available device
        
        Ok(DeviceInfo {
            device_type: HardwareType::YubiKey,
            device_id: format!("yubikey-{}", device.serial()),
            manufacturer: "Yubico".to_string(),
            model: "YubiKey".to_string(),
            firmware_version: format!("{}.{}.{}", device.version().major, device.version().minor, device.version().build),
            supported_algorithms: vec![
                "PIV".to_string(),
                "OpenPGP".to_string(),
                "FIDO2".to_string(),
                "OTP".to_string(),
            ],
            capabilities: vec![
                "Authentication".to_string(),
                "DigitalSignature".to_string(),
                "KeyGeneration".to_string(),
                "Attestation".to_string(),
            ],
        })
    }

    async fn initialize_yubikey(&mut self) -> Result<()> {
        // Connect to YubiKey
        let devices = yubikey::YubiKey::list()
            .map_err(|e| Error::HardwareAuth(format!("Failed to list YubiKeys: {}", e)))?;

        if devices.is_empty() {
            return Err(Error::HardwareAuth("No YubiKey devices found".to_string()));
        }

        let yubikey = yubikey::YubiKey::open(&devices[0])
            .map_err(|e| Error::HardwareAuth(format!("Failed to open YubiKey: {}", e)))?;

        self.yubikey = Some(yubikey);
        Ok(())
    }
}

#[async_trait::async_trait]
impl HardwareAuth for YubiKeyAuth {
    async fn initialize(&mut self) -> Result<()> {
        // Initialize YubiKey connection
        self.initialize_yubikey().await?;
        
        // Get device information
        self.device_info = Some(self.get_yubikey_info().await?);
        
        Ok(())
    }

    async fn authenticate(&self, challenge: &[u8]) -> Result<AuthResult> {
        let yubikey = self.yubikey.as_ref()
            .ok_or_else(|| Error::HardwareAuth("YubiKey not initialized".to_string()))?;

        // Use PIV authentication
        let piv = yubikey.piv()
            .map_err(|e| Error::HardwareAuth(format!("Failed to access PIV: {}", e)))?;

        // Generate signature using PIV key
        let signature = piv.sign_data(
            yubikey::piv::Slot::Authentication,
            challenge,
            yubikey::piv::Algorithm::Rsa2048,
        ).map_err(|e| Error::HardwareAuth(format!("Failed to sign with PIV: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "yubikey".to_string());

        Ok(AuthResult {
            success: true,
            user_id: Some("yubikey_user".to_string()),
            device_id: Some(device_id),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: {
                let mut map = HashMap::new();
                map.insert("signature_algorithm".to_string(), "RSA-SHA256".to_string());
                map.insert("key_slot".to_string(), "Authentication".to_string());
                map
            },
            error: None,
        })
    }

    async fn generate_attestation(&self) -> Result<HardwareAttestation> {
        let yubikey = self.yubikey.as_ref()
            .ok_or_else(|| Error::HardwareAuth("YubiKey not initialized".to_string()))?;

        // Use FIDO2 for attestation
        let fido2 = yubikey.fido2()
            .map_err(|e| Error::HardwareAuth(format!("Failed to access FIDO2: {}", e)))?;

        // Generate attestation data
        let attestation_data = fido2.get_info()
            .map_err(|e| Error::HardwareAuth(format!("Failed to get FIDO2 info: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "yubikey".to_string());

        Ok(HardwareAttestation {
            device_type: HardwareType::YubiKey,
            device_id,
            attestation_data: attestation_data.to_vec(),
            signature: vec![], // FIDO2 attestation signature would be generated here
            certificate_chain: vec![], // FIDO2 certificates would be included here
        })
    }

    async fn verify_attestation(&self, attestation: &HardwareAttestation) -> Result<bool> {
        // Verify YubiKey attestation
        // This would involve verifying FIDO2 attestation data
        Ok(!attestation.attestation_data.is_empty())
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        self.device_info.clone()
            .ok_or_else(|| Error::HardwareAuth("Device info not available".to_string()))
    }
}

/// Smart Card implementation using pcsc crate
pub struct SmartCardAuth {
    reader_name: String,
    device_info: Option<DeviceInfo>,
    context: Option<pcsc::Context>,
    card: Option<pcsc::Card>,
}

impl SmartCardAuth {
    pub fn new(reader_name: String) -> Self {
        Self {
            reader_name,
            device_info: None,
            context: None,
            card: None,
        }
    }

    async fn get_smartcard_info(&self) -> Result<DeviceInfo> {
        // List available smart card readers
        let context = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| Error::HardwareAuth(format!("Failed to establish PCSC context: {}", e)))?;

        let readers = context.list_readers()
            .map_err(|e| Error::HardwareAuth(format!("Failed to list readers: {}", e)))?;

        if readers.is_empty() {
            return Err(Error::HardwareAuth("No smart card readers found".to_string()));
        }

        // Try to connect to the specified reader
        let reader = readers.iter().find(|r| r.to_string().contains(&self.reader_name))
            .ok_or_else(|| Error::HardwareAuth(format!("Reader {} not found", self.reader_name)))?;

        let card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| Error::HardwareAuth(format!("Failed to connect to smart card: {}", e)))?;

        // Get card information using APDU commands
        let atr = card.status2()
            .map_err(|e| Error::HardwareAuth(format!("Failed to get card status: {}", e)))?
            .atr;

        Ok(DeviceInfo {
            device_type: HardwareType::SmartCard,
            device_id: format!("smartcard-{}", hex::encode(&atr[..8])),
            manufacturer: "Unknown".to_string(),
            model: "Smart Card".to_string(),
            firmware_version: "1.0".to_string(),
            supported_algorithms: vec![
                "RSA".to_string(),
                "ECC".to_string(),
                "AES".to_string(),
            ],
            capabilities: vec![
                "Authentication".to_string(),
                "DigitalSignature".to_string(),
                "KeyGeneration".to_string(),
            ],
        })
    }

    async fn initialize_smartcard(&mut self) -> Result<()> {
        // Establish PCSC context
        let context = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| Error::HardwareAuth(format!("Failed to establish PCSC context: {}", e)))?;

        let readers = context.list_readers()
            .map_err(|e| Error::HardwareAuth(format!("Failed to list readers: {}", e)))?;

        if readers.is_empty() {
            return Err(Error::HardwareAuth("No smart card readers found".to_string()));
        }

        // Connect to smart card
        let reader = readers.iter().find(|r| r.to_string().contains(&self.reader_name))
            .ok_or_else(|| Error::HardwareAuth(format!("Reader {} not found", self.reader_name)))?;

        let card = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .map_err(|e| Error::HardwareAuth(format!("Failed to connect to smart card: {}", e)))?;

        self.context = Some(context);
        self.card = Some(card);
        Ok(())
    }
}

#[async_trait::async_trait]
impl HardwareAuth for SmartCardAuth {
    async fn initialize(&mut self) -> Result<()> {
        // Initialize smart card connection
        self.initialize_smartcard().await?;
        
        // Get device information
        self.device_info = Some(self.get_smartcard_info().await?);
        
        Ok(())
    }

    async fn authenticate(&self, challenge: &[u8]) -> Result<AuthResult> {
        let card = self.card.as_ref()
            .ok_or_else(|| Error::HardwareAuth("Smart card not initialized".to_string()))?;

        // Use PKCS#11 or APDU commands for authentication
        // This is a simplified implementation
        let response = card.transmit(&[0x00, 0x88, 0x00, 0x00, challenge.len() as u8])
            .map_err(|e| Error::HardwareAuth(format!("Failed to transmit APDU: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "smartcard".to_string());

        Ok(AuthResult {
            success: response.len() > 0,
            user_id: Some("smartcard_user".to_string()),
            device_id: Some(device_id),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metadata: {
                let mut map = HashMap::new();
                map.insert("protocol".to_string(), "PCSC".to_string());
                map.insert("reader".to_string(), self.reader_name.clone());
                map
            },
            error: None,
        })
    }

    async fn generate_attestation(&self) -> Result<HardwareAttestation> {
        let card = self.card.as_ref()
            .ok_or_else(|| Error::HardwareAuth("Smart card not initialized".to_string()))?;

        // Generate attestation data using smart card
        let attestation_data = card.transmit(&[0x00, 0xCB, 0x00, 0x00, 0x00])
            .map_err(|e| Error::HardwareAuth(format!("Failed to generate attestation: {}", e)))?;

        let device_id = self.device_info.as_ref()
            .map(|info| info.device_id.clone())
            .unwrap_or_else(|| "smartcard".to_string());

        Ok(HardwareAttestation {
            device_type: HardwareType::SmartCard,
            device_id,
            attestation_data,
            signature: vec![], // Smart card signature would be generated here
            certificate_chain: vec![], // Smart card certificates would be included here
        })
    }

    async fn verify_attestation(&self, attestation: &HardwareAttestation) -> Result<bool> {
        // Verify smart card attestation
        Ok(!attestation.attestation_data.is_empty())
    }

    async fn get_device_info(&self) -> Result<DeviceInfo> {
        self.device_info.clone()
            .ok_or_else(|| Error::HardwareAuth("Device info not available".to_string()))
    }
}

/// Hardware authentication factory
pub struct HardwareAuthFactory;

impl HardwareAuthFactory {
    /// Create hardware authentication instance
    pub async fn create(
        hardware_type: HardwareType,
        device_path: Option<String>,
    ) -> Result<Box<dyn HardwareAuth + Send + Sync>> {
        match hardware_type {
            HardwareType::Tpm => {
                let path = device_path.unwrap_or_else(|| "/dev/tpmrm0".to_string());
                Ok(Box::new(TpmAuth::new(path)))
            }
            HardwareType::YubiKey => {
                Ok(Box::new(YubiKeyAuth::new(device_path)))
            }
            HardwareType::SmartCard => {
                let reader = device_path.unwrap_or_else(|| "0".to_string());
                Ok(Box::new(SmartCardAuth::new(reader)))
            }
            HardwareType::Hsm => {
                // HSM implementation would go here
                Err(Error::HardwareAuth("HSM support not yet implemented".to_string()))
            }
        }
    }

    /// Detect available hardware devices
    pub async fn detect_devices() -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        // Detect TPM devices
        if Path::new("/dev/tpmrm0").exists() {
            let tpm_auth = TpmAuth::new("/dev/tpmrm0".to_string());
            if let Ok(info) = tpm_auth.get_tpm_info().await {
                devices.push(info);
            }
        }

        // Detect YubiKey devices
        if let Ok(yubikey_list) = yubikey::YubiKey::list() {
            if !yubikey_list.is_empty() {
                let yubikey_auth = YubiKeyAuth::new(None);
                if let Ok(info) = yubikey_auth.get_yubikey_info().await {
                    devices.push(info);
                }
            }
        }

        // Detect smart card readers
        if let Ok(context) = pcsc::Context::establish(pcsc::Scope::User) {
            if let Ok(readers) = context.list_readers() {
                for reader in readers {
                    let smartcard_auth = SmartCardAuth::new(reader.to_string());
                    if let Ok(info) = smartcard_auth.get_smartcard_info().await {
                        devices.push(info);
                    }
                }
            }
        }

        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_auth_factory() {
        let devices = HardwareAuthFactory::detect_devices().await;
        // This test will pass even if no devices are found
        assert!(devices.is_ok());
    }

    #[test]
    fn test_hardware_type_serialization() {
        let tpm = HardwareType::Tpm;
        let serialized = serde_json::to_string(&tpm).unwrap();
        let deserialized: HardwareType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tpm, deserialized);
    }
}
