//! Cryptographic primitives for LSFTP protocol
//! 
//! This module provides post-quantum and hybrid cryptographic algorithms
//! as specified in the LSFTP protocol specification.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use ring::signature::KeyPair;
use std::time::SystemTime;
use libc;

/// Supported key exchange algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// Classical ECDH P-256 (to be phased out)
    EcdheP256,
    /// Hybrid ECDH P-256 + ML-KEM-768
    HybridEcdheP256MlKem768,
    /// Pure post-quantum ML-KEM-768
    MlKem768,
    /// Pure post-quantum ML-KEM-1024 (paranoid mode)
    MlKem1024,
}

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Classical Ed25519 (to be phased out)
    Ed25519,
    /// Hybrid Ed25519 + ML-DSA-65
    HybridEd25519MlDsa65,
    /// Pure post-quantum ML-DSA-65
    MlDsa65,
    /// Pure post-quantum ML-DSA-87 (paranoid mode)
    MlDsa87,
}

/// Supported AEAD algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (recommended)
    ChaCha20Poly1305,
    /// AES-256-GCM (hardware accelerated)
    Aes256Gcm,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// BLAKE3 (fast, recommended)
    Blake3,
    /// SHA3-256 (NIST standard)
    Sha3256,
}

/// Cryptographic suite configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSuite {
    pub kem: KemAlgorithm,
    pub signature: SignatureAlgorithm,
    pub aead: AeadAlgorithm,
    pub hash: HashAlgorithm,
    pub version: u16,
}

impl Default for CryptoSuite {
    fn default() -> Self {
        Self {
            kem: KemAlgorithm::HybridEcdheP256MlKem768,
            signature: SignatureAlgorithm::HybridEd25519MlDsa65,
            aead: AeadAlgorithm::ChaCha20Poly1305,
            hash: HashAlgorithm::Blake3,
            version: 1,
        }
    }
}

/// Key exchange result
#[derive(Debug)]
pub struct KeyExchange {
    pub shared_secret: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: KemAlgorithm,
}

/// Signature result
#[derive(Debug)]
pub struct Signature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
}

/// Secure private key storage
pub struct PrivateKey {
    pub algorithm: KemAlgorithm,
    pub key_material: Vec<u8>,
    pub created_at: SystemTime,
}

impl PrivateKey {
    pub fn new(algorithm: KemAlgorithm, material: Vec<u8>) -> Result<Self> {
        // Lock memory pages to prevent swap (Linux only)
        unsafe {
            if libc::mlock(material.as_ptr() as *const _, material.len()) != 0 {
                return Err(Error::System("Failed to lock memory pages".to_string()));
            }
        }

        Ok(Self {
            algorithm,
            key_material: material,
            created_at: SystemTime::now(),
        })
    }

    pub fn generate(algorithm: KemAlgorithm) -> Result<Self> {
        let material = match algorithm {
            KemAlgorithm::EcdheP256 => {
                // Generate ECDH P-256 key pair
                let rng = ring::rand::SystemRandom::new();
                let key_pair = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::X25519,
                    &rng,
                )?;
                key_pair.compute_public_key()?.as_ref().to_vec()
            }
            KemAlgorithm::HybridEcdheP256MlKem768 => {
                // Generate hybrid key pair
                let mut material = Vec::new();
                
                // Classical part
                let rng = ring::rand::SystemRandom::new();
                let classical_key = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::X25519,
                    &rng,
                )?;
                material.extend_from_slice(classical_key.compute_public_key()?.as_ref());
                
                // Post-quantum part (placeholder for ML-KEM-768)
                // TODO: Implement actual ML-KEM-768 key generation
                let pq_key = vec![0u8; 1184]; // ML-KEM-768 public key size
                material.extend_from_slice(&pq_key);
                
                material
            }
            KemAlgorithm::MlKem768 => {
                // Pure post-quantum ML-KEM-768
                // TODO: Implement actual ML-KEM-768 key generation
                vec![0u8; 1184] // ML-KEM-768 public key size
            }
            KemAlgorithm::MlKem1024 => {
                // Pure post-quantum ML-KEM-1024
                // TODO: Implement actual ML-KEM-1024 key generation
                vec![0u8; 1568] // ML-KEM-1024 public key size
            }
        };

        Self::new(algorithm, material)
    }
}

/// Cryptographic operations trait
pub trait CryptoOperations {
    fn perform_key_exchange(&self, peer_public_key: &[u8]) -> Result<KeyExchange>;
    fn sign(&self, message: &[u8]) -> Result<Signature>;
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>;
    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>>;
    fn hash(&self, data: &[u8]) -> Result<Vec<u8>>;
}

impl CryptoOperations for CryptoSuite {
    fn perform_key_exchange(&self, peer_public_key: &[u8]) -> Result<KeyExchange> {
        match self.kem {
            KemAlgorithm::EcdheP256 => {
                // Classical ECDH key exchange
                let rng = ring::rand::SystemRandom::new();
                let private_key = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::X25519,
                    &rng,
                )?;
                
                let public_key = private_key.compute_public_key()?;
                let shared_secret = ring::agreement::agree_ephemeral(
                    private_key,
                    &ring::agreement::UnparsedPublicKey::new(
                        &ring::agreement::X25519,
                        peer_public_key,
                    ),
                    |key_material| Ok::<Vec<u8>, ring::error::Unspecified>(key_material.to_vec()),
                )??;

                Ok(KeyExchange {
                    shared_secret,
                    public_key: public_key.as_ref().to_vec(),
                    algorithm: self.kem,
                })
            }
            KemAlgorithm::HybridEcdheP256MlKem768 => {
                // Hybrid key exchange
                // TODO: Implement hybrid classical + post-quantum key exchange
                Err(Error::Crypto("Hybrid key exchange not yet implemented".to_string()))
            }
            KemAlgorithm::MlKem768 | KemAlgorithm::MlKem1024 => {
                // Pure post-quantum key exchange
                // TODO: Implement ML-KEM key exchange
                Err(Error::Crypto("Post-quantum key exchange not yet implemented".to_string()))
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self.signature {
            SignatureAlgorithm::Ed25519 => {
                // Classical Ed25519 signature
                let rng = ring::rand::SystemRandom::new();
                let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
                let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
                let signature = key_pair.sign(message);
                
                Ok(Signature {
                    signature: signature.as_ref().to_vec(),
                    public_key: key_pair.public_key().as_ref().to_vec(),
                    algorithm: self.signature,
                })
            }
            SignatureAlgorithm::HybridEd25519MlDsa65 => {
                // Hybrid signature
                // TODO: Implement hybrid classical + post-quantum signature
                Err(Error::Crypto("Hybrid signature not yet implemented".to_string()))
            }
            SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
                // Pure post-quantum signature
                // TODO: Implement ML-DSA signature
                Err(Error::Crypto("Post-quantum signature not yet implemented".to_string()))
            }
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        match self.signature {
            SignatureAlgorithm::Ed25519 => {
                let public_key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ED25519,
                    public_key,
                );
                Ok(public_key.verify(message, signature).is_ok())
            }
            SignatureAlgorithm::HybridEd25519MlDsa65 => {
                // TODO: Implement hybrid signature verification
                Err(Error::Crypto("Hybrid signature verification not yet implemented".to_string()))
            }
            SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
                // TODO: Implement post-quantum signature verification
                Err(Error::Crypto("Post-quantum signature verification not yet implemented".to_string()))
            }
        }
    }

    fn encrypt(&self, plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self.aead {
            AeadAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
                
                let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
                let nonce = Nonce::from_slice(nonce);
                
                let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
                ciphertext.extend_from_slice(plaintext);
                
                cipher.encrypt_in_place(nonce, b"", &mut ciphertext)
                    .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;
                
                Ok(ciphertext)
            }
            AeadAlgorithm::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadInPlace};
                
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
                let nonce = Nonce::from_slice(nonce);
                
                let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
                ciphertext.extend_from_slice(plaintext);
                
                cipher.encrypt_in_place(nonce, b"", &mut ciphertext)
                    .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;
                
                Ok(ciphertext)
            }
        }
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        match self.aead {
            AeadAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
                
                let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
                let nonce = Nonce::from_slice(nonce);
                
                let mut plaintext = ciphertext.to_vec();
                cipher.decrypt_in_place(nonce, b"", &mut plaintext)
                    .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))?;
                
                Ok(plaintext)
            }
            AeadAlgorithm::Aes256Gcm => {
                use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadInPlace};
                
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
                let nonce = Nonce::from_slice(nonce);
                
                let mut plaintext = ciphertext.to_vec();
                cipher.decrypt_in_place(nonce, b"", &mut plaintext)
                    .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))?;
                
                Ok(plaintext)
            }
        }
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.hash {
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(data);
                Ok(hash.as_bytes().to_vec())
            }
            HashAlgorithm::Sha3256 => {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                Ok(hasher.finalize().to_vec())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_suite_default() {
        let suite = CryptoSuite::default();
        assert_eq!(suite.kem, KemAlgorithm::HybridEcdheP256MlKem768);
        assert_eq!(suite.signature, SignatureAlgorithm::HybridEd25519MlDsa65);
        assert_eq!(suite.aead, AeadAlgorithm::ChaCha20Poly1305);
        assert_eq!(suite.hash, HashAlgorithm::Blake3);
    }

    #[test]
    fn test_hash_operations() {
        let suite = CryptoSuite::default();
        let data = b"test data";
        
        let hash = suite.hash(data).unwrap();
        assert_eq!(hash.len(), 32); // BLAKE3 output size
    }

    #[test]
    fn test_encrypt_decrypt() {
        let suite = CryptoSuite::default();
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 12];
        let plaintext = b"secret message";
        
        let ciphertext = suite.encrypt(plaintext, &key, &nonce).unwrap();
        let decrypted = suite.decrypt(&ciphertext, &key, &nonce).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}
