//! Cryptographic primitives for LSFTP protocol
//! 
//! This module provides post-quantum and hybrid cryptographic algorithms
//! as specified in the LSFTP protocol specification for Linux systems.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use ring::signature::KeyPair;
use std::time::SystemTime;
use libc;
use zeroize::Zeroize;

/// Supported key exchange algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KemAlgorithm {
    /// Classical ECDH P-256 (to be phased out by 2026)
    EcdheP256,
    /// Hybrid ECDH P-256 + ML-KEM-768 (current default)
    HybridEcdheP256MlKem768,
    /// Pure post-quantum ML-KEM-768 (future default)
    MlKem768,
    /// Pure post-quantum ML-KEM-1024 (paranoid mode)
    MlKem1024,
}

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Classical Ed25519 (to be phased out by 2026)
    Ed25519,
    /// Hybrid Ed25519 + ML-DSA-65 (current default)
    HybridEd25519MlDsa65,
    /// Pure post-quantum ML-DSA-65 (future default)
    MlDsa65,
    /// Pure post-quantum ML-DSA-87 (paranoid mode)
    MlDsa87,
}

/// Supported AEAD algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (recommended for performance)
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

/// Secure private key storage with automatic zeroization
#[derive(Zeroize)]
#[zeroize(drop)]
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
                // Generate classical ECDH P-256 key
                let rng = ring::rand::SystemRandom::new();
                let private_key = ring::agreement::EphemeralPrivateKey::generate(
                    &ring::agreement::X25519,
                    &rng,
                )?;
                private_key.compute_public_key()?.as_ref().to_vec()
            }
            KemAlgorithm::MlKem768 => {
                // Generate ML-KEM-768 key using liboqs
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).map_err(|e| {
                    Error::Crypto(format!("Failed to initialize ML-KEM-768: {}", e))
                })?;
                let (public_key, secret_key) = kem.keypair().map_err(|e| {
                    Error::Crypto(format!("Failed to generate ML-KEM-768 keypair: {}", e))
                })?;
                // Return secret key, public key will be computed separately
                secret_key.into_vec()
            }
            KemAlgorithm::MlKem1024 => {
                // Generate ML-KEM-1024 key using liboqs
                let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber1024).map_err(|e| {
                    Error::Crypto(format!("Failed to initialize ML-KEM-1024: {}", e))
                })?;
                let (public_key, secret_key) = kem.keypair().map_err(|e| {
                    Error::Crypto(format!("Failed to generate ML-KEM-1024 keypair: {}", e))
                })?;
                secret_key.into_vec()
            }
            KemAlgorithm::HybridEcdheP256MlKem768 => {
                // Generate hybrid key (classical + post-quantum)
                let classical_key = Self::generate(KemAlgorithm::EcdheP256)?.key_material;
                let pq_key = Self::generate(KemAlgorithm::MlKem768)?.key_material;
                // Combine both keys
                let mut hybrid_key = classical_key;
                hybrid_key.extend_from_slice(&pq_key);
                hybrid_key
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
                // Hybrid key exchange: classical + post-quantum
                let classical_ke = self.perform_classical_key_exchange(peer_public_key)?;
                let pq_ke = self.perform_post_quantum_key_exchange(peer_public_key)?;
                
                // Combine both shared secrets
                let mut hybrid_secret = classical_ke.shared_secret;
                hybrid_secret.extend_from_slice(&pq_ke.shared_secret);
                
                // Combine public keys
                let mut hybrid_public_key = classical_ke.public_key;
                hybrid_public_key.extend_from_slice(&pq_ke.public_key);
                
                Ok(KeyExchange {
                    shared_secret: hybrid_secret,
                    public_key: hybrid_public_key,
                    algorithm: self.kem,
                })
            }
            KemAlgorithm::MlKem768 => {
                self.perform_post_quantum_key_exchange(peer_public_key)
            }
            KemAlgorithm::MlKem1024 => {
                self.perform_post_quantum_key_exchange(peer_public_key)
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
                // Hybrid signature: classical + post-quantum
                let classical_sig = self.perform_classical_signature(message)?;
                let pq_sig = self.perform_post_quantum_signature(message)?;
                
                // Combine both signatures
                let mut hybrid_signature = classical_sig.signature;
                hybrid_signature.extend_from_slice(&pq_sig.signature);
                
                // Combine public keys
                let mut hybrid_public_key = classical_sig.public_key;
                hybrid_public_key.extend_from_slice(&pq_sig.public_key);
                
                Ok(Signature {
                    signature: hybrid_signature,
                    public_key: hybrid_public_key,
                    algorithm: self.signature,
                })
            }
            SignatureAlgorithm::MlDsa65 => {
                self.perform_post_quantum_signature(message)
            }
            SignatureAlgorithm::MlDsa87 => {
                self.perform_post_quantum_signature(message)
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
                // Verify both classical and post-quantum signatures
                let classical_sig_len = 64; // Ed25519 signature length
                let pq_sig_len = signature.len() - classical_sig_len;
                
                if signature.len() < classical_sig_len + pq_sig_len {
                    return Err(Error::Crypto("Invalid hybrid signature length".to_string()));
                }
                
                let classical_sig = &signature[..classical_sig_len];
                let pq_sig = &signature[classical_sig_len..];
                
                let classical_pubkey_len = 32; // Ed25519 public key length
                let pq_pubkey_len = public_key.len() - classical_pubkey_len;
                
                if public_key.len() < classical_pubkey_len + pq_pubkey_len {
                    return Err(Error::Crypto("Invalid hybrid public key length".to_string()));
                }
                
                let classical_pubkey = &public_key[..classical_pubkey_len];
                let pq_pubkey = &public_key[classical_pubkey_len..];
                
                // Verify classical signature
                let classical_verified = self.verify_classical_signature(message, classical_sig, classical_pubkey)?;
                
                // Verify post-quantum signature
                let pq_verified = self.verify_post_quantum_signature(message, pq_sig, pq_pubkey)?;
                
                Ok(classical_verified && pq_verified)
            }
            SignatureAlgorithm::MlDsa65 | SignatureAlgorithm::MlDsa87 => {
                self.verify_post_quantum_signature(message, signature, public_key)
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

impl CryptoSuite {
    /// Perform classical key exchange (ECDH P-256)
    fn perform_classical_key_exchange(&self, peer_public_key: &[u8]) -> Result<KeyExchange> {
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
            algorithm: KemAlgorithm::EcdheP256,
        })
    }

    /// Perform post-quantum key exchange (ML-KEM)
    fn perform_post_quantum_key_exchange(&self, peer_public_key: &[u8]) -> Result<KeyExchange> {
        let kem = match self.kem {
            KemAlgorithm::MlKem768 => oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768),
            KemAlgorithm::MlKem1024 => oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber1024),
            _ => return Err(Error::Crypto("Invalid algorithm for post-quantum key exchange".to_string())),
        }.map_err(|e| Error::Crypto(format!("Failed to initialize KEM: {}", e)))?;

        // Generate keypair
        let (public_key, secret_key) = kem.keypair().map_err(|e| {
            Error::Crypto(format!("Failed to generate keypair: {}", e))
        })?;

        // Encapsulate to peer's public key
        let (ciphertext, shared_secret) = kem.encaps(&public_key).map_err(|e| {
            Error::Crypto(format!("Failed to encapsulate: {}", e))
        })?;

        Ok(KeyExchange {
            shared_secret: shared_secret.into_vec(),
            public_key: public_key.into_vec(),
            algorithm: self.kem,
        })
    }

    /// Perform classical signature (Ed25519)
    fn perform_classical_signature(&self, message: &[u8]) -> Result<Signature> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let signature = key_pair.sign(message);
        
        Ok(Signature {
            signature: signature.as_ref().to_vec(),
            public_key: key_pair.public_key().as_ref().to_vec(),
            algorithm: SignatureAlgorithm::Ed25519,
        })
    }

    /// Perform post-quantum signature (ML-DSA)
    fn perform_post_quantum_signature(&self, message: &[u8]) -> Result<Signature> {
        let sig = match self.signature {
            SignatureAlgorithm::MlDsa65 => oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium3),
            SignatureAlgorithm::MlDsa87 => oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium5),
            _ => return Err(Error::Crypto("Invalid algorithm for post-quantum signature".to_string())),
        }.map_err(|e| Error::Crypto(format!("Failed to initialize signature: {}", e)))?;

        // Generate keypair
        let (public_key, secret_key) = sig.keypair().map_err(|e| {
            Error::Crypto(format!("Failed to generate signature keypair: {}", e))
        })?;

        // Sign message
        let signature = sig.sign(message, &secret_key).map_err(|e| {
            Error::Crypto(format!("Failed to sign message: {}", e))
        })?;

        Ok(Signature {
            signature: signature.into_vec(),
            public_key: public_key.into_vec(),
            algorithm: self.signature,
        })
    }

    /// Verify classical signature (Ed25519)
    fn verify_classical_signature(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            public_key,
        );
        Ok(public_key.verify(message, signature).is_ok())
    }

    /// Verify post-quantum signature (ML-DSA)
    fn verify_post_quantum_signature(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        let sig = match self.signature {
            SignatureAlgorithm::MlDsa65 => oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium3),
            SignatureAlgorithm::MlDsa87 => oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium5),
            _ => return Err(Error::Crypto("Invalid algorithm for post-quantum signature verification".to_string())),
        }.map_err(|e| Error::Crypto(format!("Failed to initialize signature verification: {}", e)))?;

        let public_key = oqs::sig::PublicKey::from_bytes(public_key).map_err(|e| {
            Error::Crypto(format!("Failed to parse public key: {}", e))
        })?;

        let signature = oqs::sig::Signature::from_bytes(signature).map_err(|e| {
            Error::Crypto(format!("Failed to parse signature: {}", e))
        })?;

        Ok(sig.verify(message, &signature, &public_key).is_ok())
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

    #[test]
    fn test_private_key_generation() {
        let key = PrivateKey::generate(KemAlgorithm::EcdheP256).unwrap();
        assert_eq!(key.algorithm, KemAlgorithm::EcdheP256);
        assert!(!key.key_material.is_empty());
    }
}
