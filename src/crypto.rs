use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Represents a cryptographic keypair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generates a new random Ed25519 cryptographic keypair.
    ///
    /// Uses a cryptographically secure random number generator (OS-provided) to
    /// create a new signing key and its corresponding verification key. This is
    /// used to create unique identities for election supervisors and voters.
    ///
    /// # Returns
    ///
    /// A new `KeyPair` with randomly generated keys
    ///
    /// # Security
    ///
    /// Uses `OsRng` which provides cryptographically secure randomness from the
    /// operating system's random number generator.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// let message = b"Hello, world!";
    /// let signature = keypair.sign(message);
    /// ```
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        KeyPair {
            signing_key,
            verifying_key,
        }
    }

    /// Signs a message with the private (signing) key using Ed25519.
    ///
    /// Creates a cryptographic signature that proves the message was signed by
    /// the holder of this keypair. The signature can be verified by anyone with
    /// the corresponding public key.
    ///
    /// # Arguments
    ///
    /// * `message` - The bytes to sign
    ///
    /// # Returns
    ///
    /// An Ed25519 `Signature` that can be verified with the public key
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{KeyPair, PublicKey, SignatureData};
    ///
    /// let keypair = KeyPair::generate();
    /// let message = b"Important message";
    /// let signature = keypair.sign(message);
    ///
    /// let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);
    /// let sig_data = SignatureData::from_signature(&signature);
    /// assert!(public_key.verify(message, &sig_data));
    /// ```
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Returns the public key as a 32-byte array.
    ///
    /// The public key can be safely shared and is used to verify signatures
    /// created by this keypair.
    ///
    /// # Returns
    ///
    /// A fixed-size array of 32 bytes representing the Ed25519 public key
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// Represents a public key for verification only
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Creates a `PublicKey` from an Ed25519 `VerifyingKey`.
    ///
    /// Converts the Ed25519 verifying key into a serializable format that can
    /// be stored in ballots, votes, and blockchain blocks.
    ///
    /// # Arguments
    ///
    /// * `key` - The Ed25519 verifying key to convert
    ///
    /// # Returns
    ///
    /// A new `PublicKey` instance
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        PublicKey {
            bytes: key.to_bytes(),
        }
    }

    /// Creates a `PublicKey` directly from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array representing an Ed25519 public key
    ///
    /// # Returns
    ///
    /// A new `PublicKey` instance
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey { bytes }
    }

    /// Returns a reference to the 32-byte public key.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte array containing the public key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verifies an Ed25519 signature on a message using this public key.
    ///
    /// Checks whether the signature was created by the private key corresponding
    /// to this public key for the given message.
    ///
    /// # Arguments
    ///
    /// * `message` - The original message bytes that were signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid for this message and public key, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{KeyPair, PublicKey, SignatureData};
    ///
    /// let keypair = KeyPair::generate();
    /// let message = b"Sign this";
    /// let signature = keypair.sign(message);
    ///
    /// let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);
    /// let sig_data = SignatureData::from_signature(&signature);
    /// assert!(public_key.verify(message, &sig_data));
    /// ```
    pub fn verify(&self, message: &[u8], signature: &SignatureData) -> bool {
        match VerifyingKey::from_bytes(&self.bytes) {
            Ok(verifying_key) => {
                let sig = Signature::from_bytes(&signature.bytes);
                verifying_key.verify(message, &sig).is_ok()
            }
            Err(_) => false,
        }
    }

    /// Converts the public key to a hexadecimal string representation.
    ///
    /// # Returns
    ///
    /// A 64-character hexadecimal string (32 bytes = 64 hex characters)
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Creates a `PublicKey` from a hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - A 64-character hexadecimal string representing the public key
    ///
    /// # Returns
    ///
    /// `Ok(PublicKey)` if the hex string is valid, `Err(String)` otherwise
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The hex string is invalid
    /// - The decoded bytes are not exactly 32 bytes long
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Invalid hex: {}", e))?;

        if bytes.len() != 32 {
            return Err("Invalid key length".to_string());
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(PublicKey { bytes: key_bytes })
    }
}

/// Serializable signature data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
    bytes: [u8; 64],
}

impl Serialize for SignatureData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.bytes))
    }
}

impl<'de> Deserialize<'de> for SignatureData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;

        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid signature length"));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&bytes);

        Ok(SignatureData { bytes: sig_bytes })
    }
}

impl SignatureData {
    /// Creates `SignatureData` from an Ed25519 signature.
    ///
    /// Converts an Ed25519 signature into a serializable format that can be
    /// stored in JSON and transmitted across the network.
    ///
    /// # Arguments
    ///
    /// * `sig` - The Ed25519 signature to convert
    ///
    /// # Returns
    ///
    /// A new `SignatureData` instance
    pub fn from_signature(sig: &Signature) -> Self {
        SignatureData {
            bytes: sig.to_bytes(),
        }
    }

    /// Returns a reference to the 64-byte signature.
    ///
    /// # Returns
    ///
    /// A reference to the 64-byte array containing the Ed25519 signature
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// Converts the signature to a hexadecimal string representation.
    ///
    /// # Returns
    ///
    /// A 128-character hexadecimal string (64 bytes = 128 hex characters)
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}

/// Calculates the SHA-256 hash of arbitrary data.
///
/// This function is used throughout the system to create cryptographic hashes
/// of votes, blocks, and ballots for integrity verification and identification.
///
/// # Arguments
///
/// * `data` - The bytes to hash
///
/// # Returns
///
/// A 64-character hexadecimal string representing the SHA-256 hash (32 bytes = 64 hex chars)
///
/// # Example
///
/// ```
/// use verifivote::crypto::calculate_hash;
///
/// let data = b"Hello, world!";
/// let hash = calculate_hash(data);
/// assert_eq!(hash.len(), 64);
/// ```
pub fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Test message for signing";

        let signature = keypair.sign(message);
        let sig_data = SignatureData::from_signature(&signature);
        let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);

        assert!(public_key.verify(message, &sig_data));
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = KeyPair::generate();
        let message = b"Original message";
        let wrong_message = b"Different message";

        let signature = keypair.sign(message);
        let sig_data = SignatureData::from_signature(&signature);
        let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);

        assert!(!public_key.verify(wrong_message, &sig_data));
    }

    #[test]
    fn test_hash_calculation() {
        let data = b"Test data";
        let hash1 = calculate_hash(data);
        let hash2 = calculate_hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_different_data() {
        let data1 = b"Data 1";
        let data2 = b"Data 2";

        let hash1 = calculate_hash(data1);
        let hash2 = calculate_hash(data2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_public_key_hex() {
        let keypair = KeyPair::generate();
        let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);

        let hex_str = public_key.to_hex();
        assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars

        let recovered = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(public_key, recovered);
    }
}
