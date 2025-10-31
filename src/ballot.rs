use crate::crypto::{calculate_hash, PublicKey, SignatureData};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a choice in a ballot question
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BallotChoice {
    pub id: String,
    pub text: String,
}

/// Represents a question on the ballot
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BallotQuestion {
    pub id: String,
    pub question: String,
    pub choices: Vec<BallotChoice>,
}

/// Represents a ballot template created by an election supervisor
/// This is the template that will be issued to voters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ballot {
    pub id: String,
    pub election_name: String,
    pub created_at: DateTime<Utc>,
    pub questions: Vec<BallotQuestion>,
    pub supervisor_public_key: PublicKey,
    pub supervisor_signature: SignatureData,
}

impl Ballot {
    /// Creates a new ballot template for an election.
    ///
    /// The ballot is created unsigned and must be signed by the election supervisor
    /// using the [`sign`](Self::sign) method before being issued to voters.
    ///
    /// # Arguments
    ///
    /// * `election_name` - The name of the election (e.g., "2024 General Election")
    /// * `questions` - A vector of ballot questions to be answered by voters
    /// * `supervisor_public_key` - The public key of the election supervisor who will sign the ballot
    ///
    /// # Returns
    ///
    /// A new `Ballot` instance with a placeholder signature that needs to be signed
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Ballot, BallotQuestion, BallotChoice, KeyPair, PublicKey};
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let questions = vec![
    ///     BallotQuestion {
    ///         id: "q1".to_string(),
    ///         question: "Who should be president?".to_string(),
    ///         choices: vec![
    ///             BallotChoice { id: "c1".to_string(), text: "Candidate A".to_string() },
    ///             BallotChoice { id: "c2".to_string(), text: "Candidate B".to_string() },
    ///         ],
    ///     },
    /// ];
    ///
    /// let ballot = Ballot::new("2024 Election".to_string(), questions, supervisor_public_key);
    /// ```
    pub fn new(
        election_name: String,
        questions: Vec<BallotQuestion>,
        supervisor_public_key: PublicKey,
    ) -> Self {
        let id = format!("ballot_{}", Utc::now().timestamp_millis());

        Ballot {
            id,
            election_name,
            created_at: Utc::now(),
            questions,
            supervisor_public_key,
            supervisor_signature: SignatureData::from_signature(
                &ed25519_dalek::Signature::from_bytes(&[0u8; 64])
            ), // Placeholder, will be set by sign()
        }
    }

    /// Computes the canonical byte representation of the ballot for signing.
    ///
    /// This method concatenates all ballot fields (except the signature itself) into a
    /// deterministic byte vector that can be signed or verified. The order and format
    /// are fixed to ensure consistent signatures.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the concatenated bytes of all ballot fields
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(self.election_name.as_bytes());
        data.extend_from_slice(self.created_at.to_rfc3339().as_bytes());

        for question in &self.questions {
            data.extend_from_slice(question.id.as_bytes());
            data.extend_from_slice(question.question.as_bytes());
            for choice in &question.choices {
                data.extend_from_slice(choice.id.as_bytes());
                data.extend_from_slice(choice.text.as_bytes());
            }
        }

        data.extend_from_slice(self.supervisor_public_key.as_bytes());
        data
    }

    /// Signs the ballot with the election supervisor's private key.
    ///
    /// This cryptographically signs the ballot using Ed25519 digital signatures,
    /// proving that the ballot was created and authorized by the supervisor.
    /// This signature can later be verified by anyone with the supervisor's public key.
    ///
    /// # Arguments
    ///
    /// * `keypair` - The supervisor's key pair (must match `supervisor_public_key`)
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Ballot, BallotQuestion, KeyPair, PublicKey};
    ///
    /// let keypair = KeyPair::generate();
    /// let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);
    ///
    /// let mut ballot = Ballot::new("Test Election".to_string(), vec![], public_key);
    /// ballot.sign(&keypair);
    /// assert!(ballot.verify_supervisor_signature());
    /// ```
    pub fn sign(&mut self, keypair: &crate::crypto::KeyPair) {
        let data = self.signable_data();
        let signature = keypair.sign(&data);
        self.supervisor_signature = SignatureData::from_signature(&signature);
    }

    /// Verifies that the ballot's signature is valid and was created by the supervisor.
    ///
    /// This checks the cryptographic signature against the supervisor's public key
    /// to ensure the ballot has not been tampered with and was authorized by the
    /// election supervisor.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Ballot, KeyPair, PublicKey};
    ///
    /// let keypair = KeyPair::generate();
    /// let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);
    ///
    /// let mut ballot = Ballot::new("Election".to_string(), vec![], public_key);
    /// ballot.sign(&keypair);
    ///
    /// assert!(ballot.verify_supervisor_signature());
    /// ```
    pub fn verify_supervisor_signature(&self) -> bool {
        let data = self.signable_data();
        self.supervisor_public_key.verify(&data, &self.supervisor_signature)
    }

    /// Calculates a SHA-256 hash of the entire ballot for identification and tracking.
    ///
    /// This creates a unique fingerprint of the ballot by serializing it to JSON
    /// and computing its hash. Useful for tracking ballots across the system.
    ///
    /// # Returns
    ///
    /// A 64-character hexadecimal string representing the SHA-256 hash
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Ballot, KeyPair, PublicKey};
    ///
    /// let keypair = KeyPair::generate();
    /// let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);
    ///
    /// let ballot = Ballot::new("Election".to_string(), vec![], public_key);
    /// let hash = ballot.calculate_hash();
    /// assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    /// ```
    pub fn calculate_hash(&self) -> String {
        let serialized = serde_json::to_vec(self).expect("Failed to serialize ballot");
        calculate_hash(&serialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn create_test_ballot() -> (Ballot, KeyPair) {
        let keypair = KeyPair::generate();
        let public_key = PublicKey::from_verifying_key(&keypair.verifying_key);

        let questions = vec![
            BallotQuestion {
                id: "q1".to_string(),
                question: "Who should be president?".to_string(),
                choices: vec![
                    BallotChoice {
                        id: "c1".to_string(),
                        text: "Candidate A".to_string(),
                    },
                    BallotChoice {
                        id: "c2".to_string(),
                        text: "Candidate B".to_string(),
                    },
                ],
            },
            BallotQuestion {
                id: "q2".to_string(),
                question: "Approve proposition?".to_string(),
                choices: vec![
                    BallotChoice {
                        id: "c3".to_string(),
                        text: "Yes".to_string(),
                    },
                    BallotChoice {
                        id: "c4".to_string(),
                        text: "No".to_string(),
                    },
                ],
            },
        ];

        let ballot = Ballot::new("2024 General Election".to_string(), questions, public_key);

        (ballot, keypair)
    }

    #[test]
    fn test_ballot_creation() {
        let (ballot, _) = create_test_ballot();

        assert_eq!(ballot.election_name, "2024 General Election");
        assert_eq!(ballot.questions.len(), 2);
        assert_eq!(ballot.questions[0].choices.len(), 2);
    }

    #[test]
    fn test_ballot_signing() {
        let (mut ballot, keypair) = create_test_ballot();

        ballot.sign(&keypair);
        assert!(ballot.verify_supervisor_signature());
    }

    #[test]
    fn test_ballot_verification_fails_with_wrong_key() {
        let (mut ballot, keypair) = create_test_ballot();
        ballot.sign(&keypair);

        // Create a different keypair
        let wrong_keypair = KeyPair::generate();
        ballot.supervisor_public_key = PublicKey::from_verifying_key(&wrong_keypair.verifying_key);

        assert!(!ballot.verify_supervisor_signature());
    }

    #[test]
    fn test_ballot_hash() {
        let (mut ballot, keypair) = create_test_ballot();
        ballot.sign(&keypair);

        let hash1 = ballot.calculate_hash();
        let hash2 = ballot.calculate_hash();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 in hex
    }

    #[test]
    fn test_ballot_serialization() {
        let (mut ballot, keypair) = create_test_ballot();
        ballot.sign(&keypair);

        let serialized = serde_json::to_string(&ballot).unwrap();
        let deserialized: Ballot = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ballot.id, deserialized.id);
        assert_eq!(ballot.election_name, deserialized.election_name);
        assert!(deserialized.verify_supervisor_signature());
    }
}
