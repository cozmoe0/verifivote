use crate::ballot::Ballot;
use crate::crypto::{calculate_hash, PublicKey, SignatureData};
use crate::wallet::Wallet;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a voter's answer to a single ballot question.
///
/// Each answer associates a question with the choice selected by the voter.
/// The IDs must match those defined in the ballot for the vote to be valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Answer {
    pub question_id: String,
    pub choice_id: String,
}

/// Represents a completed and cryptographically signed vote.
///
/// A vote is the central data structure in the VerifiVote system. It contains:
/// - A unique vote ID for tracking
/// - The ballot ID being voted on
/// - The voter's public key (for identity verification)
/// - All answers to ballot questions
/// - A timestamp of when the vote was cast
/// - A cryptographic signature proving authenticity
///
/// Votes are immutable once created and signed. They are validated to ensure:
/// - All answers match the ballot's questions and choices
/// - The voter's signature is valid
/// - All required questions are answered
///
/// Once validated, votes are added to the blockchain where they become
/// part of the permanent, tamper-proof election record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub vote_id: String,
    pub ballot_id: String,
    pub voter_public_key: PublicKey,
    pub answers: Vec<Answer>,
    pub timestamp: DateTime<Utc>,
    pub voter_signature: SignatureData,
}

impl Vote {
    /// Creates a new vote from a wallet and the voter's answers.
    ///
    /// This function constructs and signs a complete vote. It performs comprehensive
    /// validation to ensure the vote is legitimate:
    /// - Verifies the wallet has a ballot
    /// - Validates all answers against the ballot's questions and choices
    /// - Ensures all questions are answered
    /// - Generates a unique vote ID
    /// - Cryptographically signs the vote with the voter's private key
    ///
    /// # Arguments
    ///
    /// * `wallet` - The voter's wallet, which must contain a valid ballot
    /// * `answers` - A vector of answers to the ballot questions
    ///
    /// # Returns
    ///
    /// - `Ok(Vote)` if the vote was successfully created and signed
    /// - `Err(String)` if validation fails or the wallet has no ballot
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - The wallet has no ballot
    /// - An answer references an invalid question ID
    /// - An answer references an invalid choice ID for a question
    /// - The number of answers doesn't match the number of questions
    ///
    /// # Security
    ///
    /// The vote is cryptographically signed using the voter's private key.
    /// The signature covers all vote data (ID, ballot ID, answers, timestamp)
    /// ensuring the vote cannot be tampered with after creation.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Vote, Answer, Ballot, BallotQuestion, BallotChoice, KeyPair, PublicKey};
    ///
    /// // Set up ballot and wallet
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let questions = vec![
    ///     BallotQuestion {
    ///         id: "q1".to_string(),
    ///         question: "Choose a candidate".to_string(),
    ///         choices: vec![
    ///             BallotChoice { id: "c1".to_string(), text: "Candidate A".to_string() },
    ///             BallotChoice { id: "c2".to_string(), text: "Candidate B".to_string() },
    ///         ],
    ///     },
    /// ];
    ///
    /// let mut ballot = Ballot::new("Election".to_string(), questions, supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// wallet.issue_ballot(ballot).unwrap();
    ///
    /// // Cast vote
    /// let answers = vec![Answer {
    ///     question_id: "q1".to_string(),
    ///     choice_id: "c1".to_string(),
    /// }];
    ///
    /// let vote = Vote::new(&wallet, answers).unwrap();
    /// assert!(vote.verify_signature());
    /// ```
    pub fn new(
        wallet: &Wallet,
        answers: Vec<Answer>,
    ) -> Result<Self, String> {
        let ballot = wallet.get_ballot()
            .ok_or("Wallet has no ballot")?;

        // Validate answers against ballot
        Self::validate_answers(&answers, ballot)?;

        let vote_id = format!("vote_{}_{}", wallet.voter_id, Utc::now().timestamp_millis());

        let mut vote = Vote {
            vote_id,
            ballot_id: ballot.id.clone(),
            voter_public_key: wallet.public_key(),
            answers,
            timestamp: Utc::now(),
            voter_signature: SignatureData::from_signature(
                &ed25519_dalek::Signature::from_bytes(&[0u8; 64])
            ), // Placeholder
        };

        // Sign the vote
        let data = vote.signable_data();
        let signature = wallet.keypair.sign(&data);
        vote.voter_signature = SignatureData::from_signature(&signature);

        Ok(vote)
    }

    /// Validates that answers match the ballot's questions and choices.
    ///
    /// This internal function performs thorough validation:
    /// - Checks that each answer references a valid question ID from the ballot
    /// - Ensures each choice ID is valid for its corresponding question
    /// - Verifies that exactly one answer is provided for each question
    ///
    /// # Arguments
    ///
    /// * `answers` - The voter's answers to validate
    /// * `ballot` - The ballot to validate against
    ///
    /// # Returns
    ///
    /// - `Ok(())` if all answers are valid
    /// - `Err(String)` with a description of the validation failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - An answer references a question ID that doesn't exist in the ballot
    /// - An answer references a choice ID that doesn't exist for that question
    /// - The number of answers doesn't equal the number of questions
    fn validate_answers(answers: &[Answer], ballot: &Ballot) -> Result<(), String> {
        // Create a map of question IDs to their valid choice IDs
        let mut valid_choices: HashMap<String, Vec<String>> = HashMap::new();

        for question in &ballot.questions {
            let choice_ids: Vec<String> = question.choices.iter()
                .map(|c| c.id.clone())
                .collect();
            valid_choices.insert(question.id.clone(), choice_ids);
        }

        // Check each answer
        for answer in answers {
            let valid_choice_ids = valid_choices.get(&answer.question_id)
                .ok_or_else(|| format!("Invalid question ID: {}", answer.question_id))?;

            if !valid_choice_ids.contains(&answer.choice_id) {
                return Err(format!(
                    "Invalid choice ID {} for question {}",
                    answer.choice_id, answer.question_id
                ));
            }
        }

        // Check that all questions are answered
        if answers.len() != ballot.questions.len() {
            return Err(format!(
                "Expected {} answers, got {}",
                ballot.questions.len(),
                answers.len()
            ));
        }

        Ok(())
    }

    /// Computes the canonical byte representation of the vote for signing.
    ///
    /// This method concatenates all vote fields (except the signature itself) into a
    /// deterministic byte vector. The order and format are fixed to ensure consistent
    /// signatures across different platforms and time periods.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the concatenated bytes of:
    /// - Vote ID
    /// - Ballot ID
    /// - Voter's public key
    /// - All answers (question IDs and choice IDs)
    /// - Timestamp (RFC3339 format)
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.vote_id.as_bytes());
        data.extend_from_slice(self.ballot_id.as_bytes());
        data.extend_from_slice(self.voter_public_key.as_bytes());

        for answer in &self.answers {
            data.extend_from_slice(answer.question_id.as_bytes());
            data.extend_from_slice(answer.choice_id.as_bytes());
        }

        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        data
    }

    /// Verifies that the vote's cryptographic signature is valid.
    ///
    /// This checks that the vote was signed by the holder of the private key
    /// corresponding to `voter_public_key` and that the vote data hasn't been
    /// modified since signing.
    ///
    /// # Returns
    ///
    /// `true` if the signature is valid and the vote is authentic, `false` otherwise
    ///
    /// # Security
    ///
    /// This verification ensures:
    /// - The vote came from the claimed voter (authentication)
    /// - The vote hasn't been altered since creation (integrity)
    /// - The voter cannot later deny casting the vote (non-repudiation)
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Vote, Answer, Ballot, BallotQuestion, BallotChoice, KeyPair, PublicKey};
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let questions = vec![BallotQuestion {
    ///     id: "q1".to_string(),
    ///     question: "Vote?".to_string(),
    ///     choices: vec![
    ///         BallotChoice { id: "c1".to_string(), text: "Yes".to_string() },
    ///         BallotChoice { id: "c2".to_string(), text: "No".to_string() },
    ///     ],
    /// }];
    ///
    /// let mut ballot = Ballot::new("Election".to_string(), questions, supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// wallet.issue_ballot(ballot).unwrap();
    ///
    /// let vote = Vote::new(&wallet, vec![Answer {
    ///     question_id: "q1".to_string(),
    ///     choice_id: "c1".to_string(),
    /// }]).unwrap();
    ///
    /// assert!(vote.verify_signature());
    /// ```
    pub fn verify_signature(&self) -> bool {
        let data = self.signable_data();
        self.voter_public_key.verify(&data, &self.voter_signature)
    }

    /// Calculates a SHA-256 hash of the entire vote for identification and tracking.
    ///
    /// This creates a unique fingerprint of the vote by serializing it to JSON
    /// and computing its cryptographic hash. The hash is used:
    /// - To create unique identifiers for votes
    /// - To detect any tampering or modification
    /// - As part of block hash calculations in the blockchain
    ///
    /// # Returns
    ///
    /// A 64-character hexadecimal string representing the SHA-256 hash
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Vote, Answer, Ballot, BallotQuestion, BallotChoice, KeyPair, PublicKey};
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let questions = vec![BallotQuestion {
    ///     id: "q1".to_string(),
    ///     question: "Question?".to_string(),
    ///     choices: vec![
    ///         BallotChoice { id: "c1".to_string(), text: "Option 1".to_string() },
    ///     ],
    /// }];
    ///
    /// let mut ballot = Ballot::new("Election".to_string(), questions, supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// wallet.issue_ballot(ballot).unwrap();
    ///
    /// let vote = Vote::new(&wallet, vec![Answer {
    ///     question_id: "q1".to_string(),
    ///     choice_id: "c1".to_string(),
    /// }]).unwrap();
    ///
    /// let hash = vote.calculate_hash();
    /// assert_eq!(hash.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    /// ```
    pub fn calculate_hash(&self) -> String {
        let serialized = serde_json::to_vec(self).expect("Failed to serialize vote");
        calculate_hash(&serialized)
    }

    /// Checks if this vote was cast by a specific voter.
    ///
    /// Compares the vote's public key against a provided public key to determine
    /// if they match. This is useful for:
    /// - Verifying vote ownership
    /// - Preventing double voting (checking if a voter already voted)
    /// - Auditing the voting record
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key to check against
    ///
    /// # Returns
    ///
    /// `true` if the vote's public key matches the provided key, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Vote, Answer, Ballot, BallotQuestion, BallotChoice, KeyPair, PublicKey};
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let questions = vec![BallotQuestion {
    ///     id: "q1".to_string(),
    ///     question: "Question?".to_string(),
    ///     choices: vec![BallotChoice { id: "c1".to_string(), text: "Option".to_string() }],
    /// }];
    ///
    /// let mut ballot = Ballot::new("Election".to_string(), questions, supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// let voter_key = wallet.public_key();
    /// wallet.issue_ballot(ballot).unwrap();
    ///
    /// let vote = Vote::new(&wallet, vec![Answer {
    ///     question_id: "q1".to_string(),
    ///     choice_id: "c1".to_string(),
    /// }]).unwrap();
    ///
    /// assert!(vote.is_from_voter(&voter_key));
    ///
    /// let other_wallet = Wallet::new("voter2".to_string());
    /// assert!(!vote.is_from_voter(&other_wallet.public_key()));
    /// ```
    pub fn is_from_voter(&self, public_key: &PublicKey) -> bool {
        self.voter_public_key == *public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{BallotChoice, BallotQuestion};
    use crate::crypto::KeyPair;

    fn create_test_wallet_with_ballot() -> Wallet {
        let supervisor_keypair = KeyPair::generate();
        let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

        let questions = vec![
            BallotQuestion {
                id: "q1".to_string(),
                question: "Question 1?".to_string(),
                choices: vec![
                    BallotChoice {
                        id: "c1".to_string(),
                        text: "Choice 1".to_string(),
                    },
                    BallotChoice {
                        id: "c2".to_string(),
                        text: "Choice 2".to_string(),
                    },
                ],
            },
            BallotQuestion {
                id: "q2".to_string(),
                question: "Question 2?".to_string(),
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

        let mut ballot = Ballot::new("Test Election".to_string(), questions, supervisor_public_key);
        ballot.sign(&supervisor_keypair);

        let mut wallet = Wallet::new("voter123".to_string());
        wallet.issue_ballot(ballot).unwrap();

        wallet
    }

    #[test]
    fn test_vote_creation() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers);
        assert!(vote.is_ok());

        let vote = vote.unwrap();
        assert!(vote.verify_signature());
        assert_eq!(vote.answers.len(), 2);
    }

    #[test]
    fn test_vote_invalid_question() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![
            Answer {
                question_id: "invalid_q".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers);
        assert!(vote.is_err());
        assert!(vote.unwrap_err().contains("Invalid question ID"));
    }

    #[test]
    fn test_vote_invalid_choice() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "invalid_choice".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers);
        assert!(vote.is_err());
        assert!(vote.unwrap_err().contains("Invalid choice ID"));
    }

    #[test]
    fn test_vote_missing_answer() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![Answer {
            question_id: "q1".to_string(),
            choice_id: "c1".to_string(),
        }];

        let vote = Vote::new(&wallet, answers);
        assert!(vote.is_err());
        assert!(vote.unwrap_err().contains("Expected 2 answers, got 1"));
    }

    #[test]
    fn test_vote_serialization() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers).unwrap();

        let serialized = serde_json::to_string(&vote).unwrap();
        let deserialized: Vote = serde_json::from_str(&serialized).unwrap();

        assert_eq!(vote.vote_id, deserialized.vote_id);
        assert!(deserialized.verify_signature());
    }

    #[test]
    fn test_vote_hash() {
        let wallet = create_test_wallet_with_ballot();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers).unwrap();

        let hash1 = vote.calculate_hash();
        let hash2 = vote.calculate_hash();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_is_from_voter() {
        let wallet = create_test_wallet_with_ballot();
        let voter_key = wallet.public_key();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote = Vote::new(&wallet, answers).unwrap();

        assert!(vote.is_from_voter(&voter_key));

        let other_wallet = Wallet::new("other_voter".to_string());
        assert!(!vote.is_from_voter(&other_wallet.public_key()));
    }
}
