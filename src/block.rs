use crate::crypto::calculate_hash;
use crate::vote::Vote;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a block in the blockchain containing votes and proof-of-work.
///
/// A block is a fundamental unit of the blockchain that groups multiple votes
/// together into an immutable record. Each block contains:
/// - An index indicating its position in the chain
/// - A timestamp of when it was created
/// - A collection of votes to be recorded
/// - A hash of the previous block (creating the chain)
/// - Its own hash (fingerprint of all block data)
/// - A nonce used for proof-of-work mining
///
/// Blocks are linked together through their hashes, forming a tamper-evident
/// chain. Any modification to a block would change its hash, breaking the
/// chain and revealing the tampering.
///
/// The proof-of-work mechanism (mining) ensures that blocks cannot be easily
/// created or modified, providing additional security against attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub votes: Vec<Vote>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

impl Block {
    /// Creates a new block with the given votes and links it to the previous block.
    ///
    /// This function constructs a new block in the blockchain. The block is created
    /// with a timestamp of the current time and an initial nonce of 0. The block's
    /// hash is calculated immediately but may need to be recalculated during mining.
    ///
    /// # Arguments
    ///
    /// * `index` - The position of this block in the chain (genesis block is 0)
    /// * `votes` - A vector of votes to include in this block
    /// * `previous_hash` - The hash of the previous block in the chain (use "0" for genesis)
    ///
    /// # Returns
    ///
    /// A new `Block` instance with the specified data and a calculated hash
    ///
    /// # Note
    ///
    /// After creating a block, you typically need to call [`mine`](Self::mine) to
    /// perform proof-of-work before adding the block to the blockchain.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let votes = vec![]; // In practice, include actual votes
    /// let block = Block::new(1, votes, "previous_block_hash".to_string());
    ///
    /// assert_eq!(block.index, 1);
    /// assert_eq!(block.previous_hash, "previous_block_hash");
    /// assert!(block.is_hash_valid());
    /// ```
    pub fn new(index: u64, votes: Vec<Vote>, previous_hash: String) -> Self {
        let timestamp = Utc::now();
        let nonce = 0;

        let mut block = Block {
            index,
            timestamp,
            votes,
            previous_hash,
            hash: String::new(),
            nonce,
        };

        block.hash = block.calculate_hash();
        block
    }

    /// Creates the genesis block (the first block in the blockchain).
    ///
    /// The genesis block is a special block that serves as the foundation of the
    /// blockchain. It has:
    /// - An index of 0
    /// - No votes (empty vote list)
    /// - A previous hash of "0" (since there is no previous block)
    ///
    /// Every blockchain must start with a genesis block.
    ///
    /// # Returns
    ///
    /// A new genesis `Block` at index 0 with no votes
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let genesis = Block::genesis();
    ///
    /// assert_eq!(genesis.index, 0);
    /// assert_eq!(genesis.previous_hash, "0");
    /// assert_eq!(genesis.votes.len(), 0);
    /// assert!(genesis.is_hash_valid());
    /// ```
    pub fn genesis() -> Self {
        Block::new(0, vec![], "0".to_string())
    }

    /// Calculates the cryptographic hash (fingerprint) of this block.
    ///
    /// This method computes a SHA-256 hash of all the block's data including:
    /// - Block index
    /// - Timestamp
    /// - Previous block's hash
    /// - Nonce (for proof-of-work)
    /// - All votes in the block (via their hashes)
    ///
    /// The hash serves multiple purposes:
    /// - Uniquely identifies the block
    /// - Links blocks together in the chain
    /// - Detects any tampering (changing any data changes the hash)
    /// - Provides the basis for proof-of-work mining
    ///
    /// # Returns
    ///
    /// A 64-character hexadecimal string representing the SHA-256 hash
    ///
    /// # Note
    ///
    /// The hash is deterministic - the same block data always produces the same hash.
    /// This property is essential for blockchain integrity verification.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let block = Block::new(1, vec![], "prev_hash".to_string());
    /// let hash1 = block.calculate_hash();
    /// let hash2 = block.calculate_hash();
    ///
    /// assert_eq!(hash1, hash2); // Same block = same hash
    /// assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    /// ```
    pub fn calculate_hash(&self) -> String {
        let mut data = Vec::new();

        data.extend_from_slice(&self.index.to_le_bytes());
        data.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        data.extend_from_slice(self.previous_hash.as_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());

        // Include all vote hashes
        for vote in &self.votes {
            data.extend_from_slice(vote.calculate_hash().as_bytes());
        }

        calculate_hash(&data)
    }

    /// Verifies that all votes in the block have valid cryptographic signatures.
    ///
    /// This function checks each vote in the block to ensure it was legitimately
    /// signed by the voter who cast it. This is critical for maintaining election
    /// integrity - all votes must be authenticated before being accepted into the
    /// blockchain.
    ///
    /// # Returns
    ///
    /// `true` if all votes have valid signatures, `false` if any vote has an invalid signature
    ///
    /// # Security
    ///
    /// This verification ensures that:
    /// - All votes were cast by legitimate voters with valid private keys
    /// - No votes have been tampered with after being signed
    /// - The block only contains authentic, verified votes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use verifivote::Block;
    ///
    /// // Assume block contains votes
    /// let block = Block::new(1, vec![], "prev".to_string());
    ///
    /// if block.verify_votes() {
    ///     println!("All votes in the block are valid");
    /// } else {
    ///     println!("Block contains invalid votes!");
    /// }
    /// ```
    pub fn verify_votes(&self) -> bool {
        self.votes.iter().all(|vote| vote.verify_signature())
    }

    /// Checks if the block's stored hash matches its calculated hash.
    ///
    /// This verification ensures that the block's data hasn't been tampered with
    /// since the hash was computed. If any field in the block is modified, the
    /// recalculated hash will differ from the stored hash, revealing the tampering.
    ///
    /// # Returns
    ///
    /// `true` if the stored hash matches the calculated hash, `false` otherwise
    ///
    /// # Security
    ///
    /// This is a fundamental integrity check. A mismatch indicates either:
    /// - The block has been tampered with after creation
    /// - The hash was not properly calculated when the block was created
    /// - Data corruption has occurred
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let block = Block::new(1, vec![], "prev".to_string());
    /// assert!(block.is_hash_valid());
    ///
    /// // If someone modifies the block data, the hash becomes invalid
    /// // let mut tampered_block = block.clone();
    /// // tampered_block.nonce = 999;
    /// // assert!(!tampered_block.is_hash_valid()); // Hash no longer matches
    /// ```
    pub fn is_hash_valid(&self) -> bool {
        self.hash == self.calculate_hash()
    }

    /// Returns the number of votes contained in this block.
    ///
    /// # Returns
    ///
    /// The count of votes stored in this block
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let block = Block::new(1, vec![], "prev".to_string());
    /// assert_eq!(block.vote_count(), 0);
    /// ```
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Mines the block using proof-of-work to find a valid hash.
    ///
    /// Mining is the process of finding a nonce value that, when included in the
    /// block's hash calculation, produces a hash that starts with a specific number
    /// of leading zeros (determined by the difficulty parameter).
    ///
    /// This computational work serves several purposes:
    /// - Makes it expensive to create or modify blocks (security)
    /// - Provides consensus in distributed systems
    /// - Rate-limits block creation
    /// - Makes blockchain tampering computationally infeasible
    ///
    /// The function increments the nonce and recalculates the hash repeatedly
    /// until a valid hash is found.
    ///
    /// # Arguments
    ///
    /// * `difficulty` - The number of leading zeros required in the hash
    ///                  (higher difficulty = more computational work)
    ///
    /// # Performance
    ///
    /// Mining time increases exponentially with difficulty:
    /// - Difficulty 1: Very fast (< 1 second)
    /// - Difficulty 2: Fast (< 1 second)
    /// - Difficulty 3: Moderate (a few seconds)
    /// - Difficulty 4: Slow (tens of seconds)
    /// - Difficulty 5+: Very slow (minutes to hours)
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let mut block = Block::new(1, vec![], "prev".to_string());
    ///
    /// // Mine with difficulty 2 (hash must start with "00")
    /// block.mine(2);
    ///
    /// assert!(block.hash.starts_with("00"));
    /// assert!(block.verify_proof_of_work(2));
    /// ```
    pub fn mine(&mut self, difficulty: usize) {
        let target = "0".repeat(difficulty);

        loop {
            self.hash = self.calculate_hash();
            if self.hash.starts_with(&target) {
                break;
            }
            self.nonce += 1;
        }
    }

    /// Verifies that the block's proof-of-work meets the required difficulty.
    ///
    /// This function checks that:
    /// 1. The block's hash starts with the required number of leading zeros
    /// 2. The hash is valid (matches the block's data)
    ///
    /// This verification is essential when validating blocks received from other
    /// sources or when verifying the integrity of the entire blockchain.
    ///
    /// # Arguments
    ///
    /// * `difficulty` - The minimum number of leading zeros required
    ///
    /// # Returns
    ///
    /// `true` if the block's hash meets or exceeds the difficulty requirement
    /// and is valid, `false` otherwise
    ///
    /// # Security
    ///
    /// This verification ensures that:
    /// - The block creator performed the required computational work
    /// - The block wasn't created too easily (which could enable spam/attacks)
    /// - The blockchain's security guarantees are maintained
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Block;
    ///
    /// let mut block = Block::new(1, vec![], "prev".to_string());
    /// block.mine(2);
    ///
    /// assert!(block.verify_proof_of_work(2));  // Passes difficulty 2
    /// assert!(block.verify_proof_of_work(1));  // Also passes lower difficulty
    /// assert!(!block.verify_proof_of_work(3)); // Fails higher difficulty
    /// ```
    pub fn verify_proof_of_work(&self, difficulty: usize) -> bool {
        let target = "0".repeat(difficulty);
        self.hash.starts_with(&target) && self.is_hash_valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{Ballot, BallotChoice, BallotQuestion};
    use crate::crypto::{KeyPair, PublicKey};
    use crate::vote::Answer;
    use crate::wallet::Wallet;

    fn create_test_vote() -> Vote {
        let supervisor_keypair = KeyPair::generate();
        let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

        let questions = vec![BallotQuestion {
            id: "q1".to_string(),
            question: "Test?".to_string(),
            choices: vec![
                BallotChoice {
                    id: "c1".to_string(),
                    text: "Yes".to_string(),
                },
                BallotChoice {
                    id: "c2".to_string(),
                    text: "No".to_string(),
                },
            ],
        }];

        let mut ballot = Ballot::new("Test".to_string(), questions, supervisor_public_key);
        ballot.sign(&supervisor_keypair);

        let mut wallet = Wallet::new("voter1".to_string());
        wallet.issue_ballot(ballot).unwrap();

        let answers = vec![Answer {
            question_id: "q1".to_string(),
            choice_id: "c1".to_string(),
        }];

        Vote::new(&wallet, answers).unwrap()
    }

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis();

        assert_eq!(genesis.index, 0);
        assert_eq!(genesis.previous_hash, "0");
        assert_eq!(genesis.votes.len(), 0);
        assert!(genesis.is_hash_valid());
    }

    #[test]
    fn test_block_creation() {
        let vote = create_test_vote();
        let block = Block::new(1, vec![vote], "previous_hash".to_string());

        assert_eq!(block.index, 1);
        assert_eq!(block.votes.len(), 1);
        assert_eq!(block.previous_hash, "previous_hash");
        assert!(block.is_hash_valid());
    }

    #[test]
    fn test_block_hash_changes_with_data() {
        let vote1 = create_test_vote();
        let vote2 = create_test_vote();

        let block1 = Block::new(1, vec![vote1], "prev".to_string());
        let block2 = Block::new(1, vec![vote2], "prev".to_string());

        // Even though structure is the same, different votes should produce different hashes
        // (due to timestamps in votes making them unique)
        assert_ne!(block1.hash, block2.hash);
    }

    #[test]
    fn test_verify_votes() {
        let vote = create_test_vote();
        let block = Block::new(1, vec![vote], "prev".to_string());

        assert!(block.verify_votes());
    }

    #[test]
    fn test_vote_count() {
        let vote1 = create_test_vote();
        let vote2 = create_test_vote();

        let block = Block::new(1, vec![vote1, vote2], "prev".to_string());
        assert_eq!(block.vote_count(), 2);
    }

    #[test]
    fn test_mining() {
        let vote = create_test_vote();
        let mut block = Block::new(1, vec![vote], "prev".to_string());

        block.mine(2); // Mine with difficulty 2 (hash must start with "00")

        assert!(block.hash.starts_with("00"));
        assert!(block.is_hash_valid());
        assert!(block.verify_proof_of_work(2));
    }

    #[test]
    fn test_proof_of_work_verification() {
        let vote = create_test_vote();
        let mut block = Block::new(1, vec![vote], "prev".to_string());

        block.mine(2);

        assert!(block.verify_proof_of_work(2));
        assert!(!block.verify_proof_of_work(3)); // Shouldn't pass higher difficulty
    }

    #[test]
    fn test_block_serialization() {
        let vote = create_test_vote();
        let block = Block::new(1, vec![vote], "prev".to_string());

        let serialized = serde_json::to_string(&block).unwrap();
        let deserialized: Block = serde_json::from_str(&serialized).unwrap();

        assert_eq!(block.index, deserialized.index);
        assert_eq!(block.hash, deserialized.hash);
        assert!(deserialized.is_hash_valid());
    }
}
