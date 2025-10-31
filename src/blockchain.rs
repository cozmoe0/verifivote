use crate::block::Block;
use crate::crypto::PublicKey;
use crate::vote::Vote;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents the complete voting blockchain with all election data and validation logic.
///
/// The blockchain is the core data structure of the VerifiVote system. It maintains:
/// - A chain of blocks containing all votes
/// - A pool of pending votes waiting to be mined
/// - Mining difficulty settings for proof-of-work
/// - A registry of voters who have already cast votes (to prevent double voting)
///
/// The blockchain ensures:
/// - **Immutability**: Once votes are added to a block, they cannot be changed
/// - **Integrity**: Any tampering with votes or blocks is immediately detectable
/// - **Transparency**: All votes can be verified and audited
/// - **One-person-one-vote**: Voters cannot cast multiple votes
/// - **Authenticity**: All votes are cryptographically signed and verified
///
/// # Security Properties
///
/// The blockchain provides several security guarantees:
/// - Cryptographic hashing prevents tampering with vote data
/// - Proof-of-work mining makes it expensive to create fraudulent blocks
/// - Digital signatures authenticate voter identity
/// - The chain structure makes retroactive changes detectable
/// - Double-voting prevention through public key tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blockchain {
    pub chain: Vec<Block>,
    pub difficulty: usize,
    pub pending_votes: Vec<Vote>,
    voters_who_voted: HashSet<String>, // Track public keys of voters who have already voted
}

impl Blockchain {
    /// Creates a new blockchain with a genesis block and specified mining difficulty.
    ///
    /// The blockchain is initialized with:
    /// - A genesis block (the first block with no votes)
    /// - Empty pending votes pool
    /// - The specified proof-of-work difficulty
    /// - An empty voter registry
    ///
    /// # Arguments
    ///
    /// * `difficulty` - The number of leading zeros required in block hashes.
    ///                  Higher values increase security but slow down mining.
    ///                  Recommended values: 2-3 for development, 4+ for production
    ///
    /// # Returns
    ///
    /// A new `Blockchain` instance ready to accept votes
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// // Create blockchain with difficulty 2
    /// let blockchain = Blockchain::new(2);
    ///
    /// assert_eq!(blockchain.length(), 1); // Contains genesis block
    /// assert_eq!(blockchain.total_votes(), 0);
    /// assert!(blockchain.is_chain_valid());
    /// ```
    pub fn new(difficulty: usize) -> Self {
        let genesis = Block::genesis();

        Blockchain {
            chain: vec![genesis],
            difficulty,
            pending_votes: vec![],
            voters_who_voted: HashSet::new(),
        }
    }

    /// Returns a reference to the most recently added block in the chain.
    ///
    /// This is useful for getting the hash of the latest block when creating
    /// a new block to be added to the chain.
    ///
    /// # Returns
    ///
    /// A reference to the last block in the chain
    ///
    /// # Panics
    ///
    /// This function will panic if the chain is empty, but this should never
    /// happen as the blockchain is initialized with a genesis block.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// let latest = blockchain.latest_block();
    ///
    /// assert_eq!(latest.index, 0); // Genesis block
    /// ```
    pub fn latest_block(&self) -> &Block {
        self.chain.last().expect("Chain should never be empty")
    }

    /// Adds a vote to the pending votes pool after validation.
    ///
    /// This function performs several critical security checks before accepting
    /// a vote:
    /// 1. Verifies the vote's cryptographic signature
    /// 2. Checks that the voter hasn't already voted (prevents double voting)
    /// 3. Ensures the vote isn't already in the pending pool
    ///
    /// Once validated, the vote is added to the pending pool where it waits
    /// to be mined into a block.
    ///
    /// # Arguments
    ///
    /// * `vote` - The vote to add to the pending pool
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the vote was successfully added
    /// - `Err(String)` if validation fails
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - The vote's signature is invalid
    /// - The voter has already cast a vote (double voting attempt)
    /// - The vote is already in the pending votes pool
    ///
    /// # Security
    ///
    /// This is a critical security function that enforces:
    /// - One-person-one-vote principle
    /// - Vote authenticity through signature verification
    /// - Prevention of duplicate votes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use verifivote::{Blockchain, Vote, Wallet, Answer};
    ///
    /// let mut blockchain = Blockchain::new(2);
    ///
    /// // Create and add a vote (assuming wallet has ballot)
    /// // let vote = Vote::new(&wallet, answers).unwrap();
    /// // blockchain.add_vote(vote).expect("Failed to add vote");
    /// ```
    pub fn add_vote(&mut self, vote: Vote) -> Result<(), String> {
        // Verify vote signature
        if !vote.verify_signature() {
            return Err("Invalid vote signature".to_string());
        }

        // Check if voter has already voted
        let voter_key_hex = vote.voter_public_key.to_hex();
        if self.voters_who_voted.contains(&voter_key_hex) {
            return Err("Voter has already voted".to_string());
        }

        // Check if vote is already in pending votes
        if self.pending_votes.iter().any(|v| v.vote_id == vote.vote_id) {
            return Err("Vote already in pending votes".to_string());
        }

        self.pending_votes.push(vote);
        Ok(())
    }

    /// Mines all pending votes into a new block and adds it to the blockchain.
    ///
    /// This function performs the following operations:
    /// 1. Checks that there are pending votes to mine
    /// 2. Creates a new block with all pending votes
    /// 3. Performs proof-of-work mining on the block
    /// 4. Validates the mined block
    /// 5. Adds the block to the chain
    /// 6. Records all voters as having voted (prevents double voting)
    /// 7. Clears the pending votes pool
    ///
    /// Mining is a computationally intensive operation whose duration depends
    /// on the blockchain's difficulty setting.
    ///
    /// # Returns
    ///
    /// - `Ok(Block)` - The successfully mined block that was added to the chain
    /// - `Err(String)` - If there are no pending votes or validation fails
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - There are no pending votes to mine
    /// - The newly mined block fails validation
    ///
    /// # Performance
    ///
    /// Mining time increases exponentially with difficulty. See [`Block::mine`]
    /// for performance characteristics.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use verifivote::Blockchain;
    ///
    /// let mut blockchain = Blockchain::new(2);
    ///
    /// // Add some votes to pending pool...
    /// // blockchain.add_vote(vote1).unwrap();
    /// // blockchain.add_vote(vote2).unwrap();
    ///
    /// // Mine them into a block
    /// match blockchain.mine_pending_votes() {
    ///     Ok(block) => println!("Mined block with {} votes", block.vote_count()),
    ///     Err(e) => println!("Mining failed: {}", e),
    /// }
    /// ```
    pub fn mine_pending_votes(&mut self) -> Result<Block, String> {
        if self.pending_votes.is_empty() {
            return Err("No pending votes to mine".to_string());
        }

        let previous_hash = self.latest_block().hash.clone();
        let index = self.chain.len() as u64;

        let votes = self.pending_votes.drain(..).collect::<Vec<_>>();

        // Track voters
        for vote in &votes {
            self.voters_who_voted.insert(vote.voter_public_key.to_hex());
        }

        let mut block = Block::new(index, votes, previous_hash);

        // Mine the block with proof of work
        block.mine(self.difficulty);

        // Validate block before adding
        if !self.is_block_valid(&block) {
            return Err("Block validation failed".to_string());
        }

        self.chain.push(block.clone());
        Ok(block)
    }

    /// Validates a single block against blockchain rules.
    ///
    /// This internal function performs comprehensive validation:
    /// - Verifies all vote signatures in the block
    /// - Checks the block's hash is correct
    /// - Validates proof-of-work meets difficulty requirement
    /// - Ensures the previous hash correctly links to the chain
    ///
    /// # Arguments
    ///
    /// * `block` - The block to validate
    ///
    /// # Returns
    ///
    /// `true` if the block passes all validation checks, `false` otherwise
    fn is_block_valid(&self, block: &Block) -> bool {
        // Check all votes have valid signatures
        if !block.verify_votes() {
            return false;
        }

        // Check hash is correct
        if !block.is_hash_valid() {
            return false;
        }

        // Check proof of work
        if !block.verify_proof_of_work(self.difficulty) {
            return false;
        }

        // Check previous hash matches (except for genesis)
        if block.index > 0 && block.index < self.chain.len() as u64 {
            let previous_block = &self.chain[(block.index - 1) as usize];
            if block.previous_hash != previous_block.hash {
                return false;
            }
        }

        true
    }

    /// Validates the integrity of the entire blockchain.
    ///
    /// This function performs comprehensive validation of every block and the
    /// chain structure itself. It checks:
    /// - The genesis block is properly formed
    /// - Every block has a valid hash
    /// - All blocks are correctly linked via previous hash
    /// - All votes in all blocks have valid signatures
    /// - All blocks meet the proof-of-work difficulty requirement
    ///
    /// This is a critical security function that can detect any tampering or
    /// corruption in the blockchain.
    ///
    /// # Returns
    ///
    /// `true` if the entire blockchain is valid, `false` if any validation fails
    ///
    /// # Security
    ///
    /// This validation ensures:
    /// - No votes have been tampered with
    /// - No blocks have been modified or removed
    /// - The chain structure is intact
    /// - All cryptographic proofs are valid
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// assert!(blockchain.is_chain_valid());
    ///
    /// // After adding votes and mining blocks, validation still passes
    /// // blockchain.add_vote(vote).unwrap();
    /// // blockchain.mine_pending_votes().unwrap();
    /// // assert!(blockchain.is_chain_valid());
    /// ```
    pub fn is_chain_valid(&self) -> bool {
        // Check genesis block
        let genesis = &self.chain[0];
        if genesis.index != 0 || genesis.previous_hash != "0" {
            return false;
        }

        // Validate each block and its connection to previous
        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            // Check hash integrity
            if !current_block.is_hash_valid() {
                return false;
            }

            // Check previous hash matches
            if current_block.previous_hash != previous_block.hash {
                return false;
            }

            // Check all votes are valid
            if !current_block.verify_votes() {
                return false;
            }

            // Check proof of work
            if !current_block.verify_proof_of_work(self.difficulty) {
                return false;
            }
        }

        true
    }

    /// Checks whether a specific voter has already cast a vote.
    ///
    /// This function looks up the voter's public key in the registry of voters
    /// who have already voted. This is essential for preventing double voting.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the voter to check
    ///
    /// # Returns
    ///
    /// `true` if the voter has already voted, `false` otherwise
    ///
    /// # Security
    ///
    /// This is a critical security function that enforces the one-person-one-vote
    /// principle. Each public key can only be associated with one vote in the
    /// blockchain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use verifivote::{Blockchain, Wallet};
    ///
    /// let blockchain = Blockchain::new(2);
    /// let wallet = Wallet::new("voter1".to_string());
    /// let voter_key = wallet.public_key();
    ///
    /// assert!(!blockchain.has_voter_voted(&voter_key));
    ///
    /// // After the voter casts a vote and it's mined...
    /// // assert!(blockchain.has_voter_voted(&voter_key));
    /// ```
    pub fn has_voter_voted(&self, public_key: &PublicKey) -> bool {
        self.voters_who_voted.contains(&public_key.to_hex())
    }

    /// Returns the total number of votes recorded in the blockchain.
    ///
    /// This counts all votes across all blocks (excluding the genesis block
    /// which contains no votes).
    ///
    /// # Returns
    ///
    /// The total count of votes in the blockchain
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// assert_eq!(blockchain.total_votes(), 0);
    ///
    /// // After adding and mining votes...
    /// // assert_eq!(blockchain.total_votes(), number_of_votes);
    /// ```
    pub fn total_votes(&self) -> usize {
        self.chain.iter().map(|block| block.vote_count()).sum()
    }

    /// Returns references to all votes in the blockchain.
    ///
    /// This function collects all votes from all blocks (excluding the genesis
    /// block) and returns them as a vector of references.
    ///
    /// # Returns
    ///
    /// A vector containing references to all votes in the blockchain
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// let all_votes = blockchain.get_all_votes();
    ///
    /// assert_eq!(all_votes.len(), 0); // No votes yet
    /// ```
    pub fn get_all_votes(&self) -> Vec<&Vote> {
        self.chain.iter()
            .skip(1) // Skip genesis block
            .flat_map(|block| &block.votes)
            .collect()
    }

    /// Tallies the election results across all votes in the blockchain.
    ///
    /// This function counts how many votes each choice received for each question.
    /// The results are returned as a nested HashMap structure:
    /// - Outer HashMap: Maps question IDs to vote tallies
    /// - Inner HashMap: Maps choice IDs to vote counts
    ///
    /// # Returns
    ///
    /// A nested HashMap where:
    /// - Keys of outer map: Question IDs
    /// - Keys of inner map: Choice IDs
    /// - Values of inner map: Number of votes for that choice
    ///
    /// # Example
    ///
    /// ```no_run
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// // After adding and mining votes...
    ///
    /// let results = blockchain.tally_results();
    ///
    /// // Get results for a specific question
    /// if let Some(question_results) = results.get("q1") {
    ///     for (choice_id, count) in question_results {
    ///         println!("Choice {}: {} votes", choice_id, count);
    ///     }
    /// }
    /// ```
    pub fn tally_results(&self) -> std::collections::HashMap<String, std::collections::HashMap<String, usize>> {
        let mut results: std::collections::HashMap<String, std::collections::HashMap<String, usize>> =
            std::collections::HashMap::new();

        for vote in self.get_all_votes() {
            for answer in &vote.answers {
                results
                    .entry(answer.question_id.clone())
                    .or_insert_with(std::collections::HashMap::new)
                    .entry(answer.choice_id.clone())
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }
        }

        results
    }

    /// Returns the total number of blocks in the blockchain.
    ///
    /// This includes the genesis block, so a newly created blockchain
    /// will have a length of 1.
    ///
    /// # Returns
    ///
    /// The number of blocks in the chain
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Blockchain;
    ///
    /// let blockchain = Blockchain::new(2);
    /// assert_eq!(blockchain.length(), 1); // Genesis block
    ///
    /// // After mining a block...
    /// // assert_eq!(blockchain.length(), 2);
    /// ```
    pub fn length(&self) -> usize {
        self.chain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{Ballot, BallotChoice, BallotQuestion};
    use crate::crypto::KeyPair;
    use crate::vote::Answer;
    use crate::wallet::Wallet;

    fn create_test_ballot() -> (Ballot, KeyPair) {
        let supervisor_keypair = KeyPair::generate();
        let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

        let questions = vec![
            BallotQuestion {
                id: "q1".to_string(),
                question: "President?".to_string(),
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
                question: "Proposition?".to_string(),
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

        (ballot, supervisor_keypair)
    }

    fn create_test_vote(ballot: &Ballot, voter_id: &str, q1_choice: &str, q2_choice: &str) -> Vote {
        let mut wallet = Wallet::new(voter_id.to_string());
        wallet.issue_ballot(ballot.clone()).unwrap();

        let answers = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: q1_choice.to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: q2_choice.to_string(),
            },
        ];

        Vote::new(&wallet, answers).unwrap()
    }

    #[test]
    fn test_blockchain_creation() {
        let blockchain = Blockchain::new(2);

        assert_eq!(blockchain.length(), 1); // Genesis block
        assert_eq!(blockchain.total_votes(), 0);
        assert!(blockchain.is_chain_valid());
    }

    #[test]
    fn test_add_vote() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();
        let vote = create_test_vote(&ballot, "voter1", "c1", "c3");

        let result = blockchain.add_vote(vote);
        assert!(result.is_ok());
        assert_eq!(blockchain.pending_votes.len(), 1);
    }

    #[test]
    fn test_prevent_double_voting() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        // Create wallet and cast first vote
        let mut wallet = Wallet::new("voter1".to_string());
        wallet.issue_ballot(ballot.clone()).unwrap();

        let answers1 = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c3".to_string(),
            },
        ];

        let vote1 = Vote::new(&wallet, answers1).unwrap();
        blockchain.add_vote(vote1).unwrap();
        blockchain.mine_pending_votes().unwrap();

        // Try to vote again with same wallet (same public key)
        let mut wallet2 = wallet.clone();
        wallet2.ballot = Some(ballot);

        let answers2 = vec![
            Answer {
                question_id: "q1".to_string(),
                choice_id: "c2".to_string(),
            },
            Answer {
                question_id: "q2".to_string(),
                choice_id: "c4".to_string(),
            },
        ];

        let vote2 = Vote::new(&wallet2, answers2).unwrap();
        let result = blockchain.add_vote(vote2);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already voted"));
    }

    #[test]
    fn test_mine_pending_votes() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        let vote1 = create_test_vote(&ballot, "voter1", "c1", "c3");
        let vote2 = create_test_vote(&ballot, "voter2", "c2", "c4");

        blockchain.add_vote(vote1).unwrap();
        blockchain.add_vote(vote2).unwrap();

        let block = blockchain.mine_pending_votes().unwrap();

        assert_eq!(block.votes.len(), 2);
        assert_eq!(blockchain.length(), 2);
        assert_eq!(blockchain.pending_votes.len(), 0);
        assert!(blockchain.is_chain_valid());
    }

    #[test]
    fn test_cannot_mine_without_votes() {
        let mut blockchain = Blockchain::new(2);

        let result = blockchain.mine_pending_votes();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No pending votes"));
    }

    #[test]
    fn test_chain_validation() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        let vote1 = create_test_vote(&ballot, "voter1", "c1", "c3");
        blockchain.add_vote(vote1).unwrap();
        blockchain.mine_pending_votes().unwrap();

        assert!(blockchain.is_chain_valid());

        // Tamper with the chain
        blockchain.chain[1].votes[0].answers[0].choice_id = "c2".to_string();

        assert!(!blockchain.is_chain_valid());
    }

    #[test]
    fn test_tally_results() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        // Three votes: 2 for c1, 1 for c2 on question 1
        //              2 for c3, 1 for c4 on question 2
        let vote1 = create_test_vote(&ballot, "voter1", "c1", "c3");
        let vote2 = create_test_vote(&ballot, "voter2", "c1", "c3");
        let vote3 = create_test_vote(&ballot, "voter3", "c2", "c4");

        blockchain.add_vote(vote1).unwrap();
        blockchain.add_vote(vote2).unwrap();
        blockchain.add_vote(vote3).unwrap();
        blockchain.mine_pending_votes().unwrap();

        let results = blockchain.tally_results();

        assert_eq!(results.get("q1").unwrap().get("c1"), Some(&2));
        assert_eq!(results.get("q1").unwrap().get("c2"), Some(&1));
        assert_eq!(results.get("q2").unwrap().get("c3"), Some(&2));
        assert_eq!(results.get("q2").unwrap().get("c4"), Some(&1));
    }

    #[test]
    fn test_has_voter_voted() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        let wallet = Wallet::new("voter1".to_string());
        let voter_key = wallet.public_key();

        assert!(!blockchain.has_voter_voted(&voter_key));

        let mut wallet_with_ballot = wallet.clone();
        wallet_with_ballot.issue_ballot(ballot).unwrap();

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

        let vote = Vote::new(&wallet_with_ballot, answers).unwrap();
        blockchain.add_vote(vote).unwrap();
        blockchain.mine_pending_votes().unwrap();

        assert!(blockchain.has_voter_voted(&voter_key));
    }

    #[test]
    fn test_total_votes() {
        let mut blockchain = Blockchain::new(2);
        let (ballot, _) = create_test_ballot();

        assert_eq!(blockchain.total_votes(), 0);

        let vote1 = create_test_vote(&ballot, "voter1", "c1", "c3");
        blockchain.add_vote(vote1).unwrap();
        blockchain.mine_pending_votes().unwrap();

        assert_eq!(blockchain.total_votes(), 1);

        let vote2 = create_test_vote(&ballot, "voter2", "c2", "c4");
        blockchain.add_vote(vote2).unwrap();
        blockchain.mine_pending_votes().unwrap();

        assert_eq!(blockchain.total_votes(), 2);
    }
}
