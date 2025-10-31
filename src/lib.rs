//! VerifiVote - A blockchain-based voting system
//!
//! This library implements a secure, transparent voting system using blockchain technology.
//! It provides cryptographic signing and verification, ballot management, voter wallets,
//! and a full blockchain implementation with proof-of-work.
//!
//! # Architecture
//!
//! The system consists of several key components:
//!
//! - **Crypto**: Digital signatures using Ed25519 and SHA-256 hashing
//! - **Ballot**: Election ballot templates created and signed by supervisors
//! - **Wallet**: Voter wallets that hold ballots and signing keys
//! - **Vote**: Completed ballots signed by voters
//! - **Block**: Blockchain blocks with proof-of-work mining
//! - **Blockchain**: Full blockchain with vote validation and tallying
//!
//! # Example Usage
//!
//! ```rust
//! use verifivote::*;
//!
//! // Election supervisor creates a ballot
//! let supervisor_keypair = crypto::KeyPair::generate();
//! let supervisor_public_key = crypto::PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
//!
//! let questions = vec![
//!     ballot::BallotQuestion {
//!         id: "q1".to_string(),
//!         question: "Who should be president?".to_string(),
//!         choices: vec![
//!             ballot::BallotChoice {
//!                 id: "c1".to_string(),
//!                 text: "Candidate A".to_string(),
//!             },
//!             ballot::BallotChoice {
//!                 id: "c2".to_string(),
//!                 text: "Candidate B".to_string(),
//!             },
//!         ],
//!     },
//! ];
//!
//! let mut ballot = ballot::Ballot::new(
//!     "2024 Election".to_string(),
//!     questions,
//!     supervisor_public_key,
//! );
//! ballot.sign(&supervisor_keypair);
//!
//! // Voter receives ballot in their wallet
//! let mut voter_wallet = wallet::Wallet::new("voter1".to_string());
//! voter_wallet.issue_ballot(ballot).unwrap();
//!
//! // Voter fills out and signs ballot
//! let answers = vec![
//!     vote::Answer {
//!         question_id: "q1".to_string(),
//!         choice_id: "c1".to_string(),
//!     },
//! ];
//!
//! let vote = vote::Vote::new(&voter_wallet, answers).unwrap();
//!
//! // Vote is submitted to blockchain
//! let mut blockchain = blockchain::Blockchain::new(2);
//! blockchain.add_vote(vote).unwrap();
//! blockchain.mine_pending_votes().unwrap();
//!
//! // Verify blockchain integrity
//! assert!(blockchain.is_chain_valid());
//! ```

pub mod ballot;
pub mod block;
pub mod blockchain;
pub mod crypto;
pub mod vote;
pub mod wallet;

// Re-export commonly used types
pub use ballot::{Ballot, BallotChoice, BallotQuestion};
pub use block::Block;
pub use blockchain::Blockchain;
pub use crypto::{KeyPair, PublicKey, SignatureData};
pub use vote::{Answer, Vote};
pub use wallet::{Wallet, WalletInfo};
