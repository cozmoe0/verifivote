//! VerifiVote Demonstration Program
//!
//! This program demonstrates a complete end-to-end voting workflow using the
//! VerifiVote blockchain-based voting system. It showcases all major components
//! and capabilities of the system.
//!
//! # What This Demo Does
//!
//! 1. **Election Setup**: An election supervisor creates a signed ballot with
//!    multiple questions and choices
//!
//! 2. **Blockchain Initialization**: A blockchain is created with proof-of-work
//!    difficulty to secure the voting records
//!
//! 3. **Voter Registration**: Multiple voters receive wallets with cryptographic
//!    keypairs and are issued the election ballot
//!
//! 4. **Voting**: Each voter casts their vote by selecting choices for each
//!    ballot question. Votes are cryptographically signed with their private keys
//!
//! 5. **Vote Collection**: All votes are added to the blockchain's pending pool
//!    after validation (signature verification, double-vote prevention)
//!
//! 6. **Block Mining**: Pending votes are mined into a block using proof-of-work,
//!    which is then added to the blockchain
//!
//! 7. **Security Demonstration**: The system attempts to prevent a double-voting
//!    attack, showing how the blockchain rejects duplicate votes
//!
//! 8. **Result Tallying**: The blockchain tallies all votes and determines the
//!    election results for each question
//!
//! # Key Security Features Demonstrated
//!
//! - **Digital Signatures**: All ballots and votes are cryptographically signed
//! - **Signature Verification**: Every vote's authenticity is verified before acceptance
//! - **Double-Vote Prevention**: The blockchain tracks voters and prevents multiple votes
//! - **Proof-of-Work**: Mining makes it expensive to create fraudulent blocks
//! - **Blockchain Integrity**: The entire chain is validated to detect tampering
//! - **Immutability**: Once votes are in the blockchain, they cannot be altered
//!
//! # Sample Election
//!
//! The demo runs a "2024 General Election" with two questions:
//! - Presidential election (3 candidates)
//! - Proposition 123 referendum (Yes/No)
//!
//! Five voters cast their votes, which are mined into the blockchain, and
//! the results are tallied to determine the winners.
//!
//! # Running the Demo
//!
//! ```bash
//! cargo run
//! ```
//!
//! The program will output detailed information about each step, including:
//! - Supervisor and voter public keys
//! - Ballot verification status
//! - Vote casting confirmations
//! - Block mining progress (hash, nonce)
//! - Blockchain validation results
//! - Final election results
//!

use verifivote::*;

fn main() {
    println!("=== VerifiVote - Blockchain Voting System ===\n");

    // Step 1: Election supervisor creates a ballot
    println!("1. Election Supervisor creates ballot...");
    let supervisor_keypair = crypto::KeyPair::generate();
    let supervisor_public_key = crypto::PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

    println!("   Supervisor Public Key: {}", supervisor_public_key.to_hex());

    let questions = vec![
        ballot::BallotQuestion {
            id: "q1".to_string(),
            question: "Who should be the next President?".to_string(),
            choices: vec![
                ballot::BallotChoice {
                    id: "c1".to_string(),
                    text: "Alice Johnson".to_string(),
                },
                ballot::BallotChoice {
                    id: "c2".to_string(),
                    text: "Bob Smith".to_string(),
                },
                ballot::BallotChoice {
                    id: "c3".to_string(),
                    text: "Carol Williams".to_string(),
                },
            ],
        },
        ballot::BallotQuestion {
            id: "q2".to_string(),
            question: "Should Proposition 123 be approved?".to_string(),
            choices: vec![
                ballot::BallotChoice {
                    id: "c4".to_string(),
                    text: "Yes".to_string(),
                },
                ballot::BallotChoice {
                    id: "c5".to_string(),
                    text: "No".to_string(),
                },
            ],
        },
    ];

    let mut ballot = ballot::Ballot::new(
        "2024 General Election".to_string(),
        questions,
        supervisor_public_key,
    );
    ballot.sign(&supervisor_keypair);

    println!("   Ballot ID: {}", ballot.id);
    println!("   Ballot verified: {}\n", ballot.verify_supervisor_signature());

    // Step 2: Initialize blockchain
    println!("2. Initializing blockchain (difficulty: 2)...");
    let mut blockchain = blockchain::Blockchain::new(2);
    println!("   Genesis block created\n");

    // Step 3: Create voters and issue ballots
    println!("3. Issuing ballots to voters...");
    let mut voters = vec![];

    for i in 1..=5 {
        let voter_id = format!("voter{}", i);
        let mut wallet = wallet::Wallet::new(voter_id.clone());
        wallet.issue_ballot(ballot.clone()).expect("Failed to issue ballot");

        println!("   Issued ballot to {} (Key: {})",
                 voter_id,
                 wallet.public_key().to_hex()[..16].to_string() + "...");

        voters.push(wallet);
    }
    println!();

    // Step 4: Voters cast their votes
    println!("4. Voters casting their votes...");

    // Voter 1: Alice, Yes
    let vote1 = vote::Vote::new(
        &voters[0],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c4".to_string(),
            },
        ],
    ).expect("Failed to create vote");
    blockchain.add_vote(vote1).expect("Failed to add vote");
    println!("   voter1 voted for Alice Johnson, Yes on Prop 123");

    // Voter 2: Alice, Yes
    let vote2 = vote::Vote::new(
        &voters[1],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c4".to_string(),
            },
        ],
    ).expect("Failed to create vote");
    blockchain.add_vote(vote2).expect("Failed to add vote");
    println!("   voter2 voted for Alice Johnson, Yes on Prop 123");

    // Voter 3: Bob, No
    let vote3 = vote::Vote::new(
        &voters[2],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c2".to_string(),
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c5".to_string(),
            },
        ],
    ).expect("Failed to create vote");
    blockchain.add_vote(vote3).expect("Failed to add vote");
    println!("   voter3 voted for Bob Smith, No on Prop 123");

    // Voter 4: Alice, No
    let vote4 = vote::Vote::new(
        &voters[3],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c1".to_string(),
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c5".to_string(),
            },
        ],
    ).expect("Failed to create vote");
    blockchain.add_vote(vote4).expect("Failed to add vote");
    println!("   voter4 voted for Alice Johnson, No on Prop 123");

    // Voter 5: Carol, Yes
    let vote5 = vote::Vote::new(
        &voters[4],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c3".to_string(),
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c4".to_string(),
            },
        ],
    ).expect("Failed to create vote");
    blockchain.add_vote(vote5).expect("Failed to add vote");
    println!("   voter5 voted for Carol Williams, Yes on Prop 123\n");

    // Step 5: Mine the votes into a block
    println!("5. Mining votes into blockchain...");
    let block = blockchain.mine_pending_votes().expect("Failed to mine block");
    println!("   Block mined!");
    println!("   Block hash: {}", block.hash);
    println!("   Votes in block: {}", block.vote_count());
    println!("   Nonce: {}\n", block.nonce);

    // Step 6: Verify blockchain integrity
    println!("6. Verifying blockchain integrity...");
    let is_valid = blockchain.is_chain_valid();
    println!("   Blockchain valid: {}", is_valid);
    println!("   Total blocks: {}", blockchain.length());
    println!("   Total votes: {}\n", blockchain.total_votes());

    // Step 7: Demonstrate double-vote prevention
    println!("7. Testing double-vote prevention...");
    println!("   Attempting to cast second vote with voter1's wallet...");

    let double_vote_attempt = vote::Vote::new(
        &voters[0],
        vec![
            vote::Answer {
                question_id: "q1".to_string(),
                choice_id: "c2".to_string(), // Different choice
            },
            vote::Answer {
                question_id: "q2".to_string(),
                choice_id: "c5".to_string(),
            },
        ],
    );

    if let Ok(double_vote) = double_vote_attempt {
        match blockchain.add_vote(double_vote) {
            Ok(_) => println!("   ERROR: Double vote was accepted!"),
            Err(e) => println!("   SUCCESS: Double vote prevented - {}\n", e),
        }
    }

    // Step 8: Tally results
    println!("8. Tallying election results...");
    let results = blockchain.tally_results();

    println!("\n   === ELECTION RESULTS ===");
    println!("\n   Question: Who should be the next President?");
    if let Some(q1_results) = results.get("q1") {
        let alice_votes = q1_results.get("c1").unwrap_or(&0);
        let bob_votes = q1_results.get("c2").unwrap_or(&0);
        let carol_votes = q1_results.get("c3").unwrap_or(&0);

        println!("   - Alice Johnson: {} votes", alice_votes);
        println!("   - Bob Smith: {} votes", bob_votes);
        println!("   - Carol Williams: {} votes", carol_votes);

        let winner = if alice_votes > bob_votes && alice_votes > carol_votes {
            "Alice Johnson"
        } else if bob_votes > alice_votes && bob_votes > carol_votes {
            "Bob Smith"
        } else {
            "Carol Williams"
        };
        println!("   WINNER: {}", winner);
    }

    println!("\n   Question: Should Proposition 123 be approved?");
    if let Some(q2_results) = results.get("q2") {
        let yes_votes = q2_results.get("c4").unwrap_or(&0);
        let no_votes = q2_results.get("c5").unwrap_or(&0);

        println!("   - Yes: {} votes", yes_votes);
        println!("   - No: {} votes", no_votes);

        let result = if yes_votes > no_votes {
            "APPROVED"
        } else {
            "REJECTED"
        };
        println!("   RESULT: {}", result);
    }

    println!("\n=== Election Complete ===");
    println!("All votes are permanently recorded on the blockchain.");
    println!("The blockchain can be verified at any time to ensure integrity.");
}
