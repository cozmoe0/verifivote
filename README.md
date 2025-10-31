# VerifiVote - Blockchain-Based Voting System

A secure, transparent, and tamper-proof voting system built with Rust and blockchain technology.

## Overview

VerifiVote implements a complete blockchain-based voting system to address election integrity concerns. The system uses cryptographic signatures, proof-of-work mining, and blockchain validation to ensure:

- **Authenticity**: Every ballot and vote is cryptographically signed
- **Transparency**: All votes are publicly recorded on the blockchain
- **Immutability**: Once recorded, votes cannot be altered
- **Privacy**: Voter identities are represented by public keys
- **Auditability**: The entire chain can be verified at any time
- **Double-vote Prevention**: Each voter can only vote once

## Features

### Core Components

1. **Cryptographic Security**
   - Ed25519 digital signatures for authentication
   - SHA-256 hashing for blockchain integrity
   - Secure key generation using OS random number generator

2. **Ballot Management**
   - Election supervisors create and sign ballot templates
   - Ballots contain multiple questions with choices
   - Supervisor signatures verify ballot authenticity

3. **Voter Wallets**
   - Each voter has a unique cryptographic wallet
   - Wallets hold one ballot per election
   - Only wallet owners can sign votes

4. **Vote Validation**
   - Votes must match ballot questions
   - All answers are validated before acceptance
   - Voter signatures ensure authenticity

5. **Blockchain**
   - Proof-of-work mining for consensus
   - Complete chain validation
   - Real-time vote tallying
   - Double-vote prevention tracking

## Architecture

```
┌─────────────────┐
│    Supervisor   │ Creates & Signs Ballots
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Ballot      │ Issued to Voter Wallets
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Voter Wallet   │ Signs and Submits Votes
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Blockchain    │ Mines, Validates, and Records
└─────────────────┘
```

## Technology Stack

- **Language**: Rust (Edition 2024)
- **Cryptography**: ed25519-dalek (Ed25519 signatures)
- **Hashing**: sha2 (SHA-256)
- **Serialization**: serde + serde_json
- **Time**: chrono
- **Encoding**: hex
- **Random**: rand

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd VerifiVote

# Build the project
cargo build --release

# Run tests
cargo test

# Run the demonstration
cargo run
```

## Usage

### Running the Demo

The included demo demonstrates a complete election process:

```bash
cargo run
```

This will:
1. Create a ballot with presidential and proposition questions
2. Initialize a blockchain with proof-of-work (difficulty 2)
3. Issue ballots to 5 voters
4. Process 5 votes
5. Mine votes into a block
6. Verify blockchain integrity
7. Test double-vote prevention
8. Tally and display results

### As a Library

```rust
use verifivote::*;

// Supervisor creates ballot
let supervisor_keypair = crypto::KeyPair::generate();
let supervisor_public_key = crypto::PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

let questions = vec![
    ballot::BallotQuestion {
        id: "q1".to_string(),
        question: "Who should be president?".to_string(),
        choices: vec![
            ballot::BallotChoice {
                id: "c1".to_string(),
                text: "Candidate A".to_string(),
            },
            ballot::BallotChoice {
                id: "c2".to_string(),
                text: "Candidate B".to_string(),
            },
        ],
    },
];

let mut ballot = ballot::Ballot::new(
    "2024 Election".to_string(),
    questions,
    supervisor_public_key,
);
ballot.sign(&supervisor_keypair);

// Initialize blockchain
let mut blockchain = blockchain::Blockchain::new(2);

// Voter receives ballot
let mut wallet = wallet::Wallet::new("voter1".to_string());
wallet.issue_ballot(ballot).unwrap();

// Voter casts vote
let answers = vec![
    vote::Answer {
        question_id: "q1".to_string(),
        choice_id: "c1".to_string(),
    },
];

let vote = vote::Vote::new(&wallet, answers).unwrap();

// Submit to blockchain
blockchain.add_vote(vote).unwrap();
blockchain.mine_pending_votes().unwrap();

// Verify and tally
assert!(blockchain.is_chain_valid());
let results = blockchain.tally_results();
```

## Testing

The project includes comprehensive tests for all components:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific module tests
cargo test crypto::tests
cargo test ballot::tests
cargo test wallet::tests
cargo test vote::tests
cargo test block::tests
cargo test blockchain::tests
```

### Test Coverage

- **Crypto Module**: 6 tests - Key generation, signing, verification, hashing
- **Ballot Module**: 5 tests - Creation, signing, verification, serialization
- **Wallet Module**: 6 tests - Creation, ballot issuance, validation
- **Vote Module**: 7 tests - Creation, validation, signatures, serialization
- **Block Module**: 8 tests - Genesis, mining, proof-of-work, validation
- **Blockchain Module**: 9 tests - Chain validation, double-vote prevention, tallying

**Total: 41 passing tests**

## Security Features

### Cryptographic Signatures
- Ed25519 provides 128-bit security level
- All ballots signed by election supervisors
- All votes signed by voters
- Signature verification at every step

### Blockchain Integrity
- SHA-256 hashing ensures immutability
- Each block references previous block's hash
- Tampering with any vote invalidates entire chain
- Proof-of-work adds computational cost to attacks

### Double-Vote Prevention
- Voter public keys tracked in blockchain
- System rejects votes from voters who already voted
- Attempted double-votes are logged and rejected

### Validation Layers
1. Ballot must be signed by supervisor
2. Vote must match ballot questions
3. Vote must be signed by voter
4. Voter must not have voted before
5. Block must pass proof-of-work
6. Chain integrity must be maintained

## How It Works

### Step-by-Step Process

#### 1. Election Setup (Supervisor)

1. **Generate Supervisor Keypair**: The election supervisor generates a unique Ed25519 keypair
   ```rust
   let supervisor_keypair = KeyPair::generate();
   ```

2. **Create Ballot**: Design the ballot with questions and choices
   ```rust
   let ballot = Ballot::new(election_name, questions, supervisor_public_key);
   ```

3. **Sign Ballot**: Cryptographically sign the ballot to prove authenticity
   ```rust
   ballot.sign(&supervisor_keypair);
   ```

4. **Initialize Blockchain**: Set up the blockchain with a genesis block and mining difficulty
   ```rust
   let blockchain = Blockchain::new(difficulty);
   ```

#### 2. Voter Registration

1. **Create Wallet**: Each voter gets a unique wallet with its own keypair
   ```rust
   let wallet = Wallet::new(voter_id);
   ```

2. **Issue Ballot**: The supervisor issues the signed ballot to the voter's wallet
   ```rust
   wallet.issue_ballot(ballot)?;
   ```
   - The wallet verifies the supervisor's signature
   - Only one ballot can be held per wallet

#### 3. Voting Process

1. **Fill Out Ballot**: Voter selects choices for each question
   ```rust
   let answers = vec![
       Answer { question_id: "q1", choice_id: "c1" },
       Answer { question_id: "q2", choice_id: "c4" },
   ];
   ```

2. **Create Vote**: The system validates answers and creates a signed vote
   ```rust
   let vote = Vote::new(&wallet, answers)?;
   ```
   - Validates all question IDs exist
   - Validates all choice IDs are valid for their questions
   - Ensures all questions are answered
   - Signs the vote with the voter's private key

3. **Submit Vote**: The vote is added to the blockchain's pending pool
   ```rust
   blockchain.add_vote(vote)?;
   ```
   - Verifies the voter's signature
   - Checks if voter has already voted (double-vote prevention)
   - Adds to pending votes pool

#### 4. Mining and Block Creation

1. **Mine Pending Votes**: Collect pending votes and mine them into a block
   ```rust
   blockchain.mine_pending_votes()?;
   ```

2. **Proof-of-Work**: Find a nonce that produces a hash with required leading zeros
   ```rust
   block.mine(difficulty);  // e.g., difficulty=2 requires "00..."
   ```
   - Repeatedly hashes block with different nonces
   - Stops when hash starts with required number of zeros
   - Provides computational cost to prevent tampering

3. **Add to Chain**: Validated block is appended to the blockchain
   - Block hash is calculated
   - Previous block's hash is included
   - All votes are marked as confirmed

#### 5. Verification and Tallying

1. **Verify Chain**: Anyone can verify the entire blockchain's integrity
   ```rust
   blockchain.is_chain_valid();
   ```
   - Checks each block's hash is correct
   - Verifies all vote signatures
   - Confirms proof-of-work for each block
   - Validates chain linkage (each block references previous)

2. **Tally Results**: Count votes for each choice
   ```rust
   let results = blockchain.tally_results();
   ```
   - Iterates through all blocks
   - Counts answers for each question and choice
   - Returns complete election results

### Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. ELECTION SETUP                                                │
│    Supervisor → [Generate Keys] → [Create Ballot] → [Sign]       │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. VOTER REGISTRATION                                            │
│    Voter → [Generate Wallet] → [Receive Ballot] → [Verify Sig]  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. VOTING                                                         │
│    Voter → [Select Choices] → [Create Vote] → [Sign Vote]       │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. SUBMISSION & VALIDATION                                        │
│    Vote → [Verify Signature] → [Check Double-Vote] → [Add to    │
│           Pending Pool]                                          │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. MINING                                                         │
│    Pending Votes → [Create Block] → [Proof-of-Work] → [Add to   │
│                    Chain]                                        │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. VERIFICATION & TALLYING                                        │
│    Blockchain → [Verify All Signatures] → [Verify Chain] →      │
│                 [Tally Results]                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Cryptographic Details

#### Digital Signatures (Ed25519)

**Why Ed25519?**
- Fast signature generation and verification
- Small signature size (64 bytes)
- High security (128-bit security level)
- Deterministic signatures (no randomness needed)

**Signature Process:**
1. Hash the data to be signed
2. Sign the hash with the private key
3. Store signature alongside the data
4. Anyone can verify using the public key

**Used in VerifiVote:**
- Supervisor signs ballots → proves ballot authenticity
- Voters sign votes → proves voter cast the vote
- Signatures prevent tampering and impersonation

#### Hashing (SHA-256)

**Why SHA-256?**
- Produces 256-bit (32-byte) hash
- Cryptographically secure
- Industry standard
- Collision resistant

**Used in VerifiVote:**
- Block hash calculation
- Vote hash calculation
- Ballot hash calculation
- Chain integrity verification

**Hash Calculation:**
```rust
fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())  // Returns 64-character hex string
}
```

#### Proof-of-Work Mining

**Purpose:** Makes it computationally expensive to modify the blockchain

**Process:**
1. Start with nonce = 0
2. Calculate hash = SHA-256(block_data + nonce)
3. Check if hash starts with required number of zeros
4. If yes, mining complete. If no, increment nonce and repeat

**Difficulty Examples:**
- Difficulty 1: Hash must start with "0" (~16 attempts average)
- Difficulty 2: Hash must start with "00" (~256 attempts average)
- Difficulty 3: Hash must start with "000" (~4,096 attempts average)
- Difficulty 4: Hash must start with "0000" (~65,536 attempts average)

**Security:** To tamper with a vote, an attacker would need to:
1. Re-mine the block containing the vote
2. Re-mine ALL subsequent blocks
3. Outpace the honest chain
4. All voter signatures would still be invalid

## Project Structure

```
VerifiVote/
├── src/
│   ├── main.rs           # Demo application (election simulation)
│   ├── lib.rs            # Library exports and module documentation
│   ├── crypto.rs         # Cryptographic utilities (Ed25519, SHA-256)
│   ├── ballot.rs         # Ballot creation and management
│   ├── wallet.rs         # Voter wallet system (keypair storage)
│   ├── vote.rs           # Vote creation and validation
│   ├── block.rs          # Blockchain block structure
│   └── blockchain.rs     # Blockchain management and consensus
├── Cargo.toml            # Dependencies and metadata
└── README.md             # This file
```

## Future Enhancements

Potential improvements for production use:

1. **Network Layer**: Peer-to-peer blockchain distribution
2. **Persistence**: Save blockchain to disk/database
3. **Web Interface**: Browser-based voting application
4. **Mobile Apps**: iOS/Android voter applications
5. **Advanced Privacy**: Zero-knowledge proofs for anonymous voting
6. **Scalability**: Optimized consensus mechanisms
7. **Audit Tools**: Blockchain explorer and analysis tools
8. **Registration**: Voter registration and identity verification
9. **Accessibility**: Support for voters with disabilities
10. **Internationalization**: Multi-language support

## License

This project is provided as-is for educational and demonstration purposes.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code follows Rust conventions (`cargo fmt`, `cargo clippy`)
- New features include tests
- Documentation is updated

## Disclaimer

This is a demonstration project. While it implements strong cryptographic security, it has not been audited for production use in real elections. Additional features like voter registration, identity verification, network security, and regulatory compliance would be required for actual deployment.

## Author

Created as a demonstration of blockchain-based voting systems using Rust.
