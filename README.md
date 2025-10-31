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

## Project Structure

```
VerifiVote/
├── src/
│   ├── main.rs           # Demo application
│   ├── lib.rs            # Library exports
│   ├── crypto.rs         # Cryptographic utilities
│   ├── ballot.rs         # Ballot creation and management
│   ├── wallet.rs         # Voter wallet system
│   ├── vote.rs           # Vote creation and validation
│   ├── block.rs          # Blockchain block structure
│   └── blockchain.rs     # Blockchain management
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
