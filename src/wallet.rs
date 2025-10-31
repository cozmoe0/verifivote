use crate::ballot::Ballot;
use crate::crypto::{KeyPair, PublicKey};
use serde::{Deserialize, Serialize};

/// Represents a voter's wallet that holds their ballot and cryptographic keys.
///
/// A wallet serves as the digital identity for a voter in the VerifiVote system.
/// Each wallet contains:
/// - A unique voter ID for identification
/// - A cryptographic keypair (Ed25519) for signing votes
/// - An optional ballot that has been issued to this voter
///
/// Wallets enforce the one-person-one-vote principle by only allowing a single
/// ballot to be held at a time. The private key never leaves the wallet, ensuring
/// that only the legitimate voter can cast votes.
#[derive(Clone)]
pub struct Wallet {
    pub voter_id: String,
    pub keypair: KeyPair,
    pub ballot: Option<Ballot>,
}

impl Wallet {
    /// Creates a new wallet for a voter with a fresh cryptographic keypair.
    ///
    /// The wallet is initialized with no ballot. A ballot must be issued using
    /// [`issue_ballot`](Self::issue_ballot) before the voter can cast a vote.
    ///
    /// # Arguments
    ///
    /// * `voter_id` - A unique identifier for the voter (e.g., "voter123")
    ///
    /// # Returns
    ///
    /// A new `Wallet` instance with a randomly generated Ed25519 keypair
    ///
    /// # Security
    ///
    /// The keypair is generated using a cryptographically secure random number
    /// generator (OS-provided). The private key is stored within the wallet and
    /// should never be shared or transmitted.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Wallet;
    ///
    /// let wallet = Wallet::new("voter123".to_string());
    /// assert_eq!(wallet.voter_id, "voter123");
    /// assert!(!wallet.has_ballot());
    /// ```
    pub fn new(voter_id: String) -> Self {
        let keypair = KeyPair::generate();

        Wallet {
            voter_id,
            keypair,
            ballot: None,
        }
    }

    /// Issues a signed ballot to this wallet for voting.
    ///
    /// This function stores a ballot in the wallet, allowing the voter to cast
    /// their vote. Each wallet can only hold one ballot at a time to enforce
    /// the one-person-one-vote principle. The ballot must be properly signed
    /// by an election supervisor or it will be rejected.
    ///
    /// # Arguments
    ///
    /// * `ballot` - The ballot to issue, which must be signed by the election supervisor
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the ballot was successfully issued
    /// - `Err(String)` if the wallet already has a ballot or if the ballot signature is invalid
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - The wallet already has a ballot (attempting to issue a second ballot)
    /// - The ballot's supervisor signature is invalid or missing
    ///
    /// # Security
    ///
    /// The ballot's cryptographic signature is verified before being accepted.
    /// This ensures that only ballots authorized by a legitimate election supervisor
    /// can be issued to voters.
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Ballot, KeyPair, PublicKey};
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    ///
    /// let mut ballot = Ballot::new("2024 Election".to_string(), vec![], supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// let result = wallet.issue_ballot(ballot);
    /// assert!(result.is_ok());
    /// assert!(wallet.has_ballot());
    /// ```
    pub fn issue_ballot(&mut self, ballot: Ballot) -> Result<(), String> {
        if self.ballot.is_some() {
            return Err("Wallet already has a ballot".to_string());
        }

        // Verify the ballot is properly signed by supervisor
        if !ballot.verify_supervisor_signature() {
            return Err("Ballot signature is invalid".to_string());
        }

        self.ballot = Some(ballot);
        Ok(())
    }

    /// Returns the public key associated with this wallet.
    ///
    /// The public key is derived from the wallet's keypair and serves as the
    /// voter's public identity in the blockchain. It is used to:
    /// - Sign votes cryptographically
    /// - Verify that votes came from this specific voter
    /// - Track which voters have already cast their votes
    ///
    /// The public key can be safely shared, while the private key remains
    /// protected within the wallet.
    ///
    /// # Returns
    ///
    /// A `PublicKey` that can be used for signature verification
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::Wallet;
    ///
    /// let wallet = Wallet::new("voter1".to_string());
    /// let public_key = wallet.public_key();
    /// assert_eq!(public_key.as_bytes().len(), 32); // Ed25519 public keys are 32 bytes
    /// ```
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_verifying_key(&self.keypair.verifying_key)
    }

    /// Checks whether this wallet currently holds a ballot.
    ///
    /// A wallet must have a ballot before it can cast a vote. This function
    /// allows checking the wallet's state before attempting vote operations.
    ///
    /// # Returns
    ///
    /// `true` if the wallet has a ballot, `false` otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Ballot, KeyPair, PublicKey};
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// assert!(!wallet.has_ballot());
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    /// let mut ballot = Ballot::new("Election".to_string(), vec![], supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    ///
    /// wallet.issue_ballot(ballot).unwrap();
    /// assert!(wallet.has_ballot());
    /// ```
    pub fn has_ballot(&self) -> bool {
        self.ballot.is_some()
    }

    /// Returns a reference to the ballot held by this wallet, if any.
    ///
    /// This allows read-only access to the ballot for operations such as:
    /// - Viewing the questions and choices
    /// - Validating answers before creating a vote
    /// - Checking the ballot ID and election name
    ///
    /// # Returns
    ///
    /// - `Some(&Ballot)` if the wallet has a ballot
    /// - `None` if no ballot has been issued to this wallet
    ///
    /// # Example
    ///
    /// ```
    /// use verifivote::{Wallet, Ballot, KeyPair, PublicKey};
    ///
    /// let mut wallet = Wallet::new("voter1".to_string());
    /// assert!(wallet.get_ballot().is_none());
    ///
    /// let supervisor_keypair = KeyPair::generate();
    /// let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);
    /// let mut ballot = Ballot::new("Election".to_string(), vec![], supervisor_public_key);
    /// ballot.sign(&supervisor_keypair);
    /// let ballot_id = ballot.id.clone();
    ///
    /// wallet.issue_ballot(ballot).unwrap();
    ///
    /// let retrieved_ballot = wallet.get_ballot();
    /// assert!(retrieved_ballot.is_some());
    /// assert_eq!(retrieved_ballot.unwrap().id, ballot_id);
    /// ```
    pub fn get_ballot(&self) -> Option<&Ballot> {
        self.ballot.as_ref()
    }
}

/// Serializable representation of wallet information without the private key.
///
/// This struct provides a safe way to transmit or display wallet information
/// without exposing the sensitive private key. It contains only public data
/// that can be safely shared:
/// - The voter's ID
/// - The public key (for signature verification)
/// - Whether the wallet has a ballot
/// - The ID of the ballot, if present
///
/// This is useful for:
/// - Displaying wallet status to users
/// - Transmitting wallet state over the network
/// - Logging and auditing without security risks
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub voter_id: String,
    pub public_key: PublicKey,
    pub has_ballot: bool,
    pub ballot_id: Option<String>,
}

impl From<&Wallet> for WalletInfo {
    fn from(wallet: &Wallet) -> Self {
        WalletInfo {
            voter_id: wallet.voter_id.clone(),
            public_key: wallet.public_key(),
            has_ballot: wallet.has_ballot(),
            ballot_id: wallet.ballot.as_ref().map(|b| b.id.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::{BallotChoice, BallotQuestion};
    use crate::crypto::KeyPair;

    fn create_signed_ballot() -> Ballot {
        let supervisor_keypair = KeyPair::generate();
        let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

        let questions = vec![BallotQuestion {
            id: "q1".to_string(),
            question: "Test question?".to_string(),
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
        }];

        let mut ballot = Ballot::new("Test Election".to_string(), questions, supervisor_public_key);
        ballot.sign(&supervisor_keypair);

        ballot
    }

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new("voter123".to_string());

        assert_eq!(wallet.voter_id, "voter123");
        assert!(!wallet.has_ballot());
        assert_eq!(wallet.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_issue_ballot() {
        let mut wallet = Wallet::new("voter123".to_string());
        let ballot = create_signed_ballot();

        let result = wallet.issue_ballot(ballot);
        assert!(result.is_ok());
        assert!(wallet.has_ballot());
    }

    #[test]
    fn test_cannot_issue_multiple_ballots() {
        let mut wallet = Wallet::new("voter123".to_string());
        let ballot1 = create_signed_ballot();
        let ballot2 = create_signed_ballot();

        wallet.issue_ballot(ballot1).unwrap();
        let result = wallet.issue_ballot(ballot2);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wallet already has a ballot");
    }

    #[test]
    fn test_reject_invalid_ballot() {
        let mut wallet = Wallet::new("voter123".to_string());
        let supervisor_keypair = KeyPair::generate();
        let supervisor_public_key = PublicKey::from_verifying_key(&supervisor_keypair.verifying_key);

        let questions = vec![BallotQuestion {
            id: "q1".to_string(),
            question: "Test?".to_string(),
            choices: vec![],
        }];

        let ballot = Ballot::new("Test".to_string(), questions, supervisor_public_key);
        // Don't sign the ballot

        let result = wallet.issue_ballot(ballot);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn test_wallet_info_conversion() {
        let mut wallet = Wallet::new("voter123".to_string());
        let ballot = create_signed_ballot();
        let ballot_id = ballot.id.clone();

        wallet.issue_ballot(ballot).unwrap();

        let info = WalletInfo::from(&wallet);
        assert_eq!(info.voter_id, "voter123");
        assert!(info.has_ballot);
        assert_eq!(info.ballot_id, Some(ballot_id));
    }

    #[test]
    fn test_get_ballot() {
        let mut wallet = Wallet::new("voter123".to_string());
        let ballot = create_signed_ballot();
        let ballot_id = ballot.id.clone();

        wallet.issue_ballot(ballot).unwrap();

        let retrieved = wallet.get_ballot();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, ballot_id);
    }
}
