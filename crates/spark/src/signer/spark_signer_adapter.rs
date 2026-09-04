//! Default in-process [`SparkSigner`] implementation.
//!
//! `SparkSignerAdapter` wraps the low-level [`Signer`] trait and performs the
//! flow orchestration (key-tweak / Feldman split / ECIES / payload signing)
//! that used to live in the service layer. It reproduces the exact key
//! derivation we use today, so a wallet keyed by `DefaultSigner` produces
//! byte-identical keys whether it goes through this adapter or the old direct
//! `Signer` calls.

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::round1::{NonceCommitment, SigningCommitments};
use prost::Message as _;

use super::spark_signer::*;
use super::{
    AggregateFrostRequest, CommitAndSignFrostRequest, CommittedFrostShare, SecretSource,
    SecretToSplit, SignFrostRequest, Signer, SignerError, VerifiableSecretShare,
};
use crate::operator::rpc::spark as proto;
use crate::utils::frost::aggregate_frost;
use crate::utils::tagged_hasher::TaggedHasher;

struct OperatorShares {
    statechain_commitments: BTreeMap<Identifier, frost_secp256k1_tr::round1::SigningCommitments>,
    statechain_signatures: BTreeMap<Identifier, frost_secp256k1_tr::round2::SignatureShare>,
    statechain_public_keys: BTreeMap<Identifier, PublicKey>,
}

/// Length of a Lightning payment preimage in bytes.
const PREIMAGE_LEN: usize = 32;

pub struct SparkSignerAdapter {
    signer: Arc<dyn Signer>,
    secp: Secp256k1<bitcoin::secp256k1::All>,
    leaf_key_store: Option<Arc<dyn LeafKeyOverrideStore>>,
}

impl SparkSignerAdapter {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Self {
            signer,
            secp: Secp256k1::new(),
            leaf_key_store: None,
        }
    }

    #[must_use]
    pub fn with_leaf_key_override_store(mut self, store: Arc<dyn LeafKeyOverrideStore>) -> Self {
        self.leaf_key_store = Some(store);
        self
    }

    /// Maps a flow-level [`FrostDerivation`] onto the low-level signer's
    /// [`SecretSource`] derivation path, reproducing the current key derivation
    /// exactly.
    async fn secret_source_for(
        &self,
        derivation: &FrostDerivation,
    ) -> Result<SecretSource, SignerError> {
        match derivation {
            FrostDerivation::SigningLeaf { leaf_id } => {
                if let Some(store) = &self.leaf_key_store
                    && let Some(ciphertext) = store
                        .get_leaf_key(leaf_id)
                        .await
                        .map_err(|e| SignerError::Generic(e.to_string()))?
                {
                    return Ok(SecretSource::new_encrypted(ciphertext));
                }
                Ok(SecretSource::Derived(signing_path(leaf_id)?))
            }
            FrostDerivation::StaticDeposit { index } => {
                Ok(SecretSource::Derived(static_deposit_path(*index)?))
            }
            FrostDerivation::HtlcPreimage => Err(SignerError::Generic(
                "HtlcPreimage FROST derivation not yet supported by the default adapter"
                    .to_string(),
            )),
            FrostDerivation::Identity => Err(SignerError::Generic(
                "Identity FROST derivation not supported".to_string(),
            )),
        }
    }

    async fn start_commit_first(
        &self,
        derivation: &FrostDerivation,
        user_statement: &[u8],
    ) -> Result<
        (
            PublicKey,
            frost_secp256k1_tr::round1::SigningCommitments,
            bitcoin::secp256k1::ecdsa::Signature,
        ),
        SignerError,
    > {
        let private_key = self.secret_source_for(derivation).await?;
        let signing_public_key = self.signer.public_key_from_secret(&private_key).await?;
        let nonce_commitment = self.signer.generate_random_signing_commitment().await?;
        let user_signature = self
            .signer
            .sign_message_ecdsa(&identity_path()?, user_statement)
            .await?;
        Ok((signing_public_key, nonce_commitment, user_signature))
    }

    async fn finish_commit_first(
        &self,
        derivation: &FrostDerivation,
        sighash: &[u8; 32],
        verifying_key: &PublicKey,
        nonce_commitment: &frost_secp256k1_tr::round1::SigningCommitments,
        operators: OperatorShares,
    ) -> Result<frost_secp256k1_tr::Signature, SignerError> {
        let OperatorShares {
            statechain_commitments,
            statechain_signatures,
            statechain_public_keys,
        } = operators;
        let private_key = self.secret_source_for(derivation).await?;
        let aggregating_public_key = self.signer.public_key_from_secret(&private_key).await?;
        let user_signature = self
            .signer
            .sign_frost(SignFrostRequest {
                message: sighash,
                public_key: &aggregating_public_key,
                private_key: &private_key,
                verifying_key,
                self_nonce_commitment: nonce_commitment,
                statechain_commitments: statechain_commitments.clone(),
                adaptor_public_key: None,
            })
            .await?;

        aggregate_frost(AggregateFrostRequest {
            message: sighash,
            statechain_signatures,
            statechain_public_keys,
            verifying_key,
            statechain_commitments,
            self_commitment: nonce_commitment,
            public_key: &aggregating_public_key,
            self_signature: &user_signature,
            adaptor_public_key: None,
        })
    }

    /// Signs one FROST job: generates a fresh nonce commitment, derives the
    /// signing key, and produces the round-2 share.
    async fn sign_one_frost(
        &self,
        derivation: &FrostDerivation,
        sighash: &[u8; 32],
        verifying_key: &PublicKey,
        operator_commitments: BTreeMap<Identifier, frost_secp256k1_tr::round1::SigningCommitments>,
        adaptor_public_key: Option<&PublicKey>,
    ) -> Result<FrostShareResult, SignerError> {
        let private_key = self.secret_source_for(derivation).await?;
        let public_key = self.signer.public_key_from_secret(&private_key).await?;
        let CommittedFrostShare {
            commitments,
            signature_share,
        } = self
            .signer
            .commit_and_sign_frost(CommitAndSignFrostRequest {
                message: sighash,
                public_key: &public_key,
                private_key: &private_key,
                verifying_key,
                statechain_commitments: operator_commitments,
                adaptor_public_key,
            })
            .await?;
        Ok(FrostShareResult {
            commitment: commitments,
            signature_share,
        })
    }

    /// Signs one FROST job with a nonce the signer issued earlier through
    /// [`SparkSigner::prepare_frost_nonces`]. The signer consumes that nonce
    /// (`Signer::sign_frost`), so presenting the same commitment twice fails with
    /// `UnknownNonceCommitment` instead of signing twice under one nonce.
    async fn sign_one_frost_with_nonce(
        &self,
        derivation: &FrostDerivation,
        sighash: &[u8; 32],
        verifying_key: &PublicKey,
        operator_commitments: BTreeMap<Identifier, frost_secp256k1_tr::round1::SigningCommitments>,
        adaptor_public_key: Option<&PublicKey>,
        self_nonce_commitment: SigningCommitments,
    ) -> Result<FrostShareResult, SignerError> {
        let private_key = self.secret_source_for(derivation).await?;
        let public_key = self.signer.public_key_from_secret(&private_key).await?;
        let signature_share = self
            .signer
            .sign_frost(SignFrostRequest {
                message: sighash,
                public_key: &public_key,
                private_key: &private_key,
                verifying_key,
                self_nonce_commitment: &self_nonce_commitment,
                statechain_commitments: operator_commitments,
                adaptor_public_key,
            })
            .await?;
        Ok(FrostShareResult {
            commitment: self_nonce_commitment,
            signature_share,
        })
    }

    fn decode_prepared_nonce(
        nonce: &PreparedFrostNonce,
    ) -> Result<SigningCommitments, SignerError> {
        let hiding = NonceCommitment::deserialize(&nonce.hiding_commitment)
            .map_err(|e| SignerError::SerializationError(e.to_string()))?;
        let binding = NonceCommitment::deserialize(&nonce.binding_commitment)
            .map_err(|e| SignerError::SerializationError(e.to_string()))?;
        Ok(SigningCommitments::new(hiding, binding))
    }

    fn encode_prepared_nonce(
        commitments: &SigningCommitments,
    ) -> Result<PreparedFrostNonce, SignerError> {
        Ok(PreparedFrostNonce {
            hiding_commitment: commitments
                .hiding()
                .serialize()
                .map_err(|e| SignerError::SerializationError(e.to_string()))?,
            binding_commitment: commitments
                .binding()
                .serialize()
                .map_err(|e| SignerError::SerializationError(e.to_string()))?,
        })
    }

    /// ECIES-encrypts `data` to an operator's public key (BIP-340 uncompressed
    /// SEC1, matching the rest of the codebase).
    fn encrypt_for_operator(
        &self,
        operator_public_key: &PublicKey,
        data: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        utils::ecies::encrypt(&operator_public_key.serialize_uncompressed(), data)
            .map_err(|e| SignerError::Generic(format!("ECIES encryption failed: {e}")))
    }

    /// Computes the per-operator public-key tweak shares for a Feldman split.
    fn pubkey_shares_tweak(
        &self,
        recipients: &[OperatorRecipient],
        shares: &[VerifiableSecretShare],
    ) -> Result<BTreeMap<String, Vec<u8>>, SignerError> {
        let mut pubkey_shares_tweak = BTreeMap::new();
        for recipient in recipients {
            let share = find_share(shares, recipient.id).ok_or_else(|| {
                SignerError::Generic(format!("Share not found for operator {}", recipient.id))
            })?;
            let pubkey_tweak = SecretKey::from_slice(&share.secret_share.share.to_bytes())
                .map_err(|_| SignerError::Generic("Invalid secret share".to_string()))?
                .public_key(&self.secp);
            pubkey_shares_tweak.insert(
                hex::encode(recipient.identifier.serialize()),
                pubkey_tweak.serialize().to_vec(),
            );
        }
        Ok(pubkey_shares_tweak)
    }

    fn proto_secret_share(share: &VerifiableSecretShare) -> proto::SecretShare {
        proto::SecretShare {
            secret_share: share.secret_share.share.to_bytes().to_vec(),
            proofs: share
                .proofs
                .iter()
                .map(|p| p.to_sec1_bytes().to_vec())
                .collect(),
        }
    }

    fn encrypted_bytes(source: &SecretSource) -> Result<Vec<u8>, SignerError> {
        match source {
            SecretSource::Encrypted(secret) => Ok(secret.as_slice().to_vec()),
            SecretSource::Derived(_) => Err(SignerError::Generic(
                "split key must be stored as an encrypted secret".to_string(),
            )),
        }
    }
}

/// Finds the Feldman share belonging to operator `operator_id` (share index is
/// `operator_id + 1`).
fn find_share(
    shares: &[VerifiableSecretShare],
    operator_id: usize,
) -> Option<&VerifiableSecretShare> {
    let target = k256::Scalar::from((operator_id + 1) as u64);
    shares.iter().find(|s| s.secret_share.index == target)
}

fn transfer_id_bytes(transfer_id: &crate::services::TransferId) -> Result<Vec<u8>, SignerError> {
    hex::decode(transfer_id.to_string().replace('-', ""))
        .map_err(|e| SignerError::Generic(format!("Failed to decode transfer ID: {e}")))
}

/// Derivation path for the leaf signing key derived from `leaf_id`: the `1'`
/// signing purpose followed by a hardened child from the id (sha256 of the id,
/// first 4 bytes mod 2^31).
pub fn signing_path(leaf_id: &crate::tree::TreeNodeId) -> Result<DerivationPath, SignerError> {
    let hash = sha256::Hash::hash(leaf_id.to_string().as_bytes());
    let u32_bytes: [u8; 4] = hash.as_byte_array()[..4]
        .try_into()
        .map_err(|_| SignerError::InvalidHash)?;
    let index = u32::from_be_bytes(u32_bytes) % 0x8000_0000;
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(1).map_err(|_| SignerError::InvalidHash)?,
        ChildNumber::from_hardened_idx(index).map_err(|_| SignerError::InvalidHash)?,
    ]))
}

/// Derivation path for a static-deposit key at `index`: the `3'` static-deposit
/// purpose followed by the index as a hardened child.
fn static_deposit_path(index: u32) -> Result<DerivationPath, SignerError> {
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(3)
            .map_err(|e| SignerError::Generic(format!("invalid static-deposit purpose: {e}")))?,
        ChildNumber::from_hardened_idx(index).map_err(|e| {
            SignerError::Generic(format!("failed to create child from {index}: {e}"))
        })?,
    ]))
}

/// Derivation path of the wallet identity / ECIES key: the `0'` child of the
/// account master. Identity signing and authentication use this key.
fn identity_path() -> Result<DerivationPath, SignerError> {
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(0)
            .map_err(|e| SignerError::Generic(format!("invalid identity purpose: {e}")))?,
    ]))
}

#[macros::async_trait]
impl SparkSigner for SparkSignerAdapter {
    async fn get_identity_public_key(&self) -> Result<PublicKey, SignerError> {
        self.signer.derive_public_key(&identity_path()?).await
    }

    async fn get_public_key_for_leaf(
        &self,
        leaf_id: &crate::tree::TreeNodeId,
    ) -> Result<PublicKey, SignerError> {
        let source = self
            .secret_source_for(&FrostDerivation::SigningLeaf {
                leaf_id: leaf_id.clone(),
            })
            .await?;
        self.signer.public_key_from_secret(&source).await
    }

    async fn prepare_leaf_split_keys(
        &self,
        request: PrepareLeafSplitKeysRequest,
    ) -> Result<PreparedLeafSplitKeys, SignerError> {
        if request.operation_id.is_empty() {
            return Err(SignerError::Generic(
                "split operation ID must not be empty".to_string(),
            ));
        }
        if request.child_count < 2 {
            return Err(SignerError::Generic(
                "a leaf split requires at least two children".to_string(),
            ));
        }
        let store = self.leaf_key_store.as_ref().ok_or_else(|| {
            SignerError::Generic("leaf key override store is not configured".to_string())
        })?;

        let encrypted_keys = if let Some(keys) = store
            .get_pending_split_keys(&request.operation_id, &request.parent_leaf_id)
            .await
            .map_err(|e| SignerError::Generic(e.to_string()))?
        {
            if keys.len() != request.child_count {
                return Err(SignerError::Generic(format!(
                    "split operation {} already has {} children, requested {}",
                    request.operation_id,
                    keys.len(),
                    request.child_count
                )));
            }
            keys
        } else {
            let mut remainder = self
                .secret_source_for(&FrostDerivation::SigningLeaf {
                    leaf_id: request.parent_leaf_id.clone(),
                })
                .await?;
            let mut children = Vec::with_capacity(request.child_count);
            for _ in 1..request.child_count {
                let child = SecretSource::Encrypted(self.signer.generate_random_secret().await?);
                remainder = self.signer.subtract_secrets(&remainder, &child).await?;
                children.push(Self::encrypted_bytes(&child)?);
            }
            children.push(Self::encrypted_bytes(&remainder)?);
            store
                .put_pending_split_keys(&request.operation_id, &request.parent_leaf_id, &children)
                .await
                .map_err(|e| SignerError::Generic(e.to_string()))?;
            children
        };

        let mut child_public_keys = Vec::with_capacity(encrypted_keys.len());
        for ciphertext in encrypted_keys {
            child_public_keys.push(
                self.signer
                    .public_key_from_secret(&SecretSource::new_encrypted(ciphertext))
                    .await?,
            );
        }
        Ok(PreparedLeafSplitKeys { child_public_keys })
    }

    async fn bind_leaf_split_keys(
        &self,
        request: BindLeafSplitKeysRequest,
    ) -> Result<(), SignerError> {
        let store = self.leaf_key_store.as_ref().ok_or_else(|| {
            SignerError::Generic("leaf key override store is not configured".to_string())
        })?;
        if request.child_node_ids.is_empty() {
            return Err(SignerError::Generic("missing child node IDs".to_string()));
        }
        store
            .bind_pending_split_keys(&request.operation_id, &request.child_node_ids)
            .await
            .map_err(|e| SignerError::Generic(e.to_string()))
    }

    async fn get_static_deposit_public_key(&self, index: u32) -> Result<PublicKey, SignerError> {
        self.signer
            .derive_public_key(&static_deposit_path(index)?)
            .await
    }

    async fn sign_leaf_refund_spend(
        &self,
        leaf_id: &crate::tree::TreeNodeId,
        sighash: &[u8],
    ) -> Result<bitcoin::secp256k1::schnorr::Signature, SignerError> {
        let secret = self
            .secret_source_for(&FrostDerivation::SigningLeaf {
                leaf_id: leaf_id.clone(),
            })
            .await?;
        self.signer
            .sign_hash_schnorr_with_tweak(&secret, sighash, None)
            .await
    }

    async fn sign_authentication_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, SignerError> {
        self.signer
            .sign_message_ecdsa(&identity_path()?, challenge)
            .await
    }

    async fn sign_message(
        &self,
        message: &[u8],
    ) -> Result<bitcoin::secp256k1::ecdsa::Signature, SignerError> {
        self.signer
            .sign_message_ecdsa(&identity_path()?, message)
            .await
    }

    async fn sign_frost(&self, jobs: Vec<FrostJob>) -> Result<Vec<FrostShareResult>, SignerError> {
        let mut results = Vec::with_capacity(jobs.len());
        for job in jobs {
            results.push(
                self.sign_one_frost(
                    &job.derivation,
                    &job.sighash,
                    &job.verifying_key,
                    job.operator_commitments,
                    job.adaptor_public_key.as_ref(),
                )
                .await?,
            );
        }
        Ok(results)
    }

    async fn prepare_frost_nonces(
        &self,
        count: usize,
    ) -> Result<Vec<PreparedFrostNonce>, SignerError> {
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(Self::encode_prepared_nonce(
                &self.signer.generate_random_signing_commitment().await?,
            )?);
        }
        Ok(result)
    }

    async fn sign_frost_with_nonces(
        &self,
        jobs: Vec<FrostJob>,
        nonces: Vec<PreparedFrostNonce>,
    ) -> Result<Vec<FrostShareResult>, SignerError> {
        if jobs.len() != nonces.len() {
            return Err(SignerError::Generic(format!(
                "received {} FROST jobs and {} prepared nonces",
                jobs.len(),
                nonces.len()
            )));
        }
        let mut results = Vec::with_capacity(jobs.len());
        for (job, nonce) in jobs.into_iter().zip(nonces) {
            results.push(
                self.sign_one_frost_with_nonce(
                    &job.derivation,
                    &job.sighash,
                    &job.verifying_key,
                    job.operator_commitments,
                    job.adaptor_public_key.as_ref(),
                    Self::decode_prepared_nonce(&nonce)?,
                )
                .await?,
            );
        }
        Ok(results)
    }

    async fn prepare_transfer(
        &self,
        request: PrepareTransferRequest,
    ) -> Result<PreparedTransfer, SignerError> {
        let PrepareTransferRequest {
            transfer_id,
            receiver_public_key,
            leaves,
            operator_recipients,
            threshold,
        } = request;

        // Per-operator accumulator of this transfer's leaf key tweaks.
        let mut per_operator: BTreeMap<Identifier, Vec<proto::SendLeafKeyTweak>> = BTreeMap::new();
        let mut new_leaf_keys = Vec::with_capacity(leaves.len());

        for leaf in &leaves {
            // The key the leaf is held under (upstream `LeafSigningKey`), resolved
            // through the split-key store first so a split child signs with its own key.
            let signing_key = self
                .secret_source_for(&FrostDerivation::from(&leaf.signing_key))
                .await?;
            let new_signing_key = SecretSource::Derived(signing_path(&leaf.new_leaf_id)?);

            new_leaf_keys.push(NewLeafKey {
                node_id: leaf.node.id.clone(),
                new_signing_public_key: self
                    .signer
                    .public_key_from_secret(&new_signing_key)
                    .await?,
            });

            // tweak = old - new
            let privkey_tweak = self
                .signer
                .subtract_secrets(&signing_key, &new_signing_key)
                .await?;
            let shares = self
                .signer
                .split_secret_with_proofs(
                    &SecretToSplit::SecretSource(privkey_tweak),
                    threshold,
                    operator_recipients.len(),
                )
                .await?;
            let pubkey_shares_tweak = self.pubkey_shares_tweak(&operator_recipients, &shares)?;

            // The new leaf key, encrypted for the receiver to claim with.
            let secret_cipher = self
                .signer
                .encrypt_secret_for_receiver(&new_signing_key, &receiver_public_key)
                .await?;

            // Per-leaf signature: leaf_id || transfer_id || secret_cipher.
            let mut payload = Vec::new();
            payload.extend_from_slice(leaf.node.id.to_string().as_bytes());
            payload.extend_from_slice(transfer_id.to_string().as_bytes());
            payload.extend_from_slice(&secret_cipher);
            let signature = self
                .signer
                .sign_message_ecdsa(&identity_path()?, &payload)
                .await?;

            for recipient in &operator_recipients {
                let share = find_share(&shares, recipient.id).ok_or_else(|| {
                    SignerError::Generic(format!("Share not found for operator {}", recipient.id))
                })?;
                let tweak = proto::SendLeafKeyTweak {
                    leaf_id: leaf.node.id.to_string(),
                    secret_share_tweak: Some(Self::proto_secret_share(share)),
                    pubkey_shares_tweak: pubkey_shares_tweak.clone().into_iter().collect(),
                    secret_cipher: secret_cipher.clone(),
                    sig: Some(proto::send_leaf_key_tweak::Sig::Signature(
                        signature.serialize_compact().to_vec(),
                    )),
                    refund_signature: Vec::new(),
                    direct_refund_signature: Vec::new(),
                    direct_from_cpfp_refund_signature: Vec::new(),
                };
                per_operator
                    .entry(recipient.identifier)
                    .or_default()
                    .push(tweak);
            }
        }

        // ECIES-encrypt each operator's bundle of leaf key tweaks.
        let mut key_tweak_package: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut operator_packages = Vec::with_capacity(operator_recipients.len());
        for recipient in &operator_recipients {
            let leaves_to_send = per_operator
                .remove(&recipient.identifier)
                .unwrap_or_default();
            let proto_bytes = proto::SendLeafKeyTweaks { leaves_to_send }.encode_to_vec();
            let encrypted = self.encrypt_for_operator(&recipient.public_key, &proto_bytes)?;
            key_tweak_package.insert(
                hex::encode(recipient.identifier.serialize()),
                encrypted.clone(),
            );
            operator_packages.push(OperatorPackage {
                operator_identifier: recipient.identifier,
                encrypted_package: encrypted,
            });
        }

        // Transfer-package payload signature: tag || transfer_id || tweak map.
        let signing_payload = TaggedHasher::new(&["spark", "transfer", "signing payload"])
            .add_bytes(&transfer_id_bytes(&transfer_id)?)
            .add_map_string_to_bytes(&key_tweak_package)
            .signable_message();
        let transfer_user_signature = self
            .signer
            .sign_message_ecdsa(&identity_path()?, &signing_payload)
            .await?;

        Ok(PreparedTransfer {
            operator_packages,
            new_leaf_keys,
            transfer_user_signature,
        })
    }

    async fn prepare_claim(
        &self,
        request: PrepareClaimRequest,
    ) -> Result<PreparedClaim, SignerError> {
        let PrepareClaimRequest {
            transfer_id: _,
            sender_identity_public_key: _,
            leaves,
            operator_recipients,
            threshold,
        } = request;

        // A transferred leaf keeps its node ID while ownership rotates its key.
        // If this wallet created the leaf by splitting it, the old override is
        // stale once the leaf comes back: claims always rotate to signing_path.
        // Retire it durably before any refund-key lookup can observe it.
        if let Some(store) = &self.leaf_key_store {
            let node_ids = leaves
                .iter()
                .map(|leaf| leaf.node.id.clone())
                .collect::<Vec<_>>();
            store
                .retire_leaf_keys(&node_ids)
                .await
                .map_err(|e| SignerError::Generic(e.to_string()))?;
        }

        let mut per_operator: BTreeMap<Identifier, Vec<proto::ClaimLeafKeyTweak>> = BTreeMap::new();

        for leaf in &leaves {
            // Incoming leaf key (ECIES-encrypted to our identity key by the
            // sender) and the receiver's new derived key.
            let incoming_key = SecretSource::new_encrypted(leaf.leaf_key_ciphertext.clone());
            let new_signing_key = SecretSource::Derived(signing_path(&leaf.node.id)?);

            // tweak = incoming - new
            let privkey_tweak = self
                .signer
                .subtract_secrets(&incoming_key, &new_signing_key)
                .await?;
            let shares = self
                .signer
                .split_secret_with_proofs(
                    &SecretToSplit::SecretSource(privkey_tweak),
                    threshold,
                    operator_recipients.len(),
                )
                .await?;
            let pubkey_shares_tweak = self.pubkey_shares_tweak(&operator_recipients, &shares)?;

            for recipient in &operator_recipients {
                let share = find_share(&shares, recipient.id).ok_or_else(|| {
                    SignerError::Generic(format!("Share not found for operator {}", recipient.id))
                })?;
                let tweak = proto::ClaimLeafKeyTweak {
                    leaf_id: leaf.node.id.to_string(),
                    secret_share_tweak: Some(Self::proto_secret_share(share)),
                    pubkey_shares_tweak: pubkey_shares_tweak.clone().into_iter().collect(),
                };
                per_operator
                    .entry(recipient.identifier)
                    .or_default()
                    .push(tweak);
            }
        }

        // ECIES-encrypt each operator's bundle of claim key tweaks. The
        // claim-package user signature is produced by the orchestration layer.
        let mut operator_packages = Vec::with_capacity(operator_recipients.len());
        for recipient in &operator_recipients {
            let leaves_to_receive = per_operator
                .remove(&recipient.identifier)
                .unwrap_or_default();
            let proto_bytes = proto::ClaimLeafKeyTweaks { leaves_to_receive }.encode_to_vec();
            let encrypted = self.encrypt_for_operator(&recipient.public_key, &proto_bytes)?;
            operator_packages.push(OperatorPackage {
                operator_identifier: recipient.identifier,
                encrypted_package: encrypted,
            });
        }

        Ok(PreparedClaim { operator_packages })
    }

    async fn prepare_lightning_receive(
        &self,
        request: PrepareLightningReceiveRequest,
    ) -> Result<PreparedLightningReceive, SignerError> {
        let PrepareLightningReceiveRequest {
            operator_recipients,
            threshold,
        } = request;

        // Generate a preimage in-process; only its hash leaves this method.
        let preimage: [u8; PREIMAGE_LEN] = {
            let mut rng = thread_rng();
            let sk = SecretKey::new(&mut rng);
            sk.secret_bytes()
        };
        let payment_hash = sha256::Hash::hash(&preimage).to_byte_array();

        let shares = self
            .signer
            .split_secret_with_proofs(
                &SecretToSplit::Preimage(preimage.to_vec()),
                threshold,
                operator_recipients.len(),
            )
            .await?;

        let mut operator_preimage_packages = Vec::with_capacity(operator_recipients.len());
        for recipient in &operator_recipients {
            let share = find_share(&shares, recipient.id).ok_or_else(|| {
                SignerError::Generic(format!("Share not found for operator {}", recipient.id))
            })?;
            let proto_bytes = Self::proto_secret_share(share).encode_to_vec();
            let encrypted = self.encrypt_for_operator(&recipient.public_key, &proto_bytes)?;
            operator_preimage_packages.push(OperatorPackage {
                operator_identifier: recipient.identifier,
                encrypted_package: encrypted,
            });
        }

        Ok(PreparedLightningReceive {
            payment_hash,
            operator_preimage_packages,
        })
    }

    async fn prepare_static_deposit(
        &self,
        request: PrepareStaticDepositRequest,
    ) -> Result<PreparedStaticDeposit, SignerError> {
        let PrepareStaticDepositRequest {
            index,
            ssp_public_key,
            frost_jobs,
        } = request;

        // Export the static-deposit secret (encrypted) to the SSP.
        let exported_secret = self
            .signer
            .encrypt_secret_for_receiver(
                &SecretSource::Derived(static_deposit_path(index)?),
                &ssp_public_key,
            )
            .await?;

        let frost_shares = self.sign_frost(frost_jobs).await?;

        Ok(PreparedStaticDeposit {
            exported_secret,
            frost_shares,
        })
    }

    async fn start_static_deposit_refund(
        &self,
        request: StartStaticDepositRefundRequest,
    ) -> Result<StartedStaticDepositRefund, SignerError> {
        let StartStaticDepositRefundRequest {
            index,
            user_statement,
        } = request;
        let (signing_public_key, nonce_commitment, user_signature) = self
            .start_commit_first(&FrostDerivation::StaticDeposit { index }, &user_statement)
            .await?;
        Ok(StartedStaticDepositRefund {
            signing_public_key,
            nonce_commitment,
            user_signature,
        })
    }

    async fn sign_static_deposit_refund(
        &self,
        request: SignStaticDepositRefundRequest,
    ) -> Result<frost_secp256k1_tr::Signature, SignerError> {
        let SignStaticDepositRefundRequest {
            index,
            sighash,
            verifying_key,
            nonce_commitment,
            statechain_commitments,
            statechain_signatures,
            statechain_public_keys,
        } = request;
        self.finish_commit_first(
            &FrostDerivation::StaticDeposit { index },
            &sighash,
            &verifying_key,
            &nonce_commitment,
            OperatorShares {
                statechain_commitments,
                statechain_signatures,
                statechain_public_keys,
            },
        )
        .await
    }

    async fn start_watchtower_exit_recovery(
        &self,
        request: StartWatchtowerExitRecoveryRequest,
    ) -> Result<StartedWatchtowerExitRecovery, SignerError> {
        let StartWatchtowerExitRecoveryRequest {
            leaf_id,
            user_statement,
        } = request;
        let (signing_public_key, nonce_commitment, user_signature) = self
            .start_commit_first(&FrostDerivation::SigningLeaf { leaf_id }, &user_statement)
            .await?;
        Ok(StartedWatchtowerExitRecovery {
            signing_public_key,
            nonce_commitment,
            user_signature,
        })
    }

    async fn sign_watchtower_exit_recovery(
        &self,
        request: SignWatchtowerExitRecoveryRequest,
    ) -> Result<frost_secp256k1_tr::Signature, SignerError> {
        let SignWatchtowerExitRecoveryRequest {
            leaf_id,
            sighash,
            verifying_key,
            nonce_commitment,
            statechain_commitments,
            statechain_signatures,
            statechain_public_keys,
        } = request;
        self.finish_commit_first(
            &FrostDerivation::SigningLeaf { leaf_id },
            &sighash,
            &verifying_key,
            &nonce_commitment,
            OperatorShares {
                statechain_commitments,
                statechain_signatures,
                statechain_public_keys,
            },
        )
        .await
    }

    async fn prepare_static_deposit_claim(
        &self,
        request: PrepareStaticDepositClaimRequest,
    ) -> Result<PreparedStaticDepositClaim, SignerError> {
        let PrepareStaticDepositClaimRequest {
            index,
            user_statement,
        } = request;

        // The SSP co-signs the claim, so it needs the static-deposit secret in
        // the clear (the exported/local-key path).
        let deposit_secret_key = self.signer.secret_key(&static_deposit_path(index)?).await?;
        let user_signature = self
            .signer
            .sign_message_ecdsa(&identity_path()?, &user_statement)
            .await?;

        Ok(PreparedStaticDepositClaim {
            deposit_secret_key,
            user_signature,
        })
    }

    async fn sign_spark_invoice(
        &self,
        request: SignSparkInvoiceRequest,
    ) -> Result<SignedSparkInvoice, SignerError> {
        let signature = self
            .signer
            .sign_hash_schnorr(&identity_path()?, &request.invoice_hash)
            .await?;
        Ok(SignedSparkInvoice { signature })
    }

    async fn prepare_token_transaction(
        &self,
        request: PrepareTokenTransactionRequest,
    ) -> Result<PreparedTokenTransaction, SignerError> {
        let signature = self
            .signer
            .sign_hash_schnorr(&identity_path()?, &request.digest)
            .await?;
        Ok(PreparedTokenTransaction { signature })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use frost_secp256k1_tr::Identifier;
    use macros::async_test_all;
    use prost::Message as _;

    use super::SparkSignerAdapter;
    use crate::operator::rpc::spark as proto;
    use crate::services::TransferId;
    use crate::signer::{
        LeafSigningKey, OperatorRecipient, PrepareTransferRequest, SparkSigner, TransferLeafInput,
        create_test_signer,
    };
    use crate::tree::TreeNodeId;
    use crate::tree::tests::create_test_tree_node;

    /// Operators whose identity keys the test holds, so it can open the
    /// packages the adapter encrypts to them.
    fn operators() -> Vec<(OperatorRecipient, SecretKey)> {
        let secp = Secp256k1::new();
        (0..3u16)
            .map(|id| {
                let secret = SecretKey::from_slice(&[id as u8 + 1; 32]).unwrap();
                let recipient = OperatorRecipient {
                    id: usize::from(id),
                    identifier: Identifier::try_from(id + 1).unwrap(),
                    public_key: PublicKey::from_secret_key(&secp, &secret),
                };
                (recipient, secret)
            })
            .collect()
    }

    /// Sends one leaf held under the key derived from `held_under`, and returns
    /// the leaf's key tweak as each operator reads it (the public key of the
    /// split secret, `proofs[0]`), plus the new key it tweaks towards.
    async fn tweak_seen_by_operators(
        adapter: &SparkSignerAdapter,
        node_id: &str,
        held_under: &TreeNodeId,
    ) -> (Vec<PublicKey>, PublicKey) {
        let operators = operators();
        let new_leaf_id = TreeNodeId::generate();
        let prepared = adapter
            .prepare_transfer(PrepareTransferRequest {
                transfer_id: TransferId::generate(),
                receiver_public_key: adapter.get_identity_public_key().await.unwrap(),
                leaves: vec![TransferLeafInput {
                    node: create_test_tree_node(node_id, 1_000),
                    new_leaf_id: new_leaf_id.clone(),
                    signing_key: LeafSigningKey {
                        derived_from: held_under.clone(),
                    },
                }],
                operator_recipients: operators.iter().map(|(r, _)| r.clone()).collect(),
                threshold: 2,
            })
            .await
            .unwrap();

        let new_key = prepared.new_leaf_keys[0].new_signing_public_key;
        assert_eq!(
            new_key,
            adapter.get_public_key_for_leaf(&new_leaf_id).await.unwrap(),
            "the leaf moves to the key derived from the new leaf id"
        );

        let mut tweaks = Vec::new();
        for (recipient, secret) in &operators {
            let package = prepared
                .operator_packages
                .iter()
                .find(|p| p.operator_identifier == recipient.identifier)
                .expect("a package for every operator");
            let plain = utils::ecies::decrypt(&secret.secret_bytes(), &package.encrypted_package)
                .expect("the package opens with the operator's key");
            let leaves = proto::SendLeafKeyTweaks::decode(plain.as_slice())
                .unwrap()
                .leaves_to_send;
            assert_eq!(leaves.len(), 1);
            assert_eq!(
                leaves[0].leaf_id, node_id,
                "the operators know the leaf by its node id"
            );
            let proofs = &leaves[0].secret_share_tweak.as_ref().unwrap().proofs;
            tweaks.push(PublicKey::from_slice(&proofs[0]).unwrap());
        }
        (tweaks, new_key)
    }

    /// A leaf held under a key derived from another id is tweaked away from that
    /// key: the operators' view of the tweak plus the new key adds back up to
    /// it, not to the key derived from the node id.
    #[async_test_all]
    async fn a_transfer_tweaks_away_from_the_key_the_leaf_is_held_under() {
        let adapter = SparkSignerAdapter::new(Arc::new(create_test_signer()));
        let held_under = TreeNodeId::generate();
        let held_key = adapter.get_public_key_for_leaf(&held_under).await.unwrap();
        let node_key = adapter
            .get_public_key_for_leaf(&"leaf".parse().unwrap())
            .await
            .unwrap();

        let (tweaks, new_key) = tweak_seen_by_operators(&adapter, "leaf", &held_under).await;

        for tweak in tweaks {
            let old_key = tweak.combine(&new_key).unwrap();
            assert_eq!(old_key, held_key);
            assert_ne!(old_key, node_key);
        }
    }

    /// A leaf held under the key derived from its own node id, as every leaf a
    /// wallet receives is, is tweaked away from that key.
    #[async_test_all]
    async fn a_transfer_of_a_received_leaf_tweaks_away_from_its_node_id_key() {
        let adapter = SparkSignerAdapter::new(Arc::new(create_test_signer()));
        let node_id: TreeNodeId = "leaf".parse().unwrap();
        let node_key = adapter.get_public_key_for_leaf(&node_id).await.unwrap();

        let (tweaks, new_key) = tweak_seen_by_operators(&adapter, "leaf", &node_id).await;

        for tweak in tweaks {
            assert_eq!(tweak.combine(&new_key).unwrap(), node_key);
        }
    }
}

#[cfg(test)]
mod split_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use macros::async_test_all;
    use platform_utils::tokio::sync::Mutex;

    use super::*;
    use crate::Network;
    use crate::services::TransferId;
    use crate::signer::{DefaultSigner, LeafKeyOverrideStoreError};
    use crate::tree::TreeNodeId;
    use crate::tree::tests::create_test_tree_node;

    type PendingKeys = HashMap<String, (TreeNodeId, Vec<Vec<u8>>)>;

    #[derive(Default)]
    struct TestLeafKeyStore {
        pending: Mutex<PendingKeys>,
        leaves: Mutex<HashMap<TreeNodeId, Vec<u8>>>,
    }

    #[macros::async_trait]
    impl LeafKeyOverrideStore for TestLeafKeyStore {
        async fn get_leaf_key(
            &self,
            node_id: &TreeNodeId,
        ) -> Result<Option<Vec<u8>>, LeafKeyOverrideStoreError> {
            Ok(self.leaves.lock().await.get(node_id).cloned())
        }

        async fn get_pending_split_keys(
            &self,
            operation_id: &str,
            parent_node_id: &TreeNodeId,
        ) -> Result<Option<Vec<Vec<u8>>>, LeafKeyOverrideStoreError> {
            self.pending
                .lock()
                .await
                .get(operation_id)
                .map(|(stored_parent, keys)| {
                    if stored_parent != parent_node_id {
                        Err(LeafKeyOverrideStoreError::Generic(
                            "operation parent mismatch".to_string(),
                        ))
                    } else {
                        Ok(keys.clone())
                    }
                })
                .transpose()
        }

        async fn put_pending_split_keys(
            &self,
            operation_id: &str,
            parent_node_id: &TreeNodeId,
            encrypted_keys: &[Vec<u8>],
        ) -> Result<(), LeafKeyOverrideStoreError> {
            let mut pending = self.pending.lock().await;
            if let Some((existing_parent, existing)) = pending.get(operation_id) {
                if existing_parent != parent_node_id || existing != encrypted_keys {
                    return Err(LeafKeyOverrideStoreError::Generic(
                        "operation key mismatch".to_string(),
                    ));
                }
                return Ok(());
            }
            pending.insert(
                operation_id.to_string(),
                (parent_node_id.clone(), encrypted_keys.to_vec()),
            );
            Ok(())
        }

        async fn bind_pending_split_keys(
            &self,
            operation_id: &str,
            node_ids: &[TreeNodeId],
        ) -> Result<(), LeafKeyOverrideStoreError> {
            let keys = self
                .pending
                .lock()
                .await
                .get(operation_id)
                .map(|(_, keys)| keys.clone())
                .ok_or_else(|| LeafKeyOverrideStoreError::Generic("missing keys".to_string()))?;
            if keys.len() != node_ids.len() {
                return Err(LeafKeyOverrideStoreError::Generic(
                    "key count mismatch".to_string(),
                ));
            }
            let mut leaves = self.leaves.lock().await;
            for (node_id, key) in node_ids.iter().cloned().zip(keys) {
                if let Some(existing) = leaves.get(&node_id)
                    && existing != &key
                {
                    return Err(LeafKeyOverrideStoreError::Generic(
                        "bound key mismatch".to_string(),
                    ));
                }
                leaves.insert(node_id, key);
            }
            Ok(())
        }

        async fn retire_leaf_keys(
            &self,
            node_ids: &[TreeNodeId],
        ) -> Result<(), LeafKeyOverrideStoreError> {
            let mut leaves = self.leaves.lock().await;
            for node_id in node_ids {
                leaves.remove(node_id);
            }
            Ok(())
        }
    }

    fn combine(keys: &[PublicKey]) -> PublicKey {
        keys[1..]
            .iter()
            .try_fold(keys[0], |sum, key| sum.combine(key))
            .unwrap()
    }

    #[async_test_all]
    async fn split_keys_conserve_parent_and_survive_restart_and_resplit() {
        let store = Arc::new(TestLeafKeyStore::default());
        let low_signer = Arc::new(DefaultSigner::new(&[42; 32], Network::Regtest).unwrap());
        let parent_id = TreeNodeId::generate();
        let adapter =
            SparkSignerAdapter::new(low_signer.clone()).with_leaf_key_override_store(store.clone());
        let parent_public_key = adapter.get_public_key_for_leaf(&parent_id).await.unwrap();

        let first = adapter
            .prepare_leaf_split_keys(PrepareLeafSplitKeysRequest {
                operation_id: "first".to_string(),
                parent_leaf_id: parent_id.clone(),
                child_count: 3,
            })
            .await
            .unwrap();
        assert_eq!(combine(&first.child_public_keys), parent_public_key);
        let retry = adapter
            .prepare_leaf_split_keys(PrepareLeafSplitKeysRequest {
                operation_id: "first".to_string(),
                parent_leaf_id: parent_id,
                child_count: 3,
            })
            .await
            .unwrap();
        assert_eq!(retry.child_public_keys, first.child_public_keys);

        let child_ids = vec![
            TreeNodeId::generate(),
            TreeNodeId::generate(),
            TreeNodeId::generate(),
        ];
        adapter
            .bind_leaf_split_keys(BindLeafSplitKeysRequest {
                operation_id: "first".to_string(),
                child_node_ids: child_ids.clone(),
            })
            .await
            .unwrap();

        let restarted = SparkSignerAdapter::new(low_signer).with_leaf_key_override_store(store);
        assert_eq!(
            restarted
                .get_public_key_for_leaf(&child_ids[0])
                .await
                .unwrap(),
            first.child_public_keys[0]
        );
        let second = restarted
            .prepare_leaf_split_keys(PrepareLeafSplitKeysRequest {
                operation_id: "second".to_string(),
                parent_leaf_id: child_ids[0].clone(),
                child_count: 2,
            })
            .await
            .unwrap();
        assert_eq!(
            combine(&second.child_public_keys),
            first.child_public_keys[0]
        );
    }

    #[async_test_all]
    async fn claiming_a_previously_split_node_retires_its_stale_override() {
        let store = Arc::new(TestLeafKeyStore::default());
        let low_signer = Arc::new(DefaultSigner::new(&[43; 32], Network::Regtest).unwrap());
        let adapter =
            SparkSignerAdapter::new(low_signer.clone()).with_leaf_key_override_store(store.clone());
        let parent_id = TreeNodeId::generate();
        let prepared = adapter
            .prepare_leaf_split_keys(PrepareLeafSplitKeysRequest {
                operation_id: "claim-rotation".to_string(),
                parent_leaf_id: parent_id.clone(),
                child_count: 2,
            })
            .await
            .unwrap();
        let child_ids = vec![TreeNodeId::generate(), TreeNodeId::generate()];
        adapter
            .bind_leaf_split_keys(BindLeafSplitKeysRequest {
                operation_id: "claim-rotation".to_string(),
                child_node_ids: child_ids.clone(),
            })
            .await
            .unwrap();

        let returning_id = child_ids[0].clone();
        assert_eq!(
            adapter
                .get_public_key_for_leaf(&returning_id)
                .await
                .unwrap(),
            prepared.child_public_keys[0]
        );
        let derived_key = low_signer
            .derive_public_key(&signing_path(&returning_id).unwrap())
            .await
            .unwrap();
        assert_ne!(derived_key, prepared.child_public_keys[0]);

        let identity_public_key = adapter.get_identity_public_key().await.unwrap();
        let incoming_secret = low_signer.generate_random_secret().await.unwrap();
        let incoming_ciphertext = low_signer
            .encrypt_secret_for_receiver(
                &SecretSource::Encrypted(incoming_secret),
                &identity_public_key,
            )
            .await
            .unwrap();
        let operator_recipients = (0..3)
            .map(|id| OperatorRecipient {
                id,
                identifier: Identifier::try_from((id + 1) as u16).unwrap(),
                public_key: identity_public_key,
            })
            .collect();

        adapter
            .prepare_claim(PrepareClaimRequest {
                transfer_id: TransferId::generate(),
                sender_identity_public_key: identity_public_key,
                leaves: vec![ClaimLeafInput {
                    node: create_test_tree_node(&returning_id.to_string(), 2_000),
                    sender_signature: Vec::new(),
                    leaf_key_ciphertext: incoming_ciphertext,
                }],
                operator_recipients,
                threshold: 2,
            })
            .await
            .unwrap();

        assert_eq!(
            adapter
                .get_public_key_for_leaf(&returning_id)
                .await
                .unwrap(),
            derived_key
        );
        assert!(
            store
                .get_pending_split_keys("claim-rotation", &parent_id)
                .await
                .unwrap()
                .is_some(),
            "retiring a bound override must not delete its pending split record"
        );
    }
}
