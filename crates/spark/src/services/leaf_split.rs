use std::str::FromStr;
use std::sync::Arc;

use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Amount, ScriptBuf, TxOut};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::Network;
use crate::bitcoin::sighash_from_tx;
use crate::operator::OperatorPool;
use crate::operator::rpc::{self as operator_rpc};
use crate::signer::{
    AggregateFrostRequest, BindLeafSplitKeysRequest, FrostDerivation, FrostJob,
    PrepareLeafSplitKeysRequest, PreparedFrostNonce, SparkSigner,
};
use crate::tree::{TreeNode, TreeNodeId, TreeNodeStatus};
use crate::utils::frost::aggregate_frost;
use crate::utils::transactions::{
    NodeTransactions, RefundTransactions, create_initial_timelock_node_txs_at_vout,
    create_initial_timelock_refund_txs, create_split_txs,
};

use super::ServiceError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum SplitJobOwner {
    Parent,
    Child(usize),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SplitSigningJobPlan {
    owner: SplitJobOwner,
    transaction: Vec<u8>,
    previous_output_value: u64,
    previous_output_script: Vec<u8>,
    signing_public_key: Vec<u8>,
    verifying_public_key: Vec<u8>,
    nonce: PreparedFrostNonce,
}

/// Fully prepared, serializable split request. Persist this before submission.
/// Retrying the same plan reuses both the idempotency key and nonce commitments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafSplitPlan {
    pub operation_id: String,
    pub parent_node_id: TreeNodeId,
    pub child_values: Vec<u64>,
    create_tree_request: Vec<u8>,
    signing_jobs: Vec<SplitSigningJobPlan>,
}

/// Local-only first phase of a split. The signer has durably stored the child
/// keys when this is returned; no operator RPC has happened yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafSplitDraft {
    pub operation_id: String,
    pub parent_node_id: TreeNodeId,
    pub child_values: Vec<u64>,
    child_public_keys: Vec<Vec<u8>>,
}

/// Operator response paired with its exact plan. Persist this before finalization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmittedLeafSplit {
    pub plan: LeafSplitPlan,
    create_tree_response: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SplitLeafResult {
    pub children: Vec<TreeNode>,
}

/// Performs SSP-authorized tree creation through a private operator pool and
/// finalizes signatures through the ordinary operator pool.
pub struct LeafSplitService {
    network: Network,
    operator_pool: Arc<OperatorPool>,
    ssp_operator_pool: Arc<OperatorPool>,
    spark_signer: Arc<dyn SparkSigner>,
    identity_public_key: PublicKey,
}

impl LeafSplitService {
    pub async fn new(
        network: Network,
        operator_pool: Arc<OperatorPool>,
        ssp_operator_pool: Arc<OperatorPool>,
        spark_signer: Arc<dyn SparkSigner>,
    ) -> Result<Self, ServiceError> {
        let identity_public_key = spark_signer.get_identity_public_key().await?;
        // Validate the public coordinator and mint its session before any
        // split mutation. A shared SessionStore lets the private pool reuse it;
        // otherwise the private listener authenticates independently.
        operator_pool
            .get_coordinator()
            .client
            .get_signing_operator_list()
            .await?;
        Ok(Self {
            network,
            operator_pool,
            ssp_operator_pool,
            spark_signer,
            identity_public_key,
        })
    }

    pub async fn draft_split(
        &self,
        operation_id: String,
        parent: &TreeNode,
        child_values: Vec<u64>,
    ) -> Result<LeafSplitDraft, ServiceError> {
        validate_split(operation_id.as_str(), parent, &child_values)?;
        let prepared_keys = self
            .spark_signer
            .prepare_leaf_split_keys(PrepareLeafSplitKeysRequest {
                operation_id: operation_id.clone(),
                parent_leaf_id: parent.id.clone(),
                child_count: child_values.len(),
            })
            .await?;
        Ok(LeafSplitDraft {
            operation_id,
            parent_node_id: parent.id.clone(),
            child_values,
            child_public_keys: prepared_keys
                .child_public_keys
                .iter()
                .map(|key| key.serialize().to_vec())
                .collect(),
        })
    }

    pub async fn prepare_split(
        &self,
        draft: &LeafSplitDraft,
        parent: &TreeNode,
    ) -> Result<LeafSplitPlan, ServiceError> {
        validate_split(&draft.operation_id, parent, &draft.child_values)?;
        if draft.parent_node_id != parent.id {
            return Err(ServiceError::InvalidInput(
                "split draft parent does not match supplied parent".to_string(),
            ));
        }
        let child_public_keys = draft
            .child_public_keys
            .iter()
            .map(|key| PublicKey::from_slice(key).map_err(|_| ServiceError::InvalidPublicKey))
            .collect::<Result<Vec<_>, _>>()?;
        let parent_public_key = self
            .spark_signer
            .get_public_key_for_leaf(&parent.id)
            .await?;

        let source = operator_rpc::spark::prepare_tree_address_request::Source::ParentNodeOutput(
            operator_rpc::spark::NodeOutput {
                node_id: parent.id.to_string(),
                vout: 0,
            },
        );
        let address_response = self
            .ssp_operator_pool
            .get_coordinator()
            .client
            .prepare_tree_address(operator_rpc::spark::PrepareTreeAddressRequest {
                source: Some(source),
                node: Some(operator_rpc::spark::AddressRequestNode {
                    user_public_key: parent_public_key.serialize().to_vec(),
                    children: child_public_keys
                        .iter()
                        .map(|key| operator_rpc::spark::AddressRequestNode {
                            user_public_key: key.serialize().to_vec(),
                            children: Vec::new(),
                        })
                        .collect(),
                }),
                user_identity_public_key: self.identity_public_key.serialize().to_vec(),
            })
            .await?;
        let address_root = address_response
            .node
            .ok_or_else(|| ServiceError::Generic("missing prepared address root".to_string()))?;
        let root_address = address_root
            .address
            .as_ref()
            .ok_or_else(|| ServiceError::Generic("missing prepared root address".to_string()))?;
        let root_verifying_key = PublicKey::from_slice(&root_address.verifying_key)
            .map_err(|_| ServiceError::InvalidVerifyingKey)?;
        if root_verifying_key != parent.verifying_public_key {
            return Err(ServiceError::InvalidVerifyingKey);
        }
        if address_root.children.len() != draft.child_values.len() {
            return Err(ServiceError::Generic(format!(
                "operator returned {} child addresses, expected {}",
                address_root.children.len(),
                draft.child_values.len()
            )));
        }

        let mut child_outputs = Vec::with_capacity(draft.child_values.len());
        let mut child_verifying_keys = Vec::with_capacity(draft.child_values.len());
        for (value, address_node) in draft.child_values.iter().zip(&address_root.children) {
            let address = address_node.address.as_ref().ok_or_else(|| {
                ServiceError::Generic("missing prepared child address".to_string())
            })?;
            let parsed = Address::<NetworkUnchecked>::from_str(&address.address)
                .map_err(|_| ServiceError::InvalidDepositAddress)?
                .require_network(self.network.into())
                .map_err(|_| ServiceError::InvalidDepositAddressNetwork)?;
            child_outputs.push(TxOut {
                value: Amount::from_sat(*value),
                script_pubkey: parsed.script_pubkey(),
            });
            child_verifying_keys.push(
                PublicKey::from_slice(&address.verifying_key)
                    .map_err(|_| ServiceError::InvalidVerifyingKey)?,
            );
        }

        let NodeTransactions {
            cpfp_tx: split_tx,
            direct_tx: direct_split_tx,
        } = create_split_txs(&parent.node_tx, 0, child_outputs)?;
        let nonce_count = 2 + draft.child_values.len() * 5;
        let nonces = self.spark_signer.prepare_frost_nonces(nonce_count).await?;
        let mut nonce_iter = nonces.into_iter();
        let parent_output = parent
            .node_tx
            .output
            .first()
            .ok_or(ServiceError::InvalidOutputIndex)?
            .clone();

        let mut signing_jobs = Vec::with_capacity(nonce_count);
        let root_cpfp_nonce = next_nonce(&mut nonce_iter)?;
        signing_jobs.push(job_plan(
            SplitJobOwner::Parent,
            &split_tx,
            &parent_output,
            parent_public_key,
            parent.verifying_public_key,
            root_cpfp_nonce.clone(),
        ));
        let root_direct_nonce = next_nonce(&mut nonce_iter)?;
        signing_jobs.push(job_plan(
            SplitJobOwner::Parent,
            &direct_split_tx,
            &parent_output,
            parent_public_key,
            parent.verifying_public_key,
            root_direct_nonce.clone(),
        ));

        let mut children = Vec::with_capacity(draft.child_values.len());
        for (index, (signing_public_key, verifying_public_key)) in child_public_keys
            .iter()
            .copied()
            .zip(child_verifying_keys.iter().copied())
            .enumerate()
        {
            let NodeTransactions {
                cpfp_tx: child_tx,
                direct_tx: child_direct_tx,
            } = create_initial_timelock_node_txs_at_vout(&split_tx, index as u32)?;
            let RefundTransactions {
                cpfp_tx: refund_tx,
                direct_tx: direct_refund_tx,
                direct_from_cpfp_tx,
            } = create_initial_timelock_refund_txs(
                &child_tx,
                Some(&child_direct_tx),
                &signing_public_key,
                self.network,
            )?;
            let direct_refund_tx = direct_refund_tx.ok_or_else(|| {
                ServiceError::Generic("missing direct refund transaction".to_string())
            })?;
            let direct_from_cpfp_tx = direct_from_cpfp_tx.ok_or_else(|| {
                ServiceError::Generic("missing direct-from-CPFP refund transaction".to_string())
            })?;
            let split_output = split_tx.output[index].clone();
            let child_output = child_tx.output[0].clone();
            let child_direct_output = child_direct_tx.output[0].clone();
            let owner = SplitJobOwner::Child(index);
            let child_nonces: Vec<_> = (0..5)
                .map(|_| next_nonce(&mut nonce_iter))
                .collect::<Result<_, _>>()?;
            for (tx, prevout, nonce) in [
                (&child_tx, &split_output, child_nonces[0].clone()),
                (&child_direct_tx, &split_output, child_nonces[1].clone()),
                (&refund_tx, &child_output, child_nonces[2].clone()),
                (
                    &direct_refund_tx,
                    &child_direct_output,
                    child_nonces[3].clone(),
                ),
                (&direct_from_cpfp_tx, &child_output, child_nonces[4].clone()),
            ] {
                signing_jobs.push(job_plan(
                    owner.clone(),
                    tx,
                    prevout,
                    signing_public_key,
                    verifying_public_key,
                    nonce,
                ));
            }
            children.push(operator_rpc::spark::CreationNode {
                // ponytail: no fee-bump ladder on split children (optional upstream, SP-4089); add when
                // split leaves need the ladder like transfers with fee_ladder_enabled.
                refund_ladder: None,
                node_tx_signing_job: Some(proto_job(
                    &child_tx,
                    signing_public_key,
                    &child_nonces[0],
                )),
                refund_tx_signing_job: Some(proto_job(
                    &refund_tx,
                    signing_public_key,
                    &child_nonces[2],
                )),
                children: Vec::new(),
                direct_node_tx_signing_job: Some(proto_job(
                    &child_direct_tx,
                    signing_public_key,
                    &child_nonces[1],
                )),
                direct_refund_tx_signing_job: Some(proto_job(
                    &direct_refund_tx,
                    signing_public_key,
                    &child_nonces[3],
                )),
                direct_from_cpfp_refund_tx_signing_job: Some(proto_job(
                    &direct_from_cpfp_tx,
                    signing_public_key,
                    &child_nonces[4],
                )),
            });
        }

        let request = operator_rpc::spark::CreateTreeRequest {
            source: Some(
                operator_rpc::spark::create_tree_request::Source::ParentNodeOutput(
                    operator_rpc::spark::NodeOutput {
                        node_id: parent.id.to_string(),
                        vout: 0,
                    },
                ),
            ),
            node: Some(operator_rpc::spark::CreationNode {
                // ponytail: no fee-bump ladder on split children (optional upstream, SP-4089); add when
                // split leaves need the ladder like transfers with fee_ladder_enabled.
                refund_ladder: None,
                node_tx_signing_job: Some(proto_job(
                    &split_tx,
                    parent_public_key,
                    &root_cpfp_nonce,
                )),
                refund_tx_signing_job: None,
                children,
                direct_node_tx_signing_job: Some(proto_job(
                    &direct_split_tx,
                    parent_public_key,
                    &root_direct_nonce,
                )),
                direct_refund_tx_signing_job: None,
                direct_from_cpfp_refund_tx_signing_job: None,
            }),
            user_identity_public_key: self.identity_public_key.serialize().to_vec(),
        };

        Ok(LeafSplitPlan {
            operation_id: draft.operation_id.clone(),
            parent_node_id: parent.id.clone(),
            child_values: draft.child_values.clone(),
            create_tree_request: request.encode_to_vec(),
            signing_jobs,
        })
    }

    /// Submit exactly the persisted plan. Persist the returned value before
    /// calling `finalize_split` so a crash never loses operator shares.
    pub async fn submit_split(
        &self,
        plan: LeafSplitPlan,
    ) -> Result<SubmittedLeafSplit, ServiceError> {
        let request =
            operator_rpc::spark::CreateTreeRequest::decode(plan.create_tree_request.as_slice())
                .map_err(|e| ServiceError::Generic(format!("invalid split plan: {e}")))?;
        let response = self
            .ssp_operator_pool
            .get_coordinator()
            .client
            .create_tree(request, plan.operation_id.clone())
            .await?;
        Ok(SubmittedLeafSplit {
            plan,
            create_tree_response: response.encode_to_vec(),
        })
    }

    pub async fn finalize_split(
        &self,
        submitted: &SubmittedLeafSplit,
    ) -> Result<SplitLeafResult, ServiceError> {
        let response = operator_rpc::spark::CreateTreeResponse::decode(
            submitted.create_tree_response.as_slice(),
        )
        .map_err(|e| ServiceError::Generic(format!("invalid submitted split: {e}")))?;
        let root = response
            .node
            .ok_or_else(|| ServiceError::Generic("missing created tree root".to_string()))?;
        if root.children.len() != submitted.plan.child_values.len() {
            return Err(ServiceError::Generic(format!(
                "operator created {} children, expected {}",
                root.children.len(),
                submitted.plan.child_values.len()
            )));
        }
        let child_node_ids = root
            .children
            .iter()
            .map(|child| {
                child
                    .node_id
                    .parse()
                    .map_err(|_| ServiceError::InvalidNodeId(child.node_id.clone()))
            })
            .collect::<Result<Vec<TreeNodeId>, _>>()?;

        // Install the overrides before any child signatures are produced. A
        // crash after this point can safely resume using either pending or
        // bound lookup, and normal wallet operations resolve the same keys.
        self.spark_signer
            .bind_leaf_split_keys(BindLeafSplitKeysRequest {
                operation_id: submitted.plan.operation_id.clone(),
                child_node_ids: child_node_ids.clone(),
            })
            .await?;

        let signing_results = response_signing_results(&root)?;
        if signing_results.len() != submitted.plan.signing_jobs.len() {
            return Err(ServiceError::Generic(format!(
                "operator returned {} signing results, expected {}",
                signing_results.len(),
                submitted.plan.signing_jobs.len()
            )));
        }

        let mut frost_jobs = Vec::with_capacity(signing_results.len());
        for (plan, result) in submitted.plan.signing_jobs.iter().zip(&signing_results) {
            let tx = plan.transaction()?;
            let sighash = sighash_from_tx(&tx, 0, &plan.previous_output())?;
            let verifying_key = PublicKey::from_slice(&plan.verifying_public_key)
                .map_err(|_| ServiceError::InvalidVerifyingKey)?;
            let parsed_result: super::models::SigningResult = (*result).try_into()?;
            frost_jobs.push(FrostJob {
                derivation: plan.derivation(&submitted.plan.parent_node_id, &child_node_ids)?,
                sighash: sighash.to_raw_hash().to_byte_array(),
                verifying_key,
                operator_commitments: parsed_result.signing_commitments,
                adaptor_public_key: None,
            });
        }
        let shares = self
            .spark_signer
            .sign_frost_with_nonces(
                frost_jobs.clone(),
                submitted
                    .plan
                    .signing_jobs
                    .iter()
                    .map(|job| job.nonce.clone())
                    .collect(),
            )
            .await?;
        if shares.len() != signing_results.len() {
            return Err(ServiceError::Generic(format!(
                "signer returned {} shares, expected {}",
                shares.len(),
                signing_results.len()
            )));
        }

        let mut signatures = Vec::with_capacity(shares.len());
        for (((plan, result), job), share) in submitted
            .plan
            .signing_jobs
            .iter()
            .zip(signing_results)
            .zip(frost_jobs)
            .zip(shares)
        {
            let signing_public_key = PublicKey::from_slice(&plan.signing_public_key)
                .map_err(|_| ServiceError::InvalidPublicKey)?;
            let parsed_result: super::models::SigningResult = result.try_into()?;
            signatures.push(
                aggregate_frost(AggregateFrostRequest {
                    message: &job.sighash,
                    statechain_signatures: parsed_result.signature_shares,
                    statechain_public_keys: parsed_result.public_keys,
                    verifying_key: &job.verifying_key,
                    statechain_commitments: parsed_result.signing_commitments,
                    self_commitment: &share.commitment,
                    public_key: &signing_public_key,
                    self_signature: &share.signature_share,
                    adaptor_public_key: None,
                })?
                .serialize()
                .map_err(|_| ServiceError::InvalidSignatureShare)?
                .to_vec(),
            );
        }

        let root_signatures = operator_rpc::spark::NodeSignatures {
            node_id: root.node_id.clone(),
            node_tx_signature: signatures[0].clone(),
            refund_tx_signature: Vec::new(),
            direct_node_tx_signature: signatures[1].clone(),
            direct_refund_tx_signature: Vec::new(),
            direct_from_cpfp_refund_tx_signature: Vec::new(),
        };
        let mut node_signatures = vec![root_signatures];
        for (index, child) in root.children.iter().enumerate() {
            let base = 2 + index * 5;
            node_signatures.push(operator_rpc::spark::NodeSignatures {
                node_id: child.node_id.clone(),
                node_tx_signature: signatures[base].clone(),
                refund_tx_signature: signatures[base + 2].clone(),
                direct_node_tx_signature: signatures[base + 1].clone(),
                direct_refund_tx_signature: signatures[base + 3].clone(),
                direct_from_cpfp_refund_tx_signature: signatures[base + 4].clone(),
            });
        }
        let finalized = self
            .operator_pool
            .get_coordinator()
            .client
            .finalize_node_signatures_v2(operator_rpc::spark::FinalizeNodeSignaturesRequest {
                node_signatures,
                intent: operator_rpc::common::SignatureIntent::Creation as i32,
            })
            .await?;
        let children = finalized
            .nodes
            .into_iter()
            .map(TreeNode::try_from)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|node| child_node_ids.contains(&node.id))
            .collect();
        Ok(SplitLeafResult { children })
    }
}

fn response_signing_results(
    root: &operator_rpc::spark::CreationResponseNode,
) -> Result<Vec<&operator_rpc::spark::SigningResult>, ServiceError> {
    let mut results = Vec::with_capacity(2 + root.children.len() * 5);
    results.push(
        root.node_tx_signing_result
            .as_ref()
            .ok_or(ServiceError::MissingTreeSignatures)?,
    );
    results.push(
        root.direct_node_tx_signing_result
            .as_ref()
            .ok_or(ServiceError::MissingTreeSignatures)?,
    );
    for child in &root.children {
        results.push(
            child
                .node_tx_signing_result
                .as_ref()
                .ok_or(ServiceError::MissingTreeSignatures)?,
        );
        results.push(
            child
                .direct_node_tx_signing_result
                .as_ref()
                .ok_or(ServiceError::MissingTreeSignatures)?,
        );
        results.push(
            child
                .refund_tx_signing_result
                .as_ref()
                .ok_or(ServiceError::MissingTreeSignatures)?,
        );
        results.push(
            child
                .direct_refund_tx_signing_result
                .as_ref()
                .ok_or(ServiceError::MissingTreeSignatures)?,
        );
        results.push(
            child
                .direct_from_cpfp_refund_tx_signing_result
                .as_ref()
                .ok_or(ServiceError::MissingTreeSignatures)?,
        );
    }
    Ok(results)
}

fn validate_split(
    operation_id: &str,
    parent: &TreeNode,
    child_values: &[u64],
) -> Result<(), ServiceError> {
    if operation_id.is_empty() {
        return Err(ServiceError::InvalidInput(
            "split operation ID must not be empty".to_string(),
        ));
    }
    if parent.status != TreeNodeStatus::Available {
        return Err(ServiceError::InvalidInput(format!(
            "parent leaf {} is not available",
            parent.id
        )));
    }
    if child_values.len() < 2 || child_values.contains(&0) {
        return Err(ServiceError::InvalidInput(
            "a split requires at least two non-zero child values".to_string(),
        ));
    }
    let total = child_values
        .iter()
        .try_fold(0_u64, |sum, value| sum.checked_add(*value))
        .ok_or_else(|| ServiceError::InvalidInput("split value overflow".to_string()))?;
    if total != parent.value {
        return Err(ServiceError::InvalidInput(format!(
            "split children total {total} does not equal parent value {}",
            parent.value
        )));
    }
    Ok(())
}

fn next_nonce(
    nonces: &mut impl Iterator<Item = PreparedFrostNonce>,
) -> Result<PreparedFrostNonce, ServiceError> {
    nonces
        .next()
        .ok_or_else(|| ServiceError::Generic("missing prepared split nonce".to_string()))
}

fn proto_job(
    tx: &bitcoin::Transaction,
    public_key: PublicKey,
    nonce: &PreparedFrostNonce,
) -> operator_rpc::spark::SigningJob {
    operator_rpc::spark::SigningJob {
        signing_public_key: public_key.serialize().to_vec(),
        raw_tx: serialize(tx),
        signing_nonce_commitment: Some(operator_rpc::common::SigningCommitment {
            hiding: nonce.hiding_commitment.clone(),
            binding: nonce.binding_commitment.clone(),
        }),
    }
}

fn job_plan(
    owner: SplitJobOwner,
    tx: &bitcoin::Transaction,
    previous_output: &TxOut,
    signing_public_key: PublicKey,
    verifying_public_key: PublicKey,
    nonce: PreparedFrostNonce,
) -> SplitSigningJobPlan {
    SplitSigningJobPlan {
        owner,
        transaction: serialize(tx),
        previous_output_value: previous_output.value.to_sat(),
        previous_output_script: previous_output.script_pubkey.as_bytes().to_vec(),
        signing_public_key: signing_public_key.serialize().to_vec(),
        verifying_public_key: verifying_public_key.serialize().to_vec(),
        nonce,
    }
}

impl SplitSigningJobPlan {
    fn transaction(&self) -> Result<bitcoin::Transaction, ServiceError> {
        deserialize(&self.transaction).map_err(|_| ServiceError::InvalidTransaction)
    }

    fn previous_output(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.previous_output_value),
            script_pubkey: ScriptBuf::from_bytes(self.previous_output_script.clone()),
        }
    }

    fn derivation(
        &self,
        parent_id: &TreeNodeId,
        child_node_ids: &[TreeNodeId],
    ) -> Result<FrostDerivation, ServiceError> {
        match self.owner {
            SplitJobOwner::Parent => Ok(FrostDerivation::SigningLeaf {
                leaf_id: parent_id.clone(),
            }),
            SplitJobOwner::Child(child_index) => Ok(FrostDerivation::SigningLeaf {
                leaf_id: child_node_ids
                    .get(child_index)
                    .ok_or_else(|| {
                        ServiceError::Generic("missing split child node ID".to_string())
                    })?
                    .clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        OutPoint, Sequence, Transaction, TxIn, absolute::LockTime, transaction::Version,
    };

    use super::*;

    #[test]
    fn signing_job_request_contains_complete_persisted_material() {
        let key = bitcoin::secp256k1::SecretKey::from_slice(&[7; 32])
            .unwrap()
            .public_key(&bitcoin::secp256k1::Secp256k1::new());
        let tx = Transaction {
            version: Version::non_standard(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                sequence: Sequence::ZERO,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let nonce = PreparedFrostNonce {
            hiding_commitment: vec![1; 33],
            binding_commitment: vec![2; 33],
        };

        let request = proto_job(&tx, key, &nonce);
        assert_eq!(request.raw_tx, serialize(&tx));
        assert_eq!(request.signing_public_key, key.serialize());
        let commitment = request.signing_nonce_commitment.unwrap();
        assert_eq!(commitment.hiding, nonce.hiding_commitment);
        assert_eq!(commitment.binding, nonce.binding_commitment);

        let plan = LeafSplitPlan {
            operation_id: "operation".to_string(),
            parent_node_id: "parent".parse().unwrap(),
            child_values: vec![400, 600],
            create_tree_request: vec![4, 5],
            signing_jobs: vec![job_plan(
                SplitJobOwner::Parent,
                &tx,
                &tx.output[0],
                key,
                key,
                nonce,
            )],
        };
        let encoded = serde_json::to_vec(&plan).unwrap();
        assert_eq!(
            serde_json::from_slice::<LeafSplitPlan>(&encoded).unwrap(),
            plan
        );
    }
}
