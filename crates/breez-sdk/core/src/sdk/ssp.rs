//! Rust SSP APIs for applications that need explicit quote and request control.
use super::BreezSdk;
use crate::{
    InstantStaticDepositPlan, InstantStaticDepositQuote, InstantStaticDepositQuoteResult, SdkError,
    ServiceProvider,
};
use std::sync::Arc;
impl BreezSdk {
    /// Generate a single-use deposit address for explicit operator deposit claims.
    pub async fn generate_single_use_deposit_address(&self) -> Result<String, SdkError> {
        Ok(self
            .spark_wallet
            .generate_deposit_address()
            .await?
            .address
            .to_string())
    }
    /// Claim a confirmed single-use output using the wallet's configured signer.
    pub async fn claim_single_use_deposit(
        &self,
        transaction_hex: &str,
        output_index: u32,
    ) -> Result<(), SdkError> {
        let bytes = hex::decode(transaction_hex).map_err(|e| SdkError::Generic(e.to_string()))?;
        let transaction = bitcoin::consensus::deserialize(&bytes)
            .map_err(|e| SdkError::Generic(e.to_string()))?;
        self.spark_wallet
            .claim_deposit(transaction, output_index)
            .await?;
        Ok(())
    }

    pub fn service_provider(&self) -> Arc<ServiceProvider> {
        self.spark_wallet.service_provider()
    }
    /// Fetch an upstream instant quote for an explicit funding transaction.
    pub async fn get_instant_deposit_quote(
        &self,
        transaction_hex: &str,
        output_index: u32,
    ) -> Result<InstantStaticDepositQuoteResult, SdkError> {
        let transaction = bitcoin::consensus::encode::deserialize_hex(transaction_hex)
            .map_err(|e| SdkError::Generic(e.to_string()))?;
        Ok(self
            .spark_wallet
            .fetch_instant_static_deposit_quote(transaction, Some(output_index))
            .await?)
    }
    /// Use upstream quote validation, claim signing, and key encryption.
    pub async fn claim_instant_deposit(
        &self,
        transaction_hex: &str,
        quote: InstantStaticDepositQuote,
        plan: InstantStaticDepositPlan,
    ) -> Result<String, SdkError> {
        let transaction = bitcoin::consensus::encode::deserialize_hex(transaction_hex)
            .map_err(|e| SdkError::Generic(e.to_string()))?;
        Ok(self
            .spark_wallet
            .claim_instant_static_deposit(transaction, quote, plan)
            .await?)
    }
}
