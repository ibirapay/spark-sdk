//! Typed access to durable SSP request history and BOLT12 offers.
use super::{ServiceProvider, ServiceProviderError};
use graphql_client::{GraphQLQuery, QueryBody};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestRecord {
    pub id: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub network: String,
    #[serde(flatten)]
    pub details: std::collections::BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Serialize)]
pub struct RequestHistoryFilter {
    pub first: u32,
    pub after: Option<String>,
    pub types: Option<Vec<String>>,
    pub statuses: Option<Vec<String>>,
    pub networks: Option<Vec<String>>,
}
impl Default for RequestHistoryFilter {
    fn default() -> Self {
        Self {
            first: 100,
            after: None,
            types: None,
            statuses: None,
            networks: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPage {
    pub entities: Vec<RequestRecord>,
    pub page_info: RequestPageInfo,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPageInfo {
    pub has_next_page: bool,
    pub end_cursor: Option<String>,
}

// The server extension keeps its request metadata while the common fields are
// typed above. These documents use the same authenticated transport as all
// other SDK SSP calls; callers do not create sessions or send GraphQL text.
macro_rules! query {
    ($name:ident,$document:expr) => {
        struct $name;
        impl GraphQLQuery for $name {
            type Variables = Value;
            type ResponseData = Value;
            fn build_query(variables: Value) -> QueryBody<Value> {
                QueryBody {
                    variables,
                    operation_name: stringify!($name),
                    query: $document,
                }
            }
        }
    };
}
query!(
    UserRequest,
    r#"query UserRequest($request_id:ID!) { user_request(request_id:$request_id) { id created_at updated_at network ... on ClaimStaticDeposit { status transaction_id output_index credit_amount { original_value original_unit preferred_currency_unit preferred_currency_value_rounded } deposit_amount { original_value original_unit preferred_currency_unit preferred_currency_value_rounded } max_fee { original_value original_unit preferred_currency_unit preferred_currency_value_rounded } transfer_spark_id } ... on LightningSendRequest { status encoded_invoice idempotency_key } ... on LightningReceiveRequest { status invoice { encoded_invoice payment_hash } } ... on LeavesSwapRequest { status } ... on CoopExitRequest { status coop_exit_txid } } }"#
);
query!(
    FetchCurrentUserToUserRequestsConnection,
    r#"query FetchCurrentUserToUserRequestsConnection($first:Int!,$after:String,$types:[String!],$statuses:[String!],$networks:[BitcoinNetwork!]) { current_user { user_requests(first:$first,after:$after,types:$types,statuses:$statuses,networks:$networks) { entities { id created_at updated_at network ... on ClaimStaticDeposit { status transaction_id output_index transfer_spark_id } ... on LightningSendRequest { status encoded_invoice } ... on LightningReceiveRequest { status } ... on LeavesSwapRequest { status } ... on CoopExitRequest { status } } page_info { has_next_page end_cursor } } } }"#
);
query!(
    RequestBolt12Receive,
    r#"mutation RequestBolt12Receive($amount_sats:Long!,$network:BitcoinNetwork!,$memo:String!,$expiry_secs:Int!) { request_lightning_receive: request_bolt12_receive(input:{amount_sats:$amount_sats,network:$network,memo:$memo,expiry_secs:$expiry_secs}) { request { id created_at updated_at network status invoice { encoded_invoice payment_hash } } } }"#
);
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ServiceProviderError> {
    serde_json::from_value(value).map_err(|e| ServiceProviderError::Serialization(e.to_string()))
}
impl ServiceProvider {
    pub async fn get_request_record(
        &self,
        id: &str,
    ) -> Result<Option<RequestRecord>, ServiceProviderError> {
        let response = self
            .gql_client
            .post_query::<UserRequest, _>(json!({"request_id":id}))
            .await?;
        decode(response["user_request"].clone())
    }
    pub async fn list_request_history(
        &self,
        filter: RequestHistoryFilter,
    ) -> Result<RequestPage, ServiceProviderError> {
        if !(1..=100).contains(&filter.first) {
            return Err(ServiceProviderError::Generic(
                "history page size must be 1 to 100".into(),
            ));
        }
        let response = self
            .gql_client
            .post_query::<FetchCurrentUserToUserRequestsConnection, _>(
                serde_json::to_value(filter)
                    .map_err(|e| ServiceProviderError::Serialization(e.to_string()))?,
            )
            .await?;
        decode(response["current_user"]["user_requests"].clone())
    }
    pub async fn request_bolt12_receive(
        &self,
        amount_sats: u64,
        network: &str,
        memo: &str,
        expiry_secs: u32,
    ) -> Result<RequestRecord, ServiceProviderError> {
        let response=self.gql_client.post_query::<RequestBolt12Receive,_>(json!({"amount_sats":amount_sats,"network":network,"memo":memo,"expiry_secs":expiry_secs})).await?;
        decode(response["request_lightning_receive"]["request"].clone())
    }
}
