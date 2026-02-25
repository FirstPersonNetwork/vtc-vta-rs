use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use crate::keys::{KeyRecord, KeyStatus, KeyType};

/// HTTP client for the VTA service API.
pub struct VtaClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(default)]
    pub mediator_url: Option<String>,
    #[serde(default)]
    pub mediator_did: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigResponse {
    #[serde(rename = "vta_did")]
    pub community_vta_did: Option<String>,
    #[serde(rename = "vta_name")]
    pub community_vta_name: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyRequest {
    pub key_type: KeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

// ── Context types ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateContextRequest {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateContextRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContextResponse {
    pub id: String,
    pub name: String,
    pub did: Option<String>,
    pub description: Option<String>,
    pub base_path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ContextListResponse {
    pub contexts: Vec<ContextResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CreateKeyResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub derivation_path: String,
    pub public_key: String,
    pub status: KeyStatus,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct InvalidateKeyResponse {
    pub key_id: String,
    pub status: KeyStatus,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct RenameKeyRequest {
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RenameKeyResponse {
    pub key_id: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct GetKeySecretResponse {
    pub key_id: String,
    pub key_type: KeyType,
    pub public_key_multibase: String,
    pub private_key_multibase: String,
}

#[derive(Debug, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Seed types ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SeedInfoResponse {
    pub id: u32,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListSeedsResponse {
    pub seeds: Vec<SeedInfoResponse>,
    pub active_seed_id: u32,
}

#[derive(Debug, Serialize)]
pub struct RotateSeedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RotateSeedResponse {
    pub previous_seed_id: u32,
    pub new_seed_id: u32,
}

// ── ACL types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AclEntryResponse {
    pub did: String,
    pub role: String,
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
    pub created_at: u64,
    pub created_by: String,
}

#[derive(Debug, Deserialize)]
pub struct AclListResponse {
    pub entries: Vec<AclEntryResponse>,
}

#[derive(Debug, Serialize)]
pub struct CreateAclRequest {
    pub did: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateAclRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_contexts: Option<Vec<String>>,
}

// ── WebVH server types ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct AddWebvhServerRequest {
    pub id: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateWebvhServerRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

// ── WebVH DID types ─────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateDidWebvhRequest {
    pub context_id: String,
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub portable: bool,
    pub add_mediator_service: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_services: Option<Vec<serde_json::Value>>,
    pub pre_rotation_count: u32,
}

// ── Credential types ────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct GenerateCredentialsRequest {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed_contexts: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GenerateCredentialsResponse {
    pub did: String,
    pub credential: String,
    pub role: String,
}

/// Percent-encode characters that are not safe in URL path segments.
///
/// DID verification method IDs contain `#` (fragment delimiter) and potentially
/// `?` (query delimiter) which must be encoded when used in path segments.
/// Derivation paths contain `/` which would be interpreted as path separators.
/// The `:` character is allowed in path segments per RFC 3986.
fn encode_path_segment(s: &str) -> String {
    s.replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F")
        .replace('/', "%2F")
}

// ── Client implementation ───────────────────────────────────────────

impl VtaClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: None,
        }
    }

    /// Set the Bearer token for authenticated requests.
    pub fn set_token(&mut self, token: String) {
        self.token = Some(token);
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Attach Bearer token to a request if one is set.
    fn with_auth(&self, req: RequestBuilder) -> RequestBuilder {
        match &self.token {
            Some(token) => req.bearer_auth(token),
            None => req,
        }
    }

    /// GET /health
    pub async fn health(&self) -> Result<HealthResponse, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        Self::handle_response(resp).await
    }

    /// GET /config
    pub async fn get_config(&self) -> Result<ConfigResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!("{}/config", self.base_url));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// PATCH /config
    pub async fn update_config(
        &self,
        req: UpdateConfigRequest,
    ) -> Result<ConfigResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .patch(format!("{}/config", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// POST /keys
    pub async fn create_key(
        &self,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .post(format!("{}/keys", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /keys
    pub async fn list_keys(
        &self,
        offset: u64,
        limit: u64,
        status: Option<&str>,
        context_id: Option<&str>,
    ) -> Result<ListKeysResponse, Box<dyn std::error::Error>> {
        let mut url = format!("{}/keys?offset={}&limit={}", self.base_url, offset, limit);
        if let Some(s) = status {
            url.push_str(&format!("&status={s}"));
        }
        if let Some(ctx) = context_id {
            url.push_str(&format!("&context_id={ctx}"));
        }
        let req = self.client.get(url);
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /keys/{key_id}
    pub async fn get_key(&self, key_id: &str) -> Result<KeyRecord, Box<dyn std::error::Error>> {
        let req = self.client.get(format!(
            "{}/keys/{}",
            self.base_url,
            encode_path_segment(key_id)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /keys/{key_id}/secret
    pub async fn get_key_secret(
        &self,
        key_id: &str,
    ) -> Result<GetKeySecretResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!(
            "{}/keys/{}/secret",
            self.base_url,
            encode_path_segment(key_id)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /keys/{key_id}
    pub async fn invalidate_key(
        &self,
        key_id: &str,
    ) -> Result<InvalidateKeyResponse, Box<dyn std::error::Error>> {
        let req = self.client.delete(format!(
            "{}/keys/{}",
            self.base_url,
            encode_path_segment(key_id)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// PATCH /keys/{key_id}
    pub async fn rename_key(
        &self,
        key_id: &str,
        new_key_id: &str,
    ) -> Result<RenameKeyResponse, Box<dyn std::error::Error>> {
        let body = RenameKeyRequest {
            key_id: new_key_id.to_string(),
        };
        let req = self
            .client
            .patch(format!(
                "{}/keys/{}",
                self.base_url,
                encode_path_segment(key_id)
            ))
            .json(&body);
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    // ── Seed methods ────────────────────────────────────────────────

    /// GET /keys/seeds
    pub async fn list_seeds(&self) -> Result<ListSeedsResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!("{}/keys/seeds", self.base_url));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// POST /keys/seeds/rotate
    pub async fn rotate_seed(
        &self,
        mnemonic: Option<String>,
    ) -> Result<RotateSeedResponse, Box<dyn std::error::Error>> {
        let body = RotateSeedRequest { mnemonic };
        let r = self
            .client
            .post(format!("{}/keys/seeds/rotate", self.base_url))
            .json(&body);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    // ── ACL methods ─────────────────────────────────────────────────

    /// GET /acl
    pub async fn list_acl(
        &self,
        context: Option<&str>,
    ) -> Result<AclListResponse, Box<dyn std::error::Error>> {
        let mut url = format!("{}/acl", self.base_url);
        if let Some(ctx) = context {
            url.push_str(&format!("?context={ctx}"));
        }
        let req = self.client.get(url);
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /acl/{did}
    pub async fn get_acl(&self, did: &str) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!(
            "{}/acl/{}",
            self.base_url,
            encode_path_segment(did)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// POST /acl
    pub async fn create_acl(
        &self,
        req: CreateAclRequest,
    ) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .post(format!("{}/acl", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// PATCH /acl/{did}
    pub async fn update_acl(
        &self,
        did: &str,
        req: UpdateAclRequest,
    ) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .patch(format!(
                "{}/acl/{}",
                self.base_url,
                encode_path_segment(did)
            ))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /acl/{did}
    pub async fn delete_acl(&self, did: &str) -> Result<(), Box<dyn std::error::Error>> {
        let req = self.client.delete(format!(
            "{}/acl/{}",
            self.base_url,
            encode_path_segment(did)
        ));
        let resp = self.with_auth(req).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }

    // ── Credential methods ──────────────────────────────────────────

    /// POST /auth/credentials
    pub async fn generate_credentials(
        &self,
        req: GenerateCredentialsRequest,
    ) -> Result<GenerateCredentialsResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .post(format!("{}/auth/credentials", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    // ── Context methods ──────────────────────────────────────────────

    /// GET /contexts
    pub async fn list_contexts(&self) -> Result<ContextListResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!("{}/contexts", self.base_url));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /contexts/{id}
    pub async fn get_context(
        &self,
        id: &str,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        let req = self.client.get(format!(
            "{}/contexts/{}",
            self.base_url,
            encode_path_segment(id)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// POST /contexts
    pub async fn create_context(
        &self,
        req: CreateContextRequest,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .post(format!("{}/contexts", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// PATCH /contexts/{id}
    pub async fn update_context(
        &self,
        id: &str,
        req: UpdateContextRequest,
    ) -> Result<ContextResponse, Box<dyn std::error::Error>> {
        let r = self
            .client
            .patch(format!(
                "{}/contexts/{}",
                self.base_url,
                encode_path_segment(id)
            ))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    // ── WebVH server methods ──────────────────────────────────────────

    /// POST /webvh/servers
    pub async fn add_webvh_server(
        &self,
        req: AddWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, Box<dyn std::error::Error>> {
        let r = self
            .client
            .post(format!("{}/webvh/servers", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /webvh/servers
    pub async fn list_webvh_servers(
        &self,
    ) -> Result<
        crate::protocols::did_management::servers::ListWebvhServersResultBody,
        Box<dyn std::error::Error>,
    > {
        let req = self
            .client
            .get(format!("{}/webvh/servers", self.base_url));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// PATCH /webvh/servers/{id}
    pub async fn update_webvh_server(
        &self,
        id: &str,
        req: UpdateWebvhServerRequest,
    ) -> Result<crate::webvh::WebvhServerRecord, Box<dyn std::error::Error>> {
        let r = self
            .client
            .patch(format!(
                "{}/webvh/servers/{}",
                self.base_url,
                encode_path_segment(id)
            ))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /webvh/servers/{id}
    pub async fn remove_webvh_server(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let req = self.client.delete(format!(
            "{}/webvh/servers/{}",
            self.base_url,
            encode_path_segment(id)
        ));
        let resp = self.with_auth(req).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }

    // ── WebVH DID methods ──────────────────────────────────────────

    /// POST /webvh/dids
    pub async fn create_did_webvh(
        &self,
        req: CreateDidWebvhRequest,
    ) -> Result<
        crate::protocols::did_management::create::CreateDidWebvhResultBody,
        Box<dyn std::error::Error>,
    > {
        let r = self
            .client
            .post(format!("{}/webvh/dids", self.base_url))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /webvh/dids
    pub async fn list_dids_webvh(
        &self,
        context_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<
        crate::protocols::did_management::list::ListDidsWebvhResultBody,
        Box<dyn std::error::Error>,
    > {
        let mut url = format!("{}/webvh/dids", self.base_url);
        let mut sep = '?';
        if let Some(ctx) = context_id {
            url.push_str(&format!("{sep}context_id={ctx}"));
            sep = '&';
        }
        if let Some(srv) = server_id {
            url.push_str(&format!("{sep}server_id={srv}"));
        }
        let req = self.client.get(url);
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /webvh/dids/{did}
    pub async fn get_did_webvh(
        &self,
        did: &str,
    ) -> Result<crate::webvh::WebvhDidRecord, Box<dyn std::error::Error>> {
        let req = self.client.get(format!(
            "{}/webvh/dids/{}",
            self.base_url,
            encode_path_segment(did)
        ));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /webvh/dids/{did}
    pub async fn delete_did_webvh(&self, did: &str) -> Result<(), Box<dyn std::error::Error>> {
        let req = self.client.delete(format!(
            "{}/webvh/dids/{}",
            self.base_url,
            encode_path_segment(did)
        ));
        let resp = self.with_auth(req).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }

    /// DELETE /contexts/{id}
    pub async fn delete_context(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let req = self.client.delete(format!(
            "{}/contexts/{}",
            self.base_url,
            encode_path_segment(id)
        ));
        let resp = self.with_auth(req).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, Box<dyn std::error::Error>> {
        if resp.status().is_success() {
            Ok(resp.json::<T>().await?)
        } else {
            let status = resp.status();
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map(|e| e.error)
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(format!("{status}: {body}").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── encode_path_segment ─────────────────────────────────────────

    #[test]
    fn test_encode_hash_in_did_fragment() {
        assert_eq!(
            encode_path_segment("did:key:z6Mk123#z6Mk123"),
            "did:key:z6Mk123%23z6Mk123"
        );
    }

    #[test]
    fn test_encode_question_mark() {
        assert_eq!(encode_path_segment("foo?bar"), "foo%3Fbar");
    }

    #[test]
    fn test_encode_percent_is_escaped_first() {
        assert_eq!(encode_path_segment("100%#done"), "100%25%23done");
    }

    #[test]
    fn test_encode_colon_preserved() {
        assert_eq!(encode_path_segment("did:key:z6Mk"), "did:key:z6Mk");
    }

    #[test]
    fn test_encode_plain_string_unchanged() {
        assert_eq!(encode_path_segment("simple-id"), "simple-id");
    }

    #[test]
    fn test_encode_multiple_hashes() {
        assert_eq!(encode_path_segment("a#b#c"), "a%23b%23c");
    }

    #[test]
    fn test_encode_slash_in_derivation_path() {
        assert_eq!(
            encode_path_segment("m/44'/0'/0'/0"),
            "m%2F44'%2F0'%2F0'%2F0"
        );
    }

    // ── VtaClient::new ──────────────────────────────────────────────

    #[test]
    fn test_new_strips_trailing_slash() {
        let client = VtaClient::new("http://localhost:3000/");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_strips_multiple_trailing_slashes() {
        let client = VtaClient::new("http://localhost:3000///");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_no_trailing_slash_unchanged() {
        let client = VtaClient::new("http://localhost:3000");
        assert_eq!(client.base_url(), "http://localhost:3000");
    }

    #[test]
    fn test_new_token_initially_none() {
        let client = VtaClient::new("http://example.com");
        assert!(client.token.is_none());
    }

    #[test]
    fn test_set_token() {
        let mut client = VtaClient::new("http://example.com");
        client.set_token("my-jwt".to_string());
        assert_eq!(client.token.as_deref(), Some("my-jwt"));
    }

    // ── Request/Response serialization ──────────────────────────────

    #[test]
    fn test_update_config_skips_none_fields() {
        let req = UpdateConfigRequest {
            vta_did: None,
            vta_name: Some("Test".into()),
            public_url: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("vta_did"));
        assert_eq!(json["vta_name"], "Test");
        assert!(!json.as_object().unwrap().contains_key("public_url"));
    }

    #[test]
    fn test_create_key_request_serialization() {
        let req = CreateKeyRequest {
            key_type: KeyType::Ed25519,
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some("test key".into()),
            context_id: Some("vta".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(!json.as_object().unwrap().contains_key("derivation_path"));
        assert!(!json.as_object().unwrap().contains_key("key_id"));
        assert!(!json.as_object().unwrap().contains_key("mnemonic"));
        assert_eq!(json["label"], "test key");
        assert_eq!(json["context_id"], "vta");
    }

    #[test]
    fn test_create_acl_request_serialization() {
        let req = CreateAclRequest {
            did: "did:key:z6Mk123".into(),
            role: "admin".into(),
            label: None,
            allowed_contexts: vec!["vta".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["did"], "did:key:z6Mk123");
        assert_eq!(json["role"], "admin");
        assert!(!json.as_object().unwrap().contains_key("label"));
        assert_eq!(json["allowed_contexts"], serde_json::json!(["vta"]));
    }

    #[test]
    fn test_update_acl_request_all_none() {
        let req = UpdateAclRequest {
            role: None,
            label: None,
            allowed_contexts: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.is_empty(), "all-None request should serialize to {{}}");
    }

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{"status":"ok","version":"0.1.0"}"#;
        let resp: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.version, "0.1.0");
    }

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"error":"not found"}"#;
        let resp: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.error, "not found");
    }

    #[test]
    fn test_list_keys_response_deserialization() {
        let json = r#"{"keys":[],"total":0}"#;
        let resp: ListKeysResponse = serde_json::from_str(json).unwrap();
        assert!(resp.keys.is_empty());
        assert_eq!(resp.total, 0);
    }

    #[test]
    fn test_generate_credentials_response_deserialization() {
        let json = r#"{"did":"did:key:z6Mk123","credential":"abc123","role":"admin"}"#;
        let resp: GenerateCredentialsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.did, "did:key:z6Mk123");
        assert_eq!(resp.credential, "abc123");
        assert_eq!(resp.role, "admin");
    }

    #[test]
    fn test_acl_list_response_deserialization() {
        let json = r#"{"entries":[{"did":"did:key:z6Mk1","role":"admin","label":null,"allowed_contexts":[],"created_at":1700000000,"created_by":"setup"}]}"#;
        let resp: AclListResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].did, "did:key:z6Mk1");
        assert_eq!(resp.entries[0].role, "admin");
        assert!(resp.entries[0].allowed_contexts.is_empty());
    }

    #[test]
    fn test_context_response_deserialization() {
        let json = r#"{"id":"vta","name":"Verified Trust Agent","did":null,"description":null,"base_path":"m/26'/2'/0'","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let resp: ContextResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "vta");
        assert_eq!(resp.name, "Verified Trust Agent");
        assert!(resp.did.is_none());
        assert_eq!(resp.base_path, "m/26'/2'/0'");
    }
}
