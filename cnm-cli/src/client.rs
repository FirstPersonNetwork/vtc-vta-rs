use chrono::{DateTime, Utc};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use vtc_vta_sdk::keys::{KeyRecord, KeyStatus, KeyType};

/// HTTP client for the VTC-VTA service API.
pub struct VtaClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigResponse {
    pub vta_did: Option<String>,
    pub community_name: Option<String>,
    pub community_description: Option<String>,
    pub public_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateConfigRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_description: Option<String>,
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
pub struct ListKeysResponse {
    pub keys: Vec<KeyRecord>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}

#[derive(Debug, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
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
/// The `:` character is allowed in path segments per RFC 3986.
fn encode_path_segment(s: &str) -> String {
    s.replace('%', "%25")
        .replace('#', "%23")
        .replace('?', "%3F")
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
        let r = self.client.patch(format!("{}/config", self.base_url)).json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// POST /keys
    pub async fn create_key(
        &self,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, Box<dyn std::error::Error>> {
        let r = self.client.post(format!("{}/keys", self.base_url)).json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /keys
    pub async fn list_keys(
        &self,
        offset: u64,
        limit: u64,
        status: Option<&str>,
    ) -> Result<ListKeysResponse, Box<dyn std::error::Error>> {
        let mut url = format!("{}/keys?offset={}&limit={}", self.base_url, offset, limit);
        if let Some(s) = status {
            url.push_str(&format!("&status={s}"));
        }
        let req = self.client.get(url);
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// GET /keys/{key_id}
    pub async fn get_key(
        &self,
        key_id: &str,
    ) -> Result<KeyRecord, Box<dyn std::error::Error>> {
        let req = self
            .client
            .get(format!("{}/keys/{}", self.base_url, encode_path_segment(key_id)));
        let resp = self.with_auth(req).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /keys/{key_id}
    pub async fn invalidate_key(
        &self,
        key_id: &str,
    ) -> Result<InvalidateKeyResponse, Box<dyn std::error::Error>> {
        let req = self
            .client
            .delete(format!("{}/keys/{}", self.base_url, encode_path_segment(key_id)));
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
            .patch(format!("{}/keys/{}", self.base_url, encode_path_segment(key_id)))
            .json(&body);
        let resp = self.with_auth(req).send().await?;
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
    pub async fn get_acl(
        &self,
        did: &str,
    ) -> Result<AclEntryResponse, Box<dyn std::error::Error>> {
        let req = self
            .client
            .get(format!("{}/acl/{}", self.base_url, encode_path_segment(did)));
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
            .patch(format!("{}/acl/{}", self.base_url, encode_path_segment(did)))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /acl/{did}
    pub async fn delete_acl(
        &self,
        did: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = self
            .client
            .delete(format!("{}/acl/{}", self.base_url, encode_path_segment(did)));
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
        let req = self
            .client
            .get(format!("{}/contexts/{}", self.base_url, encode_path_segment(id)));
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
            .patch(format!("{}/contexts/{}", self.base_url, encode_path_segment(id)))
            .json(&req);
        let resp = self.with_auth(r).send().await?;
        Self::handle_response(resp).await
    }

    /// DELETE /contexts/{id}
    pub async fn delete_context(
        &self,
        id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let req = self
            .client
            .delete(format!("{}/contexts/{}", self.base_url, encode_path_segment(id)));
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
