use super::internal_server::*;
use crate::cache::TokenCache;
use crate::hybrid_flow;
use azure_core::credentials::TokenCredential;
use azure_core::{
    credentials::AccessToken,
    error::ErrorKind,
    http::{new_http_client, Url},
    Error,
};
use base64::engine::general_purpose;
use base64::Engine;
use oauth2::TokenResponse;
use oauth2::{AuthorizationCode, ClientId};
use std::collections::HashSet;
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::info;

/// Default OAuth scopes used when none are provided.
#[allow(dead_code)]
const DEFAULT_SCOPE_ARR: [&str; 3] = ["openid", "offline_access", "profile"];
/// Default client ID for interactive browser authentication.
#[allow(dead_code)]
const DEFAULT_DEVELOPER_SIGNON_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
/// Default tenant ID used when none is specified.
#[allow(dead_code)]
const DEFAULT_ORGANIZATIONS_TENANT_ID: &str = "organizations";

/// Configuration options for `InteractiveBrowserCredential`.
///
/// This struct allows customization of the interactive browser authentication flow,
/// including the client ID, tenant ID, and redirect URL used during the authentication process.
#[derive(Clone, Debug)]
pub struct InteractiveBrowserCredentialOptions {
    /// Client ID of the application.
    pub client_id: Option<String>,
    /// Tenant ID for the authentication request.
    pub tenant_id: Option<String>,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Option<Url>,
}

/// Provides interactive browser-based authentication.
#[derive(Debug)]
pub struct InteractiveBrowserCredential {
    options: InteractiveBrowserCredentialOptions,
    cache: TokenCache,
}

impl InteractiveBrowserCredential {
    /// Creates a new `InteractiveBrowserCredential` instance with `InteractiveBrowserCredentialOptions` parameters.
    pub fn new(options: InteractiveBrowserCredentialOptions) -> azure_core::Result<Self> {
        let client_id = Some(
            options
                .client_id
                .unwrap_or_else(|| DEFAULT_DEVELOPER_SIGNON_CLIENT_ID.to_owned()),
        );

        let tenant_id = Some(
            options
                .tenant_id
                .unwrap_or_else(|| DEFAULT_ORGANIZATIONS_TENANT_ID.to_owned()),
        );

        let redirect_url = Some(options.redirect_url.unwrap_or_else(|| {
            Url::from_str(&format!("http://localhost:{}", LOCAL_SERVER_PORT))
                .expect("Failed to parse redirect URL")
        }));

        Ok(Self {
            options: InteractiveBrowserCredentialOptions {
                client_id,
                tenant_id,
                redirect_url,
            },
            cache: TokenCache::new(),
        })
    }

    /// Starts the interactive browser authentication flow and returns an access token.
    ///
    /// If no scopes are provided, default scopes will be used.
    #[allow(dead_code)]
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        let verified_scopes = ensure_default_scopes(scopes);

        let options = self.options.clone();

        let hybrid_flow_code = hybrid_flow::authorize(
            ClientId::new(options.client_id.unwrap().clone()),
            None,
            &options.tenant_id.unwrap().clone(),
            options.redirect_url.unwrap().clone(),
            &verified_scopes,
        );

        let auth_code: Option<TokenPair> =
            open_url(hybrid_flow_code.authorize_url.clone().as_ref()).await;

        match auth_code {
            Some(token_pair) => {
                let acc = hybrid_flow_code
                    .exchange(
                        new_http_client(),
                        AuthorizationCode::new(token_pair.auth_code).clone(),
                    )
                    .await
                    .map(|r| {
                        return AccessToken::new(
                            r.access_token().secret().clone(),
                            OffsetDateTime::now_utc() + r.expires_in().unwrap().clone(),
                        )
                        .clone();
                    });

                let _ = decode_id_token(token_pair.id_token.clone());
                return acc;
            }
            None => {
                return Err(Error::message(
                    ErrorKind::Other,
                    "Failed to retrieve authorization code.".to_string(),
                ))
            }
        };
    }
}
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for InteractiveBrowserCredential {
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        self.cache.get_token(scopes, self.get_token(scopes)).await
    }
}

///check if there at least the default scopes included
fn ensure_default_scopes<'a>(scopes: &'a [&'a str]) -> Vec<&'a str> {
    let mut scope_set: HashSet<&'a str> = scopes.iter().copied().collect();
    let mut result = scopes.to_vec();

    for default_scope in DEFAULT_SCOPE_ARR.iter() {
        if scope_set.insert(default_scope) {
            result.push(default_scope);
        }
    }

    result
}

fn decode_id_token(id_token_encoded: String) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = id_token_encoded.split('.').collect();

    //decode base64
    let a = general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;

    let id_token_decoded: serde_json::Value = serde_json::from_slice(&a)?;

    info!("id_token decoded: {:#?}", id_token_decoded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::debug;
    use tracing::Level;
    use tracing_subscriber;
    static INIT: std::sync::Once = std::sync::Once::new();

    fn init_tracing() {
        INIT.call_once(|| {
            tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .init();
        });
    }

    #[tokio::test]
    async fn interactive_auth_flow_should_return_token() {
        init_tracing();
        debug!("Starting interactive authentication test");

        let credential = InteractiveBrowserCredential::new(InteractiveBrowserCredentialOptions {
            client_id: None,
            tenant_id: None,
            redirect_url: None,
        })
        .expect("Failed to create credential");
        let scopes = &["https://management.azure.com/.default"];
        let token_response = credential.get_token(scopes).await;
        debug!("Authentication result: {:#?}", token_response);
        assert!(token_response.is_ok());
    }
}
