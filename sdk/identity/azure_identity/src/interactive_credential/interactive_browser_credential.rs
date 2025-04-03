use super::internal_server::*;
use crate::authorization_code_flow;
use azure_core::{
    error::ErrorKind,
    http::{new_http_client, Url},
    Error,
};
use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ClientId, EmptyExtraTokenFields,
    StandardTokenResponse,
};
use std::{str::FromStr, sync::Arc};
use tracing::debug;

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
#[derive(Clone)]
pub struct InteractiveBrowserCredentialOptions {
    /// Client ID of the application.
    pub client_id: Option<ClientId>,
    /// Tenant ID for the authentication request.
    pub tenant_id: Option<String>,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Option<Url>,
}

/// Provides interactive browser-based authentication.
#[derive(Clone)]
pub struct InteractiveBrowserCredential {
    options: InteractiveBrowserCredentialOptions,
}

impl InteractiveBrowserCredential {
    /// Creates a new `InteractiveBrowserCredential` instance with `InteractiveBrowserCredentialOptions` parameters.
    pub fn new(options: InteractiveBrowserCredentialOptions) -> azure_core::Result<Arc<Self>> {
        let client_id = Some(
            options
                .client_id
                .unwrap_or_else(|| ClientId::new(DEFAULT_DEVELOPER_SIGNON_CLIENT_ID.to_owned())),
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

        Ok(Arc::new(Self {
            options: InteractiveBrowserCredentialOptions {
                client_id,
                tenant_id,
                redirect_url,
            },
        }))
    }

    /// Starts the interactive browser authentication flow and returns an access token.
    ///
    /// If no scopes are provided, default scopes will be used.
    #[allow(dead_code)]
    pub async fn get_token(
        &self,
        scopes: Option<&[&str]>,
    ) -> azure_core::Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
        let scopes = scopes.unwrap_or(&DEFAULT_SCOPE_ARR);
        let options = self.options.clone();

        let authorization_code_flow = authorization_code_flow::authorize(
            options.client_id.unwrap().clone(),
            None,
            &options.tenant_id.unwrap(),
            options.redirect_url.unwrap().clone(),
            scopes,
        );

        let auth_code = open_url(authorization_code_flow.authorize_url.as_ref()).await;

        match auth_code {
            Some(code) => {
                authorization_code_flow
                    .exchange(new_http_client(), AuthorizationCode::new(code))
                    .await
            }
            None => Err(Error::message(
                ErrorKind::Other,
                "Failed to retrieve authorization code.",
            )),
        }
    }
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

        let token_response = credential.get_token(None).await;
        debug!("Authentication result: {:#?}", token_response);
        assert!(token_response.is_ok());
    }
}
