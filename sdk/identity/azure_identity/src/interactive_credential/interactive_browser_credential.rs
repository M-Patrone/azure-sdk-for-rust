use super::internal_server::*;
use crate::authorization_code_flow;
use azure_core::credentials::TokenCredential;
use azure_core::{
    credentials::AccessToken,
    error::ErrorKind,
    http::{new_http_client, HttpClient, Url},
    Error,
};
use futures::future;
use oauth2::TokenResponse;
use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ClientId, EmptyExtraTokenFields,
    StandardTokenResponse,
};
use std::borrow::Cow;
use std::future::Future;
use std::{str::FromStr, sync::Arc, time::Duration};
use time::OffsetDateTime;

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

    pub http_client: Arc<dyn HttpClient>,
}

/// Provides interactive browser-based authentication.
#[derive(Clone, Debug)]
pub struct InteractiveBrowserCredential {
    options: InteractiveBrowserCredentialOptions,
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
                http_client: options.http_client.clone(),
            },
        })
    }

    /// Starts the interactive browser authentication flow and returns an access token.
    ///
    /// If no scopes are provided, default scopes will be used.
    #[allow(dead_code)]
    async fn get_access_token(&self, scopes: Vec<Cow<'_, str>>) -> azure_core::Result<AccessToken> {
        if scopes.is_empty() {
            return Err(Error::new(
                ErrorKind::Credential,
                "exactly one scope required",
            ));
        }

        let options = self.options.clone();
        let scopes_refs: Vec<&str> = scopes.iter().map(|s| s.as_ref()).collect();

        let authorization_code_flow = authorization_code_flow::authorize(
            ClientId::new(options.client_id.unwrap().clone()),
            None,
            &options.tenant_id.unwrap().clone(),
            options.redirect_url.unwrap().clone(),
            &scopes_refs,
        );

        let auth_code = open_url(authorization_code_flow.authorize_url.clone().as_ref()).await;
        match auth_code {
            Some(code) => {
                let acc = authorization_code_flow
                    .exchange(
                        options.http_client.clone(),
                        AuthorizationCode::new(code).clone(),
                    )
                    .await
                    .map(|r| {
                        return AccessToken::new(
                            r.access_token().secret().clone(),
                            OffsetDateTime::now_utc() + r.expires_in().unwrap().clone(),
                        )
                        .clone();
                    });

                return acc;
            }
            None => {
                return Err(Error::message(
                    ErrorKind::Other,
                    "Failed to retrieve authorization code.".to_string(),
                ))
            }
        };

        //Ok(AccessToken::new("test", OffsetDateTime::now_utc()))
    }
    /*
    fn get_access_token_test(
        &self,
        scopes: &[&str],
    ) -> impl Send + Future<Output = azure_core::Result<AccessToken>> {
        assert_send(async move {
            let authorization_code_flow = authorization_code_flow::authorize(
                ClientId::new("jkadjfa".to_string()),
                None,
                &"jkadjfa".to_string(),
                Url::from_str("str").unwrap(),
                &scopes,
            );

            let b = AuthorizationCode::new("djfak".to_string()).clone();
            let c = new_http_client();

            let a = authorization_code_flow.exchange(c, b).await?.clone();

            Ok(AccessToken::new("test", OffsetDateTime::now_utc()))
        })
    }
    */
}
fn assert_send<T>(fut: impl Send + Future<Output = T>) -> impl Send + Future<Output = T> {
    fut
}
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for InteractiveBrowserCredential {
    async fn get_token(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        //self.get_access_token_test(scopes).await
        let scopes_owned: Vec<Cow<'_, str>> = scopes.iter().map(|s| Cow::Borrowed(*s)).collect();
        self.get_access_token(scopes_owned).await
    }
}

/// Convert a `AADv2` scope to an `AADv1` resource
///
/// Directly based on the `azure-sdk-for-python` implementation:
/// ref: <https://github.com/Azure/azure-sdk-for-python/blob/d6aeefef46c94b056419613f1a5cc9eaa3af0d22/sdk/identity/azure-identity/azure/identity/_internal/__init__.py#L22>
fn scopes_to_resource<'a>(scopes: &'a [&'a str]) -> azure_core::Result<&'a str> {
    if scopes.len() != 1 {
        return Err(Error::message(
            ErrorKind::Credential,
            "only one scope is supported for IMDS authentication",
        ));
    }

    let Some(scope) = scopes.first() else {
        return Err(Error::message(
            ErrorKind::Credential,
            "no scopes were provided",
        ));
    };

    Ok(scope.strip_suffix("/.default").unwrap_or(*scope))
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
