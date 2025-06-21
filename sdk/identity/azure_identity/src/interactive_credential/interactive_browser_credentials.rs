use std::{str::FromStr, sync::Arc, u16};

use azure_core::{
    http::{new_http_client, HttpClient, Url},
    process::Executor,
};

/// Default client ID for interactive browser authentication.
#[allow(dead_code)]
const DEFAULT_DEVELOPER_SIGNON_CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
/// Default tenant ID used when none is specified.
#[allow(dead_code)]
const DEFAULT_ORGANIZATIONS_TENANT_ID: &str = "organizations";

const LOCAL_SERVER_PORT: u16 = 53298;

/// Configuration options for `InteractiveBrowserCredential`.
///
/// This struct allows customization of the interactive browser authentication flow,
/// including the client ID, tenant ID, and redirect URL used during the authentication process.
#[derive(Clone, Debug)]
pub struct InteractiveBrowserCredentialOptions {
    /// Client ID of the application.
    pub client_id: String,
    /// Tenant ID for the authentication request.
    pub tenant_id: String,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Url,

    pub(crate) executor: Arc<dyn Executor>,
    local_http_client: Arc<dyn HttpClient>,
}

impl InteractiveBrowserCredentialOptions {
    pub fn http_client(&self) -> Arc<dyn HttpClient> {
        self.local_http_client.clone()
    }
}

#[derive(Debug)]
pub struct InteractiveBrowserCredential {
    pub options: InteractiveBrowserCredentialOptions,
}

impl InteractiveBrowserCredential {
    /// Creates a new `InteractiveBrowserCredential` instance with `InteractiveBrowserCredentialOptions` parameters.
    pub fn new(
        client_id: Option<String>,
        tenant_id: Option<String>,
        redirect_url: Option<Url>,
    ) -> azure_core::Result<Self> {
        let client_id = client_id.unwrap_or_else(|| DEFAULT_DEVELOPER_SIGNON_CLIENT_ID.to_owned());

        let tenant_id = tenant_id.unwrap_or_else(|| DEFAULT_ORGANIZATIONS_TENANT_ID.to_owned());

        let redirect_url = redirect_url.unwrap_or_else(|| {
            Url::from_str(&format!("http://localhost:{}", LOCAL_SERVER_PORT))
                .expect("Failed to parse redirect URL")
        });

        Ok(Self {
            options: InteractiveBrowserCredentialOptions {
                client_id,
                tenant_id,
                redirect_url,
                //TODO  implement Default trait
                local_http_client: new_http_client(),
                executor: azure_core::process::new_executor(),
            },
        })
    }

    async fn get_auth_token(scopes: &[&str]) {}
}

#[cfg(test)]
mod tests {
    use crate::interactive_credential::azure_code_credential::authorize;

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
    async fn interactive_auth_flow() {
        init_tracing();

        debug!("Starting interactive_auth_flow test");

        let credential_options =
            InteractiveBrowserCredential::new(None, None, None).expect("Error on setting ");

        let res_body = authorize(credential_options, None).await;

        debug!("body resutl: {:#?}", res_body);
    }
}
