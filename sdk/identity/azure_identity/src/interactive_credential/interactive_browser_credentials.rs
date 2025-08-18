use std::{str::FromStr, sync::Arc, u16};

use azure_core::{
    http::{new_http_client, HttpClient, Url},
    process::Executor,
};

use azure_core::{
    date::iso8601::option,
    error::ErrorKind,
    http::{Method, Request},
};
use tracing::debug;
use url::form_urlencoded;

use crate::interactive_credential::internal_server::open_url;

use super::internal_server::HybridAuthContext;

/// Default OAuth scopes used when none are provided.
#[allow(dead_code)]
const DEFAULT_SCOPE_ARR: [&str; 3] = ["openid", "offline_access", "profile"];
const AUTORIZE_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize";

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

    async fn get_auth_token(&self, scopes: Option<&[&str]>) {
        let url = self.authorize(scopes);
        match url {
            Ok(url) => {
                debug!("url to open: {}", url.to_string());
                let option_hybrid_auth_context = open_url(&url.to_string()).await.expect("Could not get auth context");
                option_hybrid_auth_context.
                },
            err => {
                debug!("Error on authorize");
            }
        }
    }

impl InteractiveBrowserCredential {
    fn authorize(&self, scopes: Option<&[&str]>) -> Result<Url, url::ParseError> {
        let InteractiveBrowserCredentialOptions {
            client_id,
            tenant_id,
            redirect_url,
            executor,
            ..
        } = self.options.clone();
        let auth_url: Url = Url::parse(&format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?",
        ))
        .expect("Invalid authorization endpoint URL");

        let scopes = scopes.unwrap_or(&DEFAULT_SCOPE_ARR);

        let mut body_authorize = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("client_info", "1")
            .append_pair("response_mode", "form_post")
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect_url.to_string())
            .finish();
        debug!("Method authorize() after variable init");

        Url::from_str(&format!("{}{}", &auth_url, &body_authorize.to_string()))
    }

    async fn execute_auth_token_req(auth_context: HybridAuthContext){
       let req = Request::new(Url::parse(&format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        )), Method::Post);


    }

    //add https://github.com/Azure/azure-sdk-for-rust/blob/7f04e44c27aa83627013b6feee71823040492898/sdk/identity/azure_identity/src/client_certificate_credential.rs#L12
}
#[cfg(test)]
mod tests {
    use crate::interactive_credential::azure_code_credential::authorize;
    use crate::interactive_credential::internal_server::open_url;

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
    }
}
