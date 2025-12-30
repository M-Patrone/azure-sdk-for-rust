use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::{
        headers::{self, content_type},
        new_http_client, HttpClient, Url,
    },
    Error,
};
use azure_core::{
    error::ErrorKind,
    http::{Method, Request},
    time::{Duration, OffsetDateTime},
};
use std::{collections::HashSet, str::FromStr, sync::Arc, u16};
use tracing::{debug, info};
use url::form_urlencoded;

use crate::{
    cache, handle_entra_response,
    interactive_credential::{
        interactive_credentials_cache::TokenCache, internal_server::open_url,
    },
    EntraIdTokenResponse,
};

/// Default OAuth scopes used when none are provided.
#[allow(dead_code)]
const DEFAULT_SCOPE_ARR: [&str; 3] = ["openid", "offline_access", "profile"];
const AUTH_URL: &str = "https://login.microsoftonline.com";

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
#[derive(Debug, Clone)]
pub struct InteractiveBrowserCredentialOptions<'a> {
    /// Client ID of the application.
    pub client_id: String,
    /// Tenant ID for the authentication request.
    pub tenant_id: String,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Url,
    pub scopes: Vec<&'a str>,

    local_http_client: Arc<dyn HttpClient>,
}

impl<'a> InteractiveBrowserCredentialOptions<'a> {
    pub fn http_client(&self) -> Arc<dyn HttpClient + 'a> {
        self.local_http_client.clone()
    }
}

#[derive(Debug)]
pub struct InteractiveBrowserCredential<'a> {
    pub options: InteractiveBrowserCredentialOptions<'a>,
    pub cache: TokenCache,
}

impl<'a> InteractiveBrowserCredential<'a> {
    /// Creates a new `InteractiveBrowserCredential` instance with `InteractiveBrowserCredentialOptions` parameters.
    pub fn new(
        client_id: Option<String>,
        tenant_id: Option<String>,
        redirect_url: Option<Url>,
        scopes: Option<&'a [&'a str]>,
    ) -> azure_core::Result<Self> {
        let client_id = client_id
            .clone()
            .unwrap_or_else(|| DEFAULT_DEVELOPER_SIGNON_CLIENT_ID.to_owned());

        let tenant_id = tenant_id
            .clone()
            .unwrap_or_else(|| DEFAULT_ORGANIZATIONS_TENANT_ID.to_owned());

        let redirect_url = redirect_url.unwrap_or_else(|| {
            Url::from_str(&format!("http://localhost:{}", LOCAL_SERVER_PORT))
                .expect("Failed to parse redirect URL")
        });

        let verified_scopes: Vec<&'a str> = match scopes {
            Some(scopes_ok) => ensure_default_scopes(scopes_ok),
            None => DEFAULT_SCOPE_ARR.to_vec(), // &[&str;3] -> Vec<&str> ('static koert zu 'a)
        };

        Ok(Self {
            options: InteractiveBrowserCredentialOptions {
                client_id: client_id.clone(),
                tenant_id: tenant_id.clone(),
                redirect_url,
                local_http_client: new_http_client(),
                scopes: verified_scopes.clone(),
            },
            cache: TokenCache::new(),
        })
    }

    pub async fn get_token_impl(&self) -> azure_core::Result<AccessToken> {
        info!("starting method");

        let url = self.authorize(self.options.scopes.as_slice());
        match url {
            Ok(url) => {
                debug!("url to open: {}", url.to_string());
                let option_hybrid_auth_context = open_url(url.as_ref())
                    .await
                    .expect("Could not get auth context");

                req_access_token(
                    self.options.scopes.as_slice(),
                    self.options.clone(),
                    &option_hybrid_auth_context.auth_code,
                )
                .await
            }
            Err(e) => {
                debug!("Error on authorize");
                Err(Error::new(ErrorKind::Other, e))
            }
        }
    }
}
impl<'a> InteractiveBrowserCredential<'a> {
    fn authorize(&self, scopes: &[&str]) -> Result<Url, url::ParseError> {
        let InteractiveBrowserCredentialOptions {
            client_id,
            tenant_id,
            redirect_url,
            ..
        } = self.options.clone();
        let auth_url: Url = Url::parse(&format!(
            "{}/{}/oauth2/v2.0/authorize?",
            AUTH_URL, tenant_id
        ))
        .expect("Invalid authorization endpoint URL");

        let body_authorize = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("client_info", "1")
            .append_pair("response_mode", "form_post")
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", redirect_url.as_ref())
            .finish();
        debug!("Method authorize() after variable init");

        Url::from_str(&format!("{}{}", &auth_url, &body_authorize.to_string()))
    }
}

async fn req_access_token(
    scopes: &[&str],
    options: InteractiveBrowserCredentialOptions<'_>,
    auth_code: &str,
) -> azure_core::Result<AccessToken> {
    let mut req = Request::new(
        Url::parse(&format!(
            "{}/{}/oauth2/v2.0/token",
            AUTH_URL, &options.tenant_id
        ))
        .unwrap(),
        Method::Post,
    );

    req.insert_header(
        headers::CONTENT_TYPE,
        content_type::APPLICATION_X_WWW_FORM_URLENCODED,
    );

    let encoded = {
        let mut encoded = &mut form_urlencoded::Serializer::new(String::new());

        encoded = encoded
            .append_pair("client_id", &options.client_id)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("code", auth_code)
            .append_pair(
                "redirect_uri",
                &format!("http://localhost:{}", LOCAL_SERVER_PORT),
            )
            .append_pair("grant_type", "authorization_code")
            //get the id token
            .append_pair("client_info", "1");

        encoded.finish()
    };

    info!("token request: {:#?}", &encoded);
    req.set_body(encoded);
    let rsp = options.local_http_client.execute_request(&req).await?;
    let rsp_status = rsp.status();

    if !rsp_status.is_success() {
        let rsp_body: azure_core::Bytes = rsp.into_body().collect().await?;
        return Err(Error::with_message(
            ErrorKind::Credential,
            format!("{}, {}", rsp_status, String::from_utf8(rsp_body.to_vec())?),
        ));
    }
    let response = handle_entra_response(rsp.try_into_raw_response().await?);
    response
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
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<'a> TokenCredential for InteractiveBrowserCredential<'a> {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions>,
    ) -> crate::Result<AccessToken> {
        println!("GETTING TOOOOOOOOKEN");

        let oid = &self.options.client_id;
        let tid = &self.options.tenant_id;
        let token = self
            .cache
            .get_token(scopes, oid.clone(), tid.clone(), self.get_token_impl())
            .await;
        return token;
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
    async fn interactive_auth_flow() {
        init_tracing();

        debug!("Starting interactive_auth_flow test");

        let credential_options =
            InteractiveBrowserCredential::new(None, None, None, None).expect("Error on setting ");

        let response = credential_options.get_token(&DEFAULT_SCOPE_ARR, None).await;

        info!("after request {:#?}", response);
    }
}
