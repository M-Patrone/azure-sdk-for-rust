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
};
use std::{collections::HashSet, str::FromStr, sync::Arc};
use tracing::debug;
use url::form_urlencoded;

use crate::{
    handle_entra_response,
    interactive_credential::{
        interactive_credentials_cache::TokenCache, internal_server::open_url,
    },
};

use super::LOCAL_SERVER_PORT;

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

///helper struct to save the options for the interactive browser credential flow
#[derive(Debug)]
pub struct InteractiveBrowserCredential {
    /// Client ID of the application.
    pub client_id: String,
    /// Tenant ID for the authentication request.
    pub tenant_id: String,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Url,

    /// saves the custom implementation for the cache for the interactive flow
    cache: TokenCache,
    local_http_client: Arc<dyn HttpClient>,
}

impl InteractiveBrowserCredential {
    /// Creates a new `InteractiveBrowserCredential` instance with `InteractiveBrowserCredentialOptions` parameters.
    pub fn new(
        client_id: Option<String>,
        tenant_id: Option<String>,
        redirect_url: Option<Url>,
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

        Ok(Self {
            client_id: client_id.clone(),
            tenant_id: tenant_id.clone(),
            redirect_url,
            local_http_client: new_http_client(),
            cache: TokenCache::new(),
        })
    }

    /// method which handles the logic implementation of the interactive flow
    /// starts firstly the internal server to get the auth code and then continues to get the
    /// access token.
    pub async fn get_token_impl(&self, scopes: &[&str]) -> azure_core::Result<AccessToken> {
        debug!("starting method");

        let url = self.authorize(scopes);
        match url {
            Ok(url) => {
                debug!("url to open: {}", url.to_string());
                let option_hybrid_auth_context = open_url(url.as_ref())
                    .await
                    .expect("Could not get auth context");

                self.req_access_token(scopes, &option_hybrid_auth_context.auth_code)
                    .await
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    async fn req_access_token(
        &self,
        scopes: &[&str],
        auth_code: &str,
    ) -> azure_core::Result<AccessToken> {
        let mut req = Request::new(
            Url::parse(&format!(
                "{}/{}/oauth2/v2.0/token",
                AUTH_URL, self.tenant_id
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
                .append_pair("client_id", &self.client_id)
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

        debug!("token request: {:#?}", &encoded);
        req.set_body(encoded);
        let rsp = self.local_http_client.execute_request(&req).await?;
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
    fn authorize(&self, scopes: &[&str]) -> Result<Url, url::ParseError> {
        let auth_url: Url = Url::parse(&format!(
            "{}/{}/oauth2/v2.0/authorize?",
            AUTH_URL, self.tenant_id
        ))
        .expect("Invalid authorization endpoint URL");

        let body_authorize = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.client_id)
            .append_pair("scope", &scopes.join(" "))
            .append_pair("client_info", "1")
            .append_pair("response_mode", "form_post")
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", self.redirect_url.as_ref())
            .finish();
        debug!("Method authorize() after variable init");

        Url::from_str(&format!("{}{}", &auth_url, &body_authorize.to_string()))
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
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl TokenCredential for InteractiveBrowserCredential {
    /// method which is exposed to get the access token
    async fn get_token(
        &self,
        scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> crate::Result<AccessToken> {
        println!("GETTING TOOOOOOOOKEN");

        let verified_scopes = ensure_default_scopes(scopes);

        //TODO: this is false should be set by the hybrid_auth_context
        //need reworks. does not work idTokencache is unimplemented!()
        //problem is that we get the oid and the tid only in access code so we have to reset the
        //token cache --> we need to check if the cache has no idTokencache or an invalid without
        //any oid and tid
        let oid = &self.client_id;
        let tid = &self.tenant_id;
        let token = self
            .cache
            .get_token(
                &verified_scopes,
                oid.clone(),
                tid.clone(),
                self.get_token_impl(&verified_scopes),
            )
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
            InteractiveBrowserCredential::new(None, None, None).expect("Error on setting ");

        let response = credential_options.get_token(&DEFAULT_SCOPE_ARR, None).await;

        debug!("after request {:#?}", response);
    }
}
