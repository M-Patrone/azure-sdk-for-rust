use azure_core::{
    credentials::AccessToken,
    error::http_response_from_body,
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

use crate::{cache, interactive_credential::internal_server::open_url, EntraIdTokenResponse};

use super::interactive_credentials_cache::IdTokenCache;

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
#[derive(Debug)]
pub struct InteractiveBrowserCredentialOptions {
    /// Client ID of the application.
    pub client_id: String,
    /// Tenant ID for the authentication request.
    pub tenant_id: String,
    /// Redirect URI where the authentication response is sent.
    pub redirect_url: Url,

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
    cache: IdTokenCache,
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
                local_http_client: new_http_client(),
            },
            cache: TokenCache::new(),
        })
    }

    pub async fn get_access_token(
        &self,
        scopes: Option<&[&str]>,
    ) -> azure_core::Result<AccessToken> {
        info!("starting method");

        let verified_scopes: &[&str] = match (scopes) {
            Some(scopes_ok) => &(ensure_default_scopes(scopes_ok)),
            None => &DEFAULT_SCOPE_ARR,
        };

        let url = self.authorize(verified_scopes);
        match url {
            Ok(url) => {
                debug!("url to open: {}", url.to_string());
                let option_hybrid_auth_context = open_url(url.as_ref())
                    .await
                    .expect("Could not get auth context");

                req_access_token(
                    scopes.unwrap_or(&DEFAULT_SCOPE_ARR),
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
impl InteractiveBrowserCredential {
    fn authorize(&self, scopes: &[&str]) -> Result<Url, url::ParseError> {
        let InteractiveBrowserCredentialOptions {
            client_id,
            tenant_id,
            redirect_url,
            ..
        } = self.options.clone();
        let auth_url: Url =
            Url::parse(&format!("{}/{}/oauth2/v2.0/authorize", AUTH_URL, tenant_id))
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
    options: InteractiveBrowserCredentialOptions,
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
        let rsp_body = rsp.into_body().collect().await?;
        return Err(http_response_from_body(rsp_status, &rsp_body).into_error());
    }

    let response: EntraIdTokenResponse = rsp.into_body().json().await?;
    Ok(AccessToken::new(
        response.access_token,
        OffsetDateTime::now_utc() + Duration::seconds(response.expires_in),
    ))
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

        let response = credential_options.get_access_token(None).await;

        info!("after request {:#?}", response);
    }
}
