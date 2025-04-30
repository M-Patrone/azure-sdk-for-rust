// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//! Authorize using the authorization code flow
//!
//! You can learn more about the `OAuth2` authorization code flow [here](https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow).

#![allow(dead_code)]

use crate::oauth2_http_client::Oauth2HttpClient;
use azure_core::{
    error::{ErrorKind, ResultExt},
    http::{HttpClient, Url},
};
use oauth2::{basic::BasicClient, EndpointNotSet, EndpointSet, HttpRequest, Scope};
use oauth2::{ClientId, ClientSecret};
use std::{str::FromStr, sync::Arc};
use tracing::info;

use super::internal_server::HybridAuthContext;

/// Start an hybrid flow.
///
/// The values for `client_id`, `client_secret`, `tenant_id`, and `redirect_url` can all be found
/// inside of the Azure portal.
#[allow(dead_code)]
pub fn authorize(
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    tenant_id: &str,
    redirect_url: Url,
    scopes: &[&str],
) -> HybridAuthCodeFlow {
    let auth_url = oauth2::AuthUrl::from_url(
        Url::parse(&format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        ))
        .expect("Invalid authorization endpoint URL"),
    );
    let token_url = oauth2::TokenUrl::from_url(
        Url::parse(&format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ))
        .expect("Invalid token endpoint URL"),
    );

    // Set up the config for the Microsoft Graph OAuth2 process.
    let mut client = BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        // Microsoft Graph requires client_id and client_secret in URL rather than
        // using Basic authentication.
        .set_auth_type(oauth2::AuthType::RequestBody)
        .set_redirect_uri(oauth2::RedirectUrl::from_url(redirect_url));

    if let Some(client_secret) = client_secret {
        client = client.set_client_secret(client_secret);
    }

    // Microsoft Graph supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, pkce_code_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

    let scopes = scopes.iter().map(ToString::to_string).map(Scope::new);

    let nonce: String = oauth2::CsrfToken::new_random().secret().to_string();

    // Generate the authorization URL to which we'll redirect the user.
    //https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
    let (authorize_url, csrf_state) = client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scopes(scopes)
        .set_pkce_challenge(pkce_code_challenge)
        .set_response_type(&oauth2::ResponseType::new("code id_token".to_string()))
        .add_extra_param("response_mode", "form_post")
        .add_extra_param("nonce", &nonce)
        .url();
    //TODO: implement verify nonce!!
    let url_string: String = format!("{}", authorize_url.as_str().to_string());

    let authorize_url = Url::from_str(&url_string).unwrap();

    HybridAuthCodeFlow {
        client,
        authorize_url,
        csrf_state,
        pkce_code_verifier,
        nonce,
    }
}

/// An object representing an hybrid code flow.
#[derive(Debug)]
pub struct HybridAuthCodeFlow {
    /// An HTTP client configured for OAuth2 authentication
    pub client:
        BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
    /// The authentication HTTP endpoint
    pub authorize_url: Url,
    /// The CSRF token
    pub csrf_state: oauth2::CsrfToken,
    /// The PKCE code verifier
    pub pkce_code_verifier: oauth2::PkceCodeVerifier,
    // The nonce
    // Openconnect: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    nonce: String,
}

#[allow(dead_code)]
impl HybridAuthCodeFlow {
    /// Exchange an authorization code for a token.
    pub async fn exchange(
        self,
        http_client: Arc<dyn HttpClient>,
        code: oauth2::AuthorizationCode,
    ) -> azure_core::Result<
        oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    > {
        //        let oauth_http_client = Oauth2HttpClient::new(http_client.clone());
        //        let client = |request: HttpRequest| oauth_http_client.request(request);

        //improve problem with implementing the `send`
        let oauth_http_client = Arc::new(Oauth2HttpClient::new(http_client.clone()));
        let client = {
            let oauth_http_client = oauth_http_client.clone();
            move |request: HttpRequest| {
                let oauth_http_client = oauth_http_client.clone();
                async move { oauth_http_client.request(request).await }
            }
        };

        self.client
            .exchange_code(code)
            // Send the PKCE code verifier in the token request
            .set_pkce_verifier(self.pkce_code_verifier)
            .request_async(&client)
            .await
            .context(
                ErrorKind::Credential,
                "exchanging an authorization code for a token failed",
            )
    }

    // validate the received nonce from the `id_token` with the send one
    pub fn validate_received_nonce(
        &self,
        auth_context: Option<HybridAuthContext>,
    ) -> Option<HybridAuthContext> {
        if let Some(ctx) = auth_context {
            if self.nonce.eq(&ctx.nonce) {
                info!(
                    "checking nonce: HybridAuthCodeFlow '{}' and from context: '{}'",
                    &self.nonce, &ctx.nonce
                );
                return Some(ctx);
            }
        }
        None
    }
}
