use std::str::FromStr;

use azure_core::{
    date::iso8601::option,
    error::ErrorKind,
    http::{Method, Request},
};
use tracing::debug;
use url::{form_urlencoded, Url};

use super::interactive_browser_credentials::{
    InteractiveBrowserCredential, InteractiveBrowserCredentialOptions,
};

/// Default OAuth scopes used when none are provided.
#[allow(dead_code)]
const DEFAULT_SCOPE_ARR: [&str; 3] = ["openid", "offline_access", "profile"];
const AUTORIZE_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize";

pub async fn authorize(
    options: InteractiveBrowserCredential,
    scopes: Option<&[&str]>,
) -> Result<Url, url::ParseError> {
    let InteractiveBrowserCredentialOptions {
        client_id,
        tenant_id,
        redirect_url,
        executor,
        ..
    } = options.options.clone();
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

    /*let mut req_authorize = Request::new(
        Url::from_str(&format!("{}{}", &auth_url, &body_authorize.to_string()))?,
        Method::Get,
    );

    //.append_pair("nonce", "ahdfakjblaj"); //TODO: implement correct nonce later

    debug!("body of the autorize: {:#?}", body_authorize);
    let res = options
        .options
        .http_client()
        .execute_request(&req_authorize)
        .await
        .map_err(|err| {
            azure_core::Error::full(
                ErrorKind::Credential,
                err,
                "could not get the authorization code",
            )
        })?;

    debug!("after request / before reading response body : ");

    let body = res.into_body().collect_string().await.map_err(|err| {
        azure_core::Error::full(
            ErrorKind::Credential,
            err,
            "could not get the authorization code",
        )
    })?;*/
    Url::from_str(&format!("{}{}", &auth_url, &body_authorize.to_string()))
}
