use azure_core::{
    date::iso8601::option,
    error::ErrorKind,
    http::{Method, Request},
};
use url::{form_urlencoded, Url};

use super::interactive_browser_credentials::InteractiveBrowserCredentialOptions;

const AUTORIZE_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize";

pub async fn authorize(
    options: InteractiveBrowserCredentialOptions,
    scopes: &[&str],
) -> azure_core::Result<String> {
    let tenant_id = options.tenant_id.expect("tenant_id has to be set");
    let auth_url: Url = Url::parse(&format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    ))
    .expect("Invalid authorization endpoint URL");
    let mut req_authorize = Request::new(auth_url, Method::Get);

    let redirect_uri = options
        .redirect_url
        .expect("There has to be a redirect uri");

    let mut body_authorize = form_urlencoded::Serializer::new(String::new())
        .append_pair("scopes", &scopes.join(" "))
        .append_pair("client_info", "1")
        .append_pair("response_mode", "")
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri.to_string())
        .finish();
    //.append_pair("nonce", "ahdfakjblaj"); //TODO: implement correct nonce later

    let body = req_authorize.set_body(body_authorize);

    options
        .http_client()
        .execute_request(&req_authorize)
        .await
        .map(|res| Ok(String::new()))
        .map_err(|err| {
            azure_core::Error::full(
                ErrorKind::Credential,
                err,
                "could not get the autorization code",
            )
        })?
}
