use azure_core::http::{Method, Request};
use url::{form_urlencoded, Url};

use super::interactive_browser_credentials::InteractiveBrowserCredentialOptions;

const AUTORIZE_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize";

pub fn authorize(options: InteractiveBrowserCredentialOptions, scopes: &[&str]) {
    let tenant_id = options.tenant_id.expect("tenant_id has to be set");
    let auth_url: Url = Url::parse(&format!(
        "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    ))
    .expect("Invalid authorization endpoint URL");
    let mut req_authorize = Request::new(auth_url, Method::Get);

    let mut body_authorize = form_urlencoded::Serializer::new(String::new())
        .append_pair("scopes", &scopes.join(" "))
        .append_pair("client_info", "1")
        .append_pair("response_mode", "form_post")
        .append_pair("response_type", "code")
        .append_pair("nonce", "ahdfakjblaj"); //TODO: implement correct nonce later

    req_authorize.set_body(body_authorize);
}
