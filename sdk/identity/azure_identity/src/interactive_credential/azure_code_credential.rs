use azure_core::http::{Request, Method};
use url::Url;

use super::interactive_browser_credentials::InteractiveBrowserCredentialOptions;

const AUTORIZE_URL: &str = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize";

pub fn authorize(options: InteractiveBrowserCredentialOptions) {
    let tenant_id = options.tenant_id.expect("tenant_id has to be set");
let auth_url: Url =
        Url::parse(&format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"))
        .expect("Invalid authorization endpoint URL");
    let mut req_authorize = Request::new(auth_url, Method::Get )
}
