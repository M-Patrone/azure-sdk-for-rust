use azure_identity::{InteractiveBrowserCredential, InteractiveBrowserCredentialOptions};
use oauth2::TokenResponse;
use reqwest::Client;
use std::error::Error;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let test_subscription_id =
        std::env::var("AZURE_SUBSCRIPTION_ID").expect("AZURE_SUBSCRIPTION_ID required");
    let test_tenant_id = std::env::var("AZURE_TENANT_ID").expect("AZURE_TENANT_ID required");

    let _ = run_app_inter(test_subscription_id, test_tenant_id).await?;
    Ok(())
}

async fn run_app_inter(subscription_id: String, tenant_id: String) -> Result<(), Box<dyn Error>> {
    let options = InteractiveBrowserCredentialOptions {
        client_id: None,
        tenant_id: Some(tenant_id),
        redirect_url: None,
    };
    let interactive_credentials = InteractiveBrowserCredential::new(options)?;

    let token_response = interactive_credentials
        .get_token(Some(&["https://management.azure.com/.default"]))
        .await?;

    let access_token_secret = token_response.access_token().secret();

    let url = Url::parse(&format!(
                 "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01"
             ))?;

    let resp = Client::new()
        .get(url)
        .header("Authorization", format!("Bearer {}", access_token_secret))
        .send()
        .await?
        .text()
        .await?;

    println!("Res interactive: {resp}");
    Ok(())
}
