use serde_json::json;
use xal::{
    extensions::JsonExDeserializeMiddleware, oauth2::TokenResponse, AccessTokenPrefix,
    CliCallbackHandler, Error, XalAuthenticator,
};
use xal_examples::auth_main;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let app_params = xal::app_params::MC_BEDROCK_SWITCH();
    let client_params = xal::client_params::CLIENT_NINTENDO();

    let ts = auth_main(
        app_params,
        client_params,
        "RETAIL".into(),
        AccessTokenPrefix::None,
        CliCallbackHandler,
    )
    .await?;

    let mut authenticator = XalAuthenticator::from(ts.clone());
    let xsts_mc_services = authenticator
        .get_xsts_token(
            ts.device_token.as_ref(),
            ts.title_token.as_ref(),
            ts.user_token.as_ref(),
            "rp://api.minecraftservices.com/",
        )
        .await?;

    let identity_token = xsts_mc_services.authorization_header_value();
    println!("identityToken: {identity_token}");

    /* Minecraft stuff */
    // Fetch minecraft token
    let mc_token = reqwest::Client::new()
        .post("https://api.minecraftservices.com/authentication/login_with_xbox")
        .json(&json!({"identityToken": identity_token}))
        .send()
        .await?
        .json_ex::<xal::oauth2::basic::BasicTokenResponse>()
        .await?;
    println!("MC: {mc_token:?}");

    // Get minecraft entitlements
    let entitlements = reqwest::Client::new()
        .get("https://api.minecraftservices.com/entitlements/mcstore")
        .bearer_auth(mc_token.access_token().secret())
        .send()
        .await?
        .text()
        .await?;
    println!("Entitlements: {entitlements}");

    // Get minecraft profile
    let profile = reqwest::Client::new()
        .get("https://api.minecraftservices.com/minecraft/profile")
        .bearer_auth(mc_token.access_token().secret())
        .send()
        .await?
        .text()
        .await?;
    println!("Profile: {profile}");

    Ok(())
}
