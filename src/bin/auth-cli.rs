use chrono::Utc;
use reqwest::Url;
use std::io;
use xal::authenticator::XalAuthenticator;
use xal::oauth2::PkceCodeVerifier;
use xal::utils::TokenStore;

const TOKENS_FILEPATH: &str = "tokens.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut xal = XalAuthenticator::default();

    if let Ok(mut ts) = TokenStore::load(TOKENS_FILEPATH) {
        let refreshed_xcoud = xal
            .exchange_refresh_token_for_xcloud_transfer_token(&ts.xcloud_transfer_token.into())
            .await?;
        println!("{:?}", refreshed_xcoud);

        ts.xcloud_transfer_token = refreshed_xcoud;
        ts.updated = Utc::now();
        ts.save(TOKENS_FILEPATH)?;

        return Ok(());
    }

    let (code_challenge, code_verifier) = XalAuthenticator::get_code_challenge();

    println!("Getting device token...");
    let device_token = xal.get_device_token().await?;
    println!("Device token={:?}", device_token);

    let state = XalAuthenticator::generate_random_state();

    println!("Fetching SISU authentication URL...");
    let (sisu_response, sisu_session_id) = xal
        .do_sisu_authentication(&device_token.token_data.token, code_challenge, &state)
        .await?;

    println!(
        r#"!!! ACTION REQUIRED !!!
Navigate to this URL and authenticate: {}
When finished, paste the Redirect URL and hit [ENTER]"#,
        sisu_response.msa_oauth_redirect
    );

    let mut redirect_uri = String::new();
    let _ = io::stdin().read_line(&mut redirect_uri)?;

    // Check if redirect URI has expected scheme
    println!("Checking redirect URI...");
    let expected_scheme = xal.get_redirect_uri().scheme().to_owned();
    if !redirect_uri.starts_with(&expected_scheme) {
        return Err(format!(
            "Invalid redirect URL, expecting scheme: {}",
            expected_scheme
        )
        .into());
    }

    // Parse redirect URI
    let parsed_url = Url::parse(&redirect_uri)?;
    // Extract query parameters {code, state}
    let mut code_query: Option<String> = None;
    let mut state_query: Option<String> = None;

    for i in parsed_url.query_pairs() {
        if i.0 == "code" {
            code_query = Some(i.1.into_owned())
        } else if i.0 == "state" {
            state_query = Some(i.1.into_owned())
        }
    }

    println!("Verifying state...");
    if let Some(returned_state) = &state_query {
        let valid_state = &state == returned_state;
        println!(
            "State valid: {} ({} vs. {})",
            valid_state, state, returned_state
        );
    } else {
        println!("WARN: No state query returned!");
    }

    if let Some(authorization_code) = code_query {
        println!("Authorization Code: {}", &authorization_code);
        let local_code_verifier = PkceCodeVerifier::new(code_verifier.secret().clone());

        println!("Getting WL tokens...");
        let wl_token = xal
            .exchange_code_for_token(&authorization_code, local_code_verifier)
            .await
            .expect("Failed exchanging code for token");
        let wl_token_clone = wl_token.clone();
        println!("WL={:?}", wl_token);

        println!("Attempting SISU authorization...");
        let auth_response = xal
            .do_sisu_authorization(
                &sisu_session_id,
                wl_token.access_token.secret(),
                &device_token.token_data.token,
            )
            .await?;
        println!("SISU={:?}", auth_response);

        println!("Getting GSSV token...");
        // Fetch GSSV (gamestreaming) token
        let gssv_token = xal
            .do_xsts_authorization(
                &auth_response.device_token,
                &auth_response.title_token.token_data.token,
                &auth_response.user_token.token_data.token,
                "http://gssv.xboxlive.com/",
            )
            .await?;
        println!("GSSV={:?}", gssv_token);

        println!("Getting XCloud transfer token...");
        // Fetch XCloud transfer token
        let transfer_token = xal
            .exchange_refresh_token_for_xcloud_transfer_token(
                &wl_token
                    .refresh_token
                    .expect("Failed to unwrap refresh token"),
            )
            .await?;
        println!("Transfer token={:?}", transfer_token);

        let ts = TokenStore {
            app_params: xal.app_params(),
            client_params: xal.client_params(),
            wl_token: wl_token_clone,
            sisu_tokens: auth_response,
            gssv_token,
            xcloud_transfer_token: transfer_token,
            updated: Utc::now(),
        };
        ts.save(TOKENS_FILEPATH)?
    } else {
        println!("No authorization code fetched :(");
    }

    Ok(())
}
