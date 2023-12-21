//! Sending a signed http request to XBL userpresence API
//!
use env_logger::Env;
use xal::{
    cvlib::CorrelationVector,
    extensions::{
        CorrelationVectorReqwestBuilder, LoggingReqwestRequestHandler,
        LoggingReqwestResponseHandler, SigningReqwestBuilder,
    },
    Error, RequestSigner, TokenStore,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    // Load tokens from JSON
    let token_store = TokenStore::load_from_file("tokens.json")?;

    // Create new instances of Correlation vector and request signer
    let mut cv = CorrelationVector::new();
    let mut signer = RequestSigner::new();

    // Check if XSTS token exists
    let xsts_token = token_store
        .authorization_token
        .ok_or(Error::GeneralError("No XSTS token was acquired".into()))?;
    xsts_token.check_validity()?;

    // Send a http request
    // Request will get signed and MS-CV header populated
    let userpresence = reqwest::Client::new()
        .get("https://userpresence.xboxlive.com/users/me?level=all")
        .header("x-xbl-contract-version", "3")
        .header("Authorization", xsts_token.authorization_header_value())
        .add_cv(&mut cv)?
        .sign(&mut signer, None)
        .await?
        .log()
        .await?
        .send()
        .await?
        .log()
        .await?
        .text()
        .await?;

    println!("{userpresence}");
    Ok(())
}
