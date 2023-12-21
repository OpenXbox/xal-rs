use chrono::{DateTime, Utc};
use env_logger::Env;
use serde::Deserialize;
use serde_json::json;
use xal::{extensions::JsonExDeserializeMiddleware, Error, TokenStore, XalAuthenticator};

#[derive(Debug, Deserialize)]
pub struct SpartanTokenExpiry {
    #[serde(rename = "ISO8601Date")]
    pub iso8601_date: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SpartanTokenResponse {
    pub expires_utc: SpartanTokenExpiry,
    pub spartan_token: String,
    pub token_duration: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FlightConfiguration {
    pub flight_configuration_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();

    // Load tokens from JSON
    let token_store = TokenStore::load_from_file("tokens.json")?;

    token_store
        .user_token
        .clone()
        .ok_or(Error::GeneralError("No User token available".into()))?;
    let xuid = token_store
        .authorization_token
        .clone()
        .ok_or(Error::GeneralError("No XSTS token available".into()))?
        .display_claims
        .ok_or(Error::GeneralError("No DisplayClaims".into()))?
        .xui
        .first()
        .ok_or(Error::GeneralError("No xui node".into()))?
        .get("xid")
        .ok_or(Error::GeneralError("No X(U)ID".into()))?
        .to_owned();

    let mut authenticator = XalAuthenticator::from(token_store.clone());
    let xsts_halo_waypoint = authenticator
        .get_xsts_token(
            None,
            None,
            token_store.user_token.as_ref(),
            "https://prod.xsts.halowaypoint.com/",
        )
        .await?;

    let xsts_token = xsts_halo_waypoint.token;

    let spartan_token_request = json!({
        "Audience": "urn:343:s3:services",
        "MinVersion": "4",
        "Proof": [{
            "Token": xsts_token,
            "TokenType": "Xbox_XSTSv3"
        }]
    });

    /* Halo stuff */
    let client = reqwest::ClientBuilder::new().build()?;

    // Fetch spartan token
    let spartan_token = client
        .post("https://settings.svc.halowaypoint.com/spartan-token")
        .header(
            "User-Agent",
            "HaloWaypoint/2021112313511900 CFNetwork/1327.0.4 Darwin/21.2.0",
        )
        .header("Accept", "application/json")
        .json(&spartan_token_request)
        .send()
        .await?
        .json_ex::<SpartanTokenResponse>()
        .await?;
    println!("Spartan Token: {spartan_token:?}");

    let clearance_url = format!("https://settings.svc.halowaypoint.com/oban/flight-configurations/titles/hi/audiences/RETAIL/players/xuid({xuid})/active?sandbox=UNUSED&build=210921.22.01.10.1706-0");
    // Get halo clearance token
    let flighting_config = client
        .get(clearance_url)
        .header(
            "User-Agent",
            "HaloWaypoint/2021112313511900 CFNetwork/1327.0.4 Darwin/21.2.0",
        )
        .header("Accept", "application/json")
        .header("x-343-authorization-spartan", spartan_token.spartan_token)
        .send()
        .await?
        .json_ex::<FlightConfiguration>()
        .await?;
    println!("Flighting: {flighting_config:?}");

    Ok(())
}
