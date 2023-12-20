#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! XAL - Xbox Live Authentication Library for Rust
//!
//! This library aims at giving a high range of configurability to the user, so that authentication
//! can be targeted inidividually for each required scenario.
//!
//! Features:
//! - (Lower level) OAuth2 Authentication - see [`crate::XalAuthenticator`]
//! - (Higher level) Authentication flows - see [`crate::Flows`]
//! - (Standalone) HTTP Request Signing - see [`crate::RequestSigner`]
//! - Container for storing tokens / authentication parameters - see [`crate::TokenStore`]
//! - Extensions for Reqwest HTTP client library - see [`crate::extensions`]
//!   - Verbose errors for JSON deserialization - see [`crate::extensions::JsonExDeserializeMiddleware`]
//!   - Debug logging for HTTP requests - see [`crate::extensions::LoggingReqwestRequestHandler`]
//!   - Debug logging for HTTP responses - see [`crate::extensions::LoggingReqwestResponseHandler`]
//!   - Signing HTTP requests - see [`crate::extensions::SigningReqwestBuilder`]
//!   - Adding `MS-CV` header to requests - see [`crate::extensions::CorrelationVectorReqwestBuilder`]
//!
//! # Quick Start
//!
//! Authenticate and save tokens to JSON file `tokens.json`
//!
//! ```no_run
//! use xal::{XalAuthenticator, Flows, CliCallbackHandler};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut authenticator = XalAuthenticator::default();
//!
//!     // Do full SISU auth flow
//!     let mut token_store = Flows::xbox_live_sisu_full_flow(
//!         &mut authenticator,
//!         CliCallbackHandler
//!     ).await?;
//! 
//!     // User will be prompted on commandline to proceed with authentication
//!
//!     token_store.update_timestamp();
//!     token_store.save_to_file("tokens.json")?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! Load tokens from file and refresh them
//!
//! ```no_run
//! use xal::{XalAuthenticator, Flows, CliCallbackHandler};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     println!("Trying to refresh tokens...");
//!     let mut token_store = match Flows::try_refresh_live_tokens_from_file("tokens.json").await {
//!         Ok((mut authenticator, ts)) => {
//!             println!("Tokens refreshed succesfully, proceeding with Xbox Live Authorization");
//!             Flows::xbox_live_sisu_authorization_flow(&mut authenticator, ts.live_token)
//!                 .await?
//!         },
//!         Err(err) => {
//!             eprintln!("Refreshing tokens failed err={err}");
//!             let mut authenticator = XalAuthenticator::default();
//!             println!("Authentication via SISU");
//!             Flows::xbox_live_sisu_full_flow(&mut authenticator, CliCallbackHandler)
//!                 .await?
//!         }
//!     };
//!
//!     token_store.update_timestamp();
//!     token_store.save_to_file("tokens.json")?;
//!     Ok(())
//! }
//! ```
//!
//! Make use of acquired XSTS token
//!
//! ```no_run
//! use xal::{XalAuthenticator, Flows, CliCallbackHandler};
//! use xal::extensions::JsonExDeserializeMiddleware;
//! use xal::oauth2::TokenResponse;
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an authenticator with minecraft client parameters
//!     let mut authenticator = XalAuthenticator::new(
//!         xal::app_params::MC_BEDROCK_SWITCH(),
//!         xal::client_params::CLIENT_NINTENDO(),
//!         "RETAIL".into(),
//!     );
//!
//!     // Do full SISU authentication flow
//!     let mut token_store = Flows::xbox_live_sisu_full_flow(
//!         &mut authenticator,
//!         CliCallbackHandler
//!     ).await?;
//!
//!     // Authorize to XSTS endpoint via Minecraft RelyingParty
//!     let xsts_mc_services = authenticator
//!         .get_xsts_token(
//!             token_store.device_token.as_ref(),
//!             token_store.title_token.as_ref(),
//!             token_store.user_token.as_ref(),
//!             "rp://api.minecraftservices.com/"
//!         )
//!         .await?;
//!
//!     let identity_token = xsts_mc_services.authorization_header_value();
//!     println!("identityToken: {identity_token}");
//!     
//!     /* Minecraft stuff */
//!     // Exchange XSTS Token against Minecraft Token
//!     let mc_token = reqwest::Client::new()
//!         .post("https://api.minecraftservices.com/authentication/login_with_xbox")
//!         .json(&json!({"identityToken": identity_token}))
//!         .send()
//!         .await?
//!         .json_ex::<xal::oauth2::basic::BasicTokenResponse>()
//!         .await?;
//!     println!("MC: {mc_token:?}");
//!     
//!     // Get minecraft profile, use Minecraft Token as Bearer Auth
//!     let profile = reqwest::Client::new()
//!         .get("https://api.minecraftservices.com/minecraft/profile")
//!         .bearer_auth(mc_token.access_token().secret())
//!         .send()
//!         .await?
//!         .text()
//!         .await?;
//!     println!("Profile: {profile}");
//!     Ok(())
//! }
//! ```
//!
//! Loading tokens from file and sending a signed a request
//!
//! ```no_run
//! use xal::{
//!     RequestSigner, TokenStore, Error,
//!     extensions::{
//!         SigningReqwestBuilder,
//!         CorrelationVectorReqwestBuilder,
//!         
//!     },
//!     cvlib::CorrelationVector,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load tokens from JSON
//!     let token_store = TokenStore::load_from_file("tokens.json")?;
//!
//!     // Create new instances of Correlation vector and request signer
//!     let mut cv = CorrelationVector::new();
//!     let mut signer = RequestSigner::new();
//!
//!     // Check if XSTS token exists
//!     let xsts_token = token_store.authorization_token
//!         .ok_or(Error::GeneralError("No XSTS token was acquired".into()))?;
//!
//!     // Send a http request
//!     // Request will get signed and MS-CV header populated
//!     let userpresence = reqwest::Client::new()
//!         .get("https://userpresence.xboxlive.com/users/me?level=all")
//!         .header("x-xbl-contract-version", "3")
//!         .header("Authorization", xsts_token.authorization_header_value())
//!         .add_cv(&mut cv)?
//!         .sign(&mut signer, None)
//!         .await?
//!         .send()
//!         .await?;
//!    
//!     println!("{:?}", userpresence);   
//!     Ok(())
//! }
//! ```
//!
//! # Examples
//!
//! Check out the [xal-examples](https://github.com/OpenXbox/xal-rs/tree/master/examples).
//!
//! # Advanced
//!
//! For advanced usage, see [`crate::XalAuthenticator`].

pub use cvlib;
pub use oauth2;
pub use url;

mod authenticator;
mod error;
mod flows;
mod models;
mod request_signer;
mod tokenstore;

pub mod extensions;
pub use authenticator::*;
pub use error::Error;
pub use flows::*;
pub use models::*;
pub use request_signer::*;
pub use tokenstore::*;
