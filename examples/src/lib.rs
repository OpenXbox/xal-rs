use clap::{Parser, ValueEnum};
use env_logger::Env;
use log::info;
use xal::{
    AccessTokenPrefix, AuthPromptCallback, Constants, Error, Flows, TokenStore, XalAppParameters,
    XalAuthenticator, XalClientParameters,
};

/// Common cli arguments
#[derive(Parser, Debug)]
#[command(author, about, long_about = None)]
pub struct Cli {
    /// Increase message verbosity ('-v' -> debug, '-vv' -> trace)
    #[arg(short, action = clap::ArgAction::Count)]
    pub verbosity: u8,

    /// Filepath to tokenstore JSON
    /// If it doesn't exists, it will be created upon successful authentication
    #[arg(short, long, default_value = "tokens.json")]
    pub token_filepath: String,

    /// Type of authentication flow to use
    #[arg(short, long, value_enum, default_value = "sisu")]
    pub flow: AuthFlow,
    // Whether to do title authentication
    // NOTE: Only works with Minecraft Client ID
    //#[arg(short, long)]
    //pub authenticate_title: bool,
}

pub fn get_loglevel(verbosity: u8) -> String {
    let default_loglevel = match verbosity {
        0 => "info",
        1 => "debug",
        2 => "trace",
        _ => "trace",
    };

    default_loglevel.to_string()
}

pub fn handle_args() -> Cli {
    let args = Cli::parse();
    let default_loglevel = get_loglevel(args.verbosity);
    env_logger::Builder::from_env(Env::default().default_filter_or(default_loglevel)).init();

    args
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AuthFlow {
    Sisu,
    DeviceCode,
    Implicit,
    AuthorizationCode,
}

pub async fn auth_main_default(
    access_token_prefix: AccessTokenPrefix,
    auth_cb: impl AuthPromptCallback,
) -> Result<TokenStore, Error> {
    auth_main(
        XalAppParameters::default(),
        XalClientParameters::default(),
        "RETAIL".to_owned(),
        access_token_prefix,
        auth_cb,
    )
    .await
}

/// Entrypoint for examples
pub async fn auth_main(
    app_params: XalAppParameters,
    client_params: XalClientParameters,
    sandbox_id: String,
    access_token_prefix: AccessTokenPrefix,
    auth_cb: impl AuthPromptCallback,
) -> Result<TokenStore, Error> {
    let args = handle_args();

    let mut ts = match Flows::try_refresh_live_tokens_from_file(&args.token_filepath).await {
        Ok((mut authenticator, ts)) => {
            info!("Tokens refreshed succesfully, proceeding with Xbox Live Authorization");
            match args.flow {
                AuthFlow::Sisu => {
                    info!("Authorize and gather rest of xbox live tokens via sisu");
                    Flows::xbox_live_sisu_authorization_flow(&mut authenticator, ts.live_token)
                        .await?
                }
                _ => {
                    info!("Authorize Xbox Live the traditional way, via individual requests");
                    Flows::xbox_live_authorization_traditional_flow(
                        &mut authenticator,
                        ts.live_token,
                        Constants::RELYING_PARTY_XBOXLIVE.into(),
                        access_token_prefix,
                        false,
                    )
                    .await?
                }
            }
        }
        Err(err) => {
            log::error!("Refreshing tokens failed err={err}");
            let mut authenticator = XalAuthenticator::new(app_params, client_params, sandbox_id);

            info!("Authentication via flow={:?}", args.flow);
            let ts = match args.flow {
                AuthFlow::Sisu => {
                    Flows::xbox_live_sisu_full_flow(&mut authenticator, auth_cb).await?
                }
                AuthFlow::DeviceCode => {
                    Flows::ms_device_code_flow(&mut authenticator, auth_cb, tokio::time::sleep)
                        .await?
                }
                AuthFlow::Implicit => {
                    Flows::ms_authorization_flow(&mut authenticator, auth_cb, true).await?
                }
                AuthFlow::AuthorizationCode => {
                    Flows::ms_authorization_flow(&mut authenticator, auth_cb, false).await?
                }
            };

            match args.flow {
                AuthFlow::Sisu => ts,
                _ => {
                    info!("Continuing flow via traditional Xbox Live authorization");
                    // Only required for non-sisu authentication, as
                    // sisu already gathers all the tokens at once
                    Flows::xbox_live_authorization_traditional_flow(
                        &mut authenticator,
                        ts.live_token,
                        Constants::RELYING_PARTY_XBOXLIVE.into(),
                        access_token_prefix,
                        false,
                    )
                    .await?
                }
            }
        }
    };

    ts.update_timestamp();
    ts.save_to_file(&args.token_filepath)?;

    Ok(ts)
}
