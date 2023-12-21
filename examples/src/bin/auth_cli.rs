use xal::{AccessTokenPrefix, CliCallbackHandler, Error};
use xal_examples::auth_main_default;

#[tokio::main]
async fn main() -> Result<(), Error> {
    auth_main_default(AccessTokenPrefix::None, CliCallbackHandler)
        .await?;

    Ok(())
}
