use xal::{CliCallbackHandler, AccessTokenPrefix, Error};
use xal_examples::auth_main_default;

#[tokio::main]
async fn main() -> Result<(), Error> {
    auth_main_default(AccessTokenPrefix::None, CliCallbackHandler)
        .await
        .ok();

    Ok(())
}
