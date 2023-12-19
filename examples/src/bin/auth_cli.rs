use xal::{flows, AccessTokenPrefix, Error};
use xal_examples::auth_main_default;

#[tokio::main]
async fn main() -> Result<(), Error> {
    auth_main_default(AccessTokenPrefix::None, flows::CliCallbackHandler)
        .await
        .ok();

    Ok(())
}
