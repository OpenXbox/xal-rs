//! Token store

use crate::{
    response::{DeviceToken, TitleToken, UserToken, WindowsLiveTokens, XSTSToken},
    Error, XalAppParameters, XalAuthenticator, XalClientParameters,
};
use chrono::{DateTime, Utc};
use log::trace;
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek};

/// Model describing authentication tokens
///
/// Can be used for de-/serializing tokens and respective
/// authentication parameters.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenStore {
    /// Stored app parameters
    pub app_params: XalAppParameters,
    /// Stored client parameters
    pub client_params: XalClientParameters,
    /// Xbox Live sandbox id used for authentication
    pub sandbox_id: String,
    /// Windows Live access- & refresh token
    pub live_token: WindowsLiveTokens,
    /// Xbox live user token
    pub user_token: Option<UserToken>,
    /// Xbox live title token
    pub title_token: Option<TitleToken>,
    /// Xbox live device token
    pub device_token: Option<DeviceToken>,
    /// Xbox live authorization/XSTS token
    pub authorization_token: Option<XSTSToken>,
    /// Update timestamp of this struct
    ///
    /// Can be updated by calling `update_timestamp`
    /// on its instance.
    pub updated: Option<DateTime<Utc>>,
}

impl From<TokenStore> for XalAuthenticator {
    fn from(value: TokenStore) -> Self {
        Self::new(
            value.app_params.clone(),
            value.client_params.clone(),
            value.sandbox_id.clone(),
        )
    }
}

impl ToString for TokenStore {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("Failed to serialize TokenStore")
    }
}

impl TokenStore {
    /// Load a tokenstore from a file by providing the filename/path to the
    /// serialized JSON
    ///
    /// Returns the json string if possible
    pub fn load_from_file(filepath: &str) -> Result<Self, Error> {
        trace!("Trying to load tokens from filepath={:?}", filepath);
        let mut file = std::fs::File::options().read(true).open(filepath)?;

        let mut json = String::new();
        file.read_to_string(&mut json)?;

        Self::deserialize_from_string(&json)
    }

    /// Load tokens from file
    pub fn deserialize_from_string(json: &str) -> Result<Self, Error> {
        trace!("Attempting to deserialize token data");
        serde_json::from_str(json).map_err(std::convert::Into::into)
    }

    /// Save tokens to writer
    pub fn save_to_writer(&self, writer: impl std::io::Write) -> Result<(), Error> {
        serde_json::to_writer_pretty(writer, self).map_err(std::convert::Into::into)
    }

    /// Save the tokens to a JSON file
    ///
    /// NOTE: If the file already exists it will be overwritten
    pub fn save_to_file(&self, filepath: &str) -> Result<(), Error> {
        trace!(
            "Trying to open tokenfile read/write/create path={:?}",
            filepath
        );
        let mut file = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(filepath)?;

        file.rewind()?;
        file.set_len(0)?;

        trace!("Saving tokens path={:?}", filepath);
        self.save_to_writer(file)
    }

    /// Update the timestamp of this instance
    pub fn update_timestamp(&mut self) {
        self.updated = Some(chrono::offset::Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString};

    use super::*;

    fn random_filename() -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), 16)
    }

    #[test]
    fn read_invalid_tokenfile() {
        let res = TokenStore::load_from_file(&random_filename());

        assert!(res.is_err());
    }
}
