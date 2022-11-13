use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;

use crate::authenticator::SpecialTokenResponse;
use crate::{
    app_params::{XalAppParameters, XalClientParameters},
    models::response::{SisuAuthorizationResponse, XCloudTokenResponse, XSTSResponse},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenStore {
    pub app_params: XalAppParameters,
    pub client_params: XalClientParameters,
    pub wl_token: SpecialTokenResponse,
    pub sisu_tokens: SisuAuthorizationResponse,
    pub gssv_token: XSTSResponse,
    pub xcloud_transfer_token: XCloudTokenResponse,
    pub updated: DateTime<Utc>,
}

impl TokenStore {
    pub fn load(filepath: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let s = fs::read_to_string(filepath)?;
        serde_json::from_str(&s).map_err(|e| e.into())
    }

    pub fn save(&self, filepath: &str) -> Result<(), Box<dyn std::error::Error>> {
        let s = serde_json::to_string_pretty(self)?;
        fs::write(filepath, s).map_err(|e| e.into())
    }
}
