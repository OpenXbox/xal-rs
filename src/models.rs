use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub enum SigningAlgorithm {
    ES256,
    ES384,
    ES521,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SigningPolicy {
    pub version: i32,
    pub supported_algorithms: Vec<SigningAlgorithm>,
    pub max_body_bytes: usize,
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            supported_algorithms: vec![SigningAlgorithm::ES256],
            max_body_bytes: 8192,
        }
    }
}

pub mod request {
    use josekit::jwk::Jwk;

    use super::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XADProperties<'a> {
        pub auth_method: &'a str,
        pub id: &'a str,
        pub device_type: &'a str,
        pub version: &'a str,
        pub proof_key: Jwk,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XADRequest<'a> {
        pub relying_party: &'a str,
        pub token_type: &'a str,
        pub properties: XADProperties<'a>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct SisuQuery<'a> {
        pub display: &'a str,
        pub code_challenge: &'a str,
        pub code_challenge_method: &'a str,
        pub state: &'a str,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SisuAuthenticationRequest<'a> {
        pub app_id: &'a str,
        pub title_id: &'a str,
        pub redirect_uri: &'a str,
        pub device_token: &'a str,
        pub sandbox: &'a str,
        pub token_type: &'a str,
        pub offers: Vec<&'a str>,
        pub query: SisuQuery<'a>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SisuAuthorizationRequest<'a> {
        pub access_token: &'a str,
        pub app_id: &'a str,
        pub device_token: &'a str,
        pub sandbox: &'a str,
        pub site_name: &'a str,
        pub session_id: &'a str,
        pub proof_key: Jwk,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct WindowsLiveTokenRequest<'a> {
        pub client_id: &'a str,
        pub refresh_token: Option<&'a str>,
        pub grant_type: &'a str,
        pub scope: &'a str,
        pub redirect_uri: Option<&'a str>,
        pub code: Option<&'a str>,
        pub code_verifier: Option<&'a str>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XSTSProperties<'a> {
        pub sandbox_id: &'a str,
        pub device_token: &'a str,
        pub title_token: &'a str,
        pub user_tokens: Vec<&'a str>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XSTSRequest<'a> {
        pub relying_party: &'a str,
        pub token_type: &'a str,
        pub properties: XSTSProperties<'a>,
    }
}

pub mod response {
    use oauth2::{
        basic::BasicTokenType, helpers, AccessToken, ExtraTokenFields, RefreshToken, Scope,
    };

    use super::{Deserialize, HashMap, Serialize, SigningPolicy};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TokenData {
        pub issue_instant: String,
        pub not_after: String,
        pub token: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct XADDisplayClaims {
        /// {"xdi": {"did": "F.....", "dcs": "0"}}
        pub xdi: HashMap<String, String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XADResponse {
        #[serde(flatten)]
        pub token_data: TokenData,
        pub display_claims: XADDisplayClaims,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct XATDisplayClaims {
        pub xti: HashMap<String, String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XATResponse {
        #[serde(flatten)]
        pub token_data: TokenData,
        pub display_claims: XATDisplayClaims,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct XAUDisplayClaims {
        pub xui: Vec<HashMap<String, String>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XAUResponse {
        #[serde(flatten)]
        pub token_data: TokenData,
        pub display_claims: XAUDisplayClaims,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct XSTSDisplayClaims {
        pub xui: Vec<HashMap<String, String>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct XSTSResponse {
        #[serde(flatten)]
        pub token_data: TokenData,
        pub display_claims: XSTSDisplayClaims,
    }

    impl XSTSResponse {
        pub fn userhash(&self) -> String {
            self.display_claims.xui[0]["uhs"].clone()
        }
        pub fn authorization_header_value(&self) -> String {
            format!("XBL3.0 x={};{}", self.userhash(), self.token_data.token)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SisuAuthenticationResponse {
        pub msa_oauth_redirect: String,
        pub msa_request_parameters: HashMap<String, String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SisuAuthorizationResponse {
        pub device_token: String,
        pub title_token: XATResponse,
        pub user_token: XAUResponse,
        pub authorization_token: XSTSResponse,
        pub web_page: String,
        pub sandbox: String,
        pub use_modern_gamertag: Option<bool>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct WindowsLiveTokenResponse<EF: ExtraTokenFields> {
        pub token_type: Option<BasicTokenType>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_in: Option<u64>,
        #[serde(rename = "scope")]
        #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
        #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        pub scopes: Option<Vec<Scope>>,
        pub access_token: AccessToken,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub refresh_token: Option<RefreshToken>,
        pub user_id: String,

        #[serde(bound = "EF: ExtraTokenFields")]
        #[serde(flatten)]
        pub extra_fields: EF,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct XCloudTokenResponse {
        pub lpt: String,
        pub refresh_token: String,
        pub user_id: String,
    }

    impl From<XCloudTokenResponse> for RefreshToken {
        fn from(t: XCloudTokenResponse) -> Self {
            Self::new(t.refresh_token)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TitleEndpointCertificate {
        pub thumbprint: String,
        pub is_issuer: Option<bool>,
        pub root_cert_index: i32,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TitleEndpointsResponse {
        pub end_points: Vec<TitleEndpoint>,
        pub signature_policies: Vec<SigningPolicy>,
        pub certs: Vec<TitleEndpointCertificate>,
        pub root_certs: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct TitleEndpoint {
        pub protocol: String,
        pub host: String,
        pub host_type: String,
        pub path: Option<String>,
        pub relying_party: Option<String>,
        pub sub_relying_party: Option<String>,
        pub token_type: Option<String>,
        pub signature_policy_index: Option<i32>,
        pub server_cert_index: Option<Vec<i32>>,
    }
}

#[cfg(test)]
mod test {
    use super::{response, SigningAlgorithm, SigningPolicy};
    use serde_json;

    #[test]
    fn deserialize_xsts() {
        let data = r#"
        {
            "IssueInstant": "2010-10-10T03:06:35.5251155Z",
            "NotAfter": "2999-10-10T19:06:35.5251155Z",
            "Token": "123456789",
            "DisplayClaims": {
              "xui": [
                {
                  "gtg": "e",
                  "xid": "2669321029139235",
                  "uhs": "abcdefg",
                  "agg": "Adult",
                  "usr": "",
                  "utr": "",
                  "prv": ""
                }
              ]
            }
        }
        "#;

        let bla: response::XSTSResponse =
            serde_json::from_str(data).expect("BUG: Failed to deserialize XSTS response");

        assert_eq!(bla.userhash(), "abcdefg");
        assert_eq!(
            bla.authorization_header_value(),
            "XBL3.0 x=abcdefg;123456789"
        );
        assert_eq!(bla.token_data.token, "123456789".to_owned());
        assert_eq!(bla.display_claims.xui[0].get("gtg"), Some(&"e".to_owned()));
        assert_ne!(
            bla.display_claims.xui[0].get("uhs"),
            Some(&"invalid".to_owned())
        );
    }

    #[test]
    fn deserialize_signing_policy() {
        let json_resp = r#"{
            "Version": 99,
            "SupportedAlgorithms": ["ES521"],
            "MaxBodyBytes": 1234
        }"#;

        let deserialized: SigningPolicy =
            serde_json::from_str(json_resp).expect("Failed to deserialize SigningPolicy");

        assert_eq!(deserialized.version, 99);
        assert_eq!(deserialized.max_body_bytes, 1234);
        assert_eq!(
            deserialized.supported_algorithms,
            vec![SigningAlgorithm::ES521]
        )
    }
}
