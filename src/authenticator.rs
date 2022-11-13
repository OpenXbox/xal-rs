use crate::app_params::XalAppParameters;

use super::{
    app_params::{DeviceType, XalClientParameters},
    models::request,
    models::response,
    request_signer::{self, SigningReqwestBuilder},
};
use base64;
use cvlib;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    reqwest::async_http_client,
    url, AccessToken, AuthType, AuthUrl, AuthorizationCode, Client as OAuthClient, ClientId,
    EmptyExtraTokenFields, ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RefreshToken, Scope, StandardRevocableToken, TokenResponse, TokenType, TokenUrl,
};
use reqwest;
use std::time::Duration;
use url::Url;
use uuid;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub type SpecialTokenResponse = response::WindowsLiveTokenResponse<EmptyExtraTokenFields>;
type SpecialClient = OAuthClient<
    BasicErrorResponse,
    SpecialTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

impl<EF> TokenResponse<BasicTokenType> for response::WindowsLiveTokenResponse<EF>
where
    EF: ExtraTokenFields,
    BasicTokenType: TokenType,
{
    ///
    /// REQUIRED. The access token issued by the authorization server.
    ///
    fn access_token(&self) -> &AccessToken {
        &self.access_token
    }
    ///
    /// REQUIRED. The type of the token issued as described in
    /// [Section 7.1](https://tools.ietf.org/html/rfc6749#section-7.1).
    /// Value is case insensitive and deserialized to the generic `TokenType` parameter.
    /// But in this particular case as the service is non compliant, it has a default value
    ///
    fn token_type(&self) -> &BasicTokenType {
        match &self.token_type {
            Some(t) => t,
            None => &BasicTokenType::Bearer,
        }
    }
    ///
    /// RECOMMENDED. The lifetime in seconds of the access token. For example, the value 3600
    /// denotes that the access token will expire in one hour from the time the response was
    /// generated. If omitted, the authorization server SHOULD provide the expiration time via
    /// other means or document the default value.
    ///
    fn expires_in(&self) -> Option<Duration> {
        self.expires_in.map(Duration::from_secs)
    }
    ///
    /// OPTIONAL. The refresh token, which can be used to obtain new access tokens using the same
    /// authorization grant as described in
    /// [Section 6](https://tools.ietf.org/html/rfc6749#section-6).
    ///
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }
    ///
    /// OPTIONAL, if identical to the scope requested by the client; otherwise, REQUIRED. The
    /// scipe of the access token as described by
    /// [Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3). If included in the response,
    /// this space-delimited field is parsed into a `Vec` of individual scopes. If omitted from
    /// the response, this field is `None`.
    ///
    fn scopes(&self) -> Option<&Vec<Scope>> {
        self.scopes.as_ref()
    }
}

#[derive(Debug)]
pub struct XalAuthenticator {
    device_id: uuid::Uuid,
    app_params: XalAppParameters,
    client_params: XalClientParameters,
    ms_cv: cvlib::CorrelationVector,
    client: reqwest::Client,
    client2: SpecialClient,
    request_signer: request_signer::RequestSigner,
}

impl Default for XalAuthenticator {
    fn default() -> Self {
        let client_params = XalClientParameters::default();
        let app_params = XalAppParameters::default();
        let client_id = ClientId::new(app_params.app_id.clone());
        let client_secret = None;

        let auth_url = AuthUrl::new("https://login.live.com/oauth20_authorize.srf".into())
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new("https://login.live.com/oauth20_token.srf".into())
            .expect("Invalid token endpoint URL");
        let redirect_url =
            RedirectUrl::new(app_params.redirect_uri.clone()).expect("Invalid redirect URL");

        let client2 = OAuthClient::new(client_id, client_secret, auth_url, Some(token_url))
            .set_auth_type(AuthType::RequestBody)
            .set_redirect_uri(redirect_url);

        Self {
            device_id: uuid::Uuid::new_v4(),
            app_params,
            client_params,
            ms_cv: cvlib::CorrelationVector::new(),
            client: reqwest::Client::new(),
            client2,
            request_signer: request_signer::RequestSigner::default(),
        }
    }
}

impl XalAuthenticator {
    pub fn get_code_challenge() -> (PkceCodeChallenge, PkceCodeVerifier) {
        PkceCodeChallenge::new_random_sha256()
    }

    pub fn generate_random_state() -> String {
        let state = uuid::Uuid::new_v4().hyphenated().to_string();

        base64::encode(state)
    }
}

impl XalAuthenticator {
    pub fn app_params(&self) -> XalAppParameters {
        self.app_params.clone()
    }

    pub fn client_params(&self) -> XalClientParameters {
        self.client_params.clone()
    }

    pub fn get_redirect_uri(&self) -> Url {
        self.client2.redirect_url().unwrap().url().to_owned()
    }

    fn next_cv(&mut self) -> String {
        self.ms_cv.increment();
        self.ms_cv.to_string()
    }

    pub async fn exchange_code_for_token(
        &mut self,
        authorization_code: &str,
        code_verifier: PkceCodeVerifier,
    ) -> Result<SpecialTokenResponse> {
        let code = AuthorizationCode::new(authorization_code.into());
        let token = self
            .client2
            .exchange_code(code)
            .set_pkce_verifier(code_verifier)
            .add_extra_param("scope", "service::user.auth.xboxlive.com::MBI_SSL")
            .request_async(async_http_client)
            .await?;

        Ok(token)
    }

    pub async fn exchange_refresh_token_for_xcloud_transfer_token(
        &mut self,
        refresh_token: &RefreshToken,
    ) -> Result<response::XCloudTokenResponse> {
        let form_body = request::WindowsLiveTokenRequest {
            client_id: &self.app_params.app_id.clone(),
            grant_type: "refresh_token",
            scope:
                "service::http://Passport.NET/purpose::PURPOSE_XBOX_CLOUD_CONSOLE_TRANSFER_TOKEN",
            refresh_token: Some(refresh_token.secret()),
            code: None,
            code_verifier: None,
            redirect_uri: None,
        };

        self.client
            .post("https://login.live.com/oauth20_token.srf")
            .header("MS-CV", self.next_cv())
            .form(&form_body)
            .send()
            .await?
            .json::<response::XCloudTokenResponse>()
            .await
            .map_err(|e| e.into())
    }

    pub async fn refresh_token(
        &mut self,
        refresh_token: &RefreshToken,
    ) -> Result<SpecialTokenResponse> {
        let token = self
            .client2
            .exchange_refresh_token(refresh_token)
            .add_scope(Scope::new(
                "service::user.auth.xboxlive.com::MBI_SSL".into(),
            ))
            .request_async(async_http_client)
            .await?;

        Ok(token)
    }
}

impl XalAuthenticator {
    pub async fn get_endpoints(&self) -> Result<response::TitleEndpointsResponse> {
        let resp = self
            .client
            .get("https://title.mgt.xboxlive.com/titles/default/endpoints")
            .header("x-xbl-contract-version", "1")
            .query(&[("type", 1)])
            .send()
            .await?
            .json::<response::TitleEndpointsResponse>()
            .await?;

        Ok(resp)
    }

    pub async fn get_device_token(&mut self) -> Result<response::XADResponse> {
        let client_uuid: String = match self.client_params.device_type {
            // {decf45e4-945d-4379-b708-d4ee92c12d99}
            DeviceType::ANDROID => [
                "{".to_string(),
                self.device_id.hyphenated().to_string(),
                "}".to_string(),
            ]
            .concat(),

            // DECF45E4-945D-4379-B708-D4EE92C12D99
            DeviceType::IOS => self.device_id.hyphenated().to_string().to_uppercase(),
            // Unknown
            _ => self.device_id.hyphenated().to_string(),
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-xbl-contract-version", "1".parse()?);
        headers.insert("MS-CV", self.next_cv().parse()?);

        let json_body = request::XADRequest {
            relying_party: "http://auth.xboxlive.com",
            token_type: "JWT",
            properties: request::XADProperties {
                auth_method: "ProofOfPossession",
                id: client_uuid.as_str(),
                device_type: &self.client_params.device_type.to_string(),
                version: &self.client_params.client_version,
                proof_key: self.request_signer.get_proof_key(),
            },
        };

        self.client
            .post("https://device.auth.xboxlive.com/device/authenticate")
            .headers(headers)
            .json(&json_body)
            .sign(&self.request_signer, None)?
            .send()
            .await?
            .json::<response::XADResponse>()
            .await
            .map_err(|e| e.into())
    }

    /// Sisu authentication
    /// Returns tuple:
    /// 1. Part: Response that contains authorization URL
    /// 2. Part: Session ID from response headers (X-SessionId)
    pub async fn do_sisu_authentication(
        &mut self,
        device_token: &str,
        code_challenge: PkceCodeChallenge,
        state: &str,
    ) -> Result<(response::SisuAuthenticationResponse, String)> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-xbl-contract-version", "1".parse()?);
        headers.insert("MS-CV", self.next_cv().parse()?);

        let json_body = request::SisuAuthenticationRequest {
            app_id: &self.app_params.app_id,
            title_id: &self.app_params.title_id,
            redirect_uri: &self.app_params.redirect_uri,
            device_token,
            sandbox: "RETAIL",
            token_type: "code",
            offers: vec!["service::user.auth.xboxlive.com::MBI_SSL"],
            query: request::SisuQuery {
                display: &self.client_params.query_display,
                code_challenge: code_challenge.as_str(),
                code_challenge_method: code_challenge.method(),
                state,
            },
        };

        let resp = self
            .client
            .post("https://sisu.xboxlive.com/authenticate")
            .headers(headers)
            .json(&json_body)
            .sign(&self.request_signer, None)?
            .send()
            .await?;

        let session_id = resp
            .headers()
            .get("X-SessionId")
            .ok_or("Failed to fetch session id")?
            .to_str()?
            .to_owned();

        let resp_json = resp.json::<response::SisuAuthenticationResponse>().await?;

        Ok((resp_json, session_id))
    }

    pub async fn do_sisu_authorization(
        &mut self,
        sisu_session_id: &str,
        access_token: &str,
        device_token: &str,
    ) -> Result<response::SisuAuthorizationResponse> {
        let json_body = request::SisuAuthorizationRequest {
            access_token: &format!("t={}", access_token),
            app_id: &self.app_params.app_id.clone(),
            device_token,
            sandbox: "RETAIL",
            site_name: "user.auth.xboxlive.com",
            session_id: sisu_session_id,
            proof_key: self.request_signer.get_proof_key(),
        };

        self.client
            .post("https://sisu.xboxlive.com/authorize")
            .header("MS-CV", self.next_cv())
            .json(&json_body)
            .sign(&self.request_signer, None)?
            .send()
            .await?
            .json::<response::SisuAuthorizationResponse>()
            .await
            .map_err(|e| e.into())
    }

    pub async fn do_xsts_authorization(
        &mut self,
        device_token: &str,
        title_token: &str,
        user_token: &str,
        relying_party: &str,
    ) -> Result<response::XSTSResponse> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-xbl-contract-version", "1".parse()?);
        headers.insert("MS-CV", self.next_cv().parse()?);

        let json_body = request::XSTSRequest {
            relying_party,
            token_type: "JWT",
            properties: request::XSTSProperties {
                sandbox_id: "RETAIL",
                device_token,
                title_token,
                user_tokens: vec![user_token],
            },
        };

        self.client
            .post("https://xsts.auth.xboxlive.com/xsts/authorize")
            .headers(headers)
            .json(&json_body)
            .sign(&self.request_signer, None)?
            .send()
            .await?
            .json::<response::XSTSResponse>()
            .await
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        assert_eq!(true, true);
    }
}
