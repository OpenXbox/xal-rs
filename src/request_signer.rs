use crate::models::SigningPolicy;

use filetime_type::FileTime;
use oauth2::url::Position;
use super::models;
use base64::{self, DecodeError};
use chrono::prelude::*;
use josekit::{
    self,
    jwk::{alg::ec::EcKeyPair, Jwk},
};
use reqwest::{self, Method};
use std::{option::Option, str::FromStr};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct XboxWebSignatureBytes {
    signing_policy_version: Vec<u8>,
    timestamp: Vec<u8>,
    signed_digest: Vec<u8>,
}

impl From<&XboxWebSignatureBytes> for Vec<u8> {
    fn from(obj: &XboxWebSignatureBytes) -> Self {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(obj.signing_policy_version.as_slice());
        bytes.extend_from_slice(obj.timestamp.as_slice());
        bytes.extend_from_slice(obj.signed_digest.as_slice());

        bytes
    }
}

impl FromStr for XboxWebSignatureBytes {
    type Err = DecodeError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = base64::decode(s)?;
        Ok(bytes.into())
    }
}
impl From<Vec<u8>> for XboxWebSignatureBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            signing_policy_version: bytes[..4].to_vec(),
            timestamp: bytes[4..12].to_vec(),
            signed_digest: bytes[12..].to_vec(),
        }
    }
}

impl ToString for XboxWebSignatureBytes {
    fn to_string(&self) -> String {
        let bytes: Vec<u8> = self.into();
        base64::encode(bytes)
    }
}

#[derive(Debug)]
pub struct HttpRequestToSign {
    method: String,
    path_and_query: String,
    authorization: String,
    body: Vec<u8>,
}

impl From<reqwest::Request> for HttpRequestToSign {
    fn from(request: reqwest::Request) -> Self {
        let url = request.url();

        let auth_header_val = match request.headers().get(reqwest::header::AUTHORIZATION) {
            Some(val) => val
                .to_str()
                .expect("Failed serializing Authentication header to string"),
            None => "",
        };

        let body = match *request.method() {
            Method::GET => {
                vec![]
            }
            Method::POST => request
                .body()
                .expect("Failed to get body from HTTP request")
                .as_bytes()
                .expect("Failed to convert HTTP body to bytes")
                .to_vec(),
            _ => panic!("Unhandled HTTP method: {:?}", request.method()),
        };

        HttpRequestToSign {
            method: request.method().to_string().to_uppercase(),
            path_and_query: url[Position::BeforePath..].to_owned(),
            authorization: auth_header_val.to_owned(),
            body,
        }
    }
}

#[derive(Debug)]
pub struct RequestSigner {
    pub keypair: EcKeyPair,
    pub signing_policy: models::SigningPolicy,
}

impl Default for RequestSigner {
    fn default() -> Self {
        Self::new(SigningPolicy::default())
    }
}

pub trait SigningReqwestBuilder {
    fn sign(
        self,
        signer: &RequestSigner,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<reqwest::RequestBuilder>;
}

impl SigningReqwestBuilder for reqwest::RequestBuilder {
    fn sign(
        self,
        signer: &RequestSigner,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<reqwest::RequestBuilder> {
        match self.try_clone() {
            Some(rb) => {
                let request = rb.build()?;
                // Fallback to Utc::now() internally
                let signed = signer.sign_request(request, timestamp)?;
                let body_bytes = signed
                    .body()
                    .ok_or("Failed getting request body")?
                    .as_bytes()
                    .ok_or("Failed getting bytes from request body")?
                    .to_vec();
                let headers = signed.headers().to_owned();

                Ok(self.headers(headers).body(body_bytes))
            }
            None => Err("Failed to clone RequestBuilder for signing".into()),
        }
    }
}

impl RequestSigner {
    pub fn new(policy: models::SigningPolicy) -> Self {
        Self {
            keypair: josekit::jws::ES256.generate_key_pair().unwrap(),
            signing_policy: policy,
        }
    }

    pub fn get_proof_key(&self) -> Jwk {
        let mut jwk = self.keypair.to_jwk_public_key();
        jwk.set_key_use("sig");

        jwk
    }

    pub fn sign_request(
        &self,
        request: reqwest::Request,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<reqwest::Request> {
        let mut clone_request = request.try_clone().unwrap();
        // Gather data from request used for signing
        let to_sign = request.into();

        // Create signature
        let signature = self
            .sign(
                self.signing_policy.version,
                timestamp.unwrap_or_else(Utc::now),
                &to_sign,
            )
            .expect("Signing request failed!");

        // Replace request body with byte representation (so signature creation is deterministic)
        clone_request.body_mut().replace(to_sign.body.into());

        // Assign Signature-header in request
        clone_request
            .headers_mut()
            .insert("Signature", signature.to_string().parse()?);

        Ok(clone_request)
    }

    /// Sign
    pub fn sign(
        &self,
        signing_policy_version: i32,
        timestamp: DateTime<Utc>,
        request: &HttpRequestToSign,
    ) -> Result<XboxWebSignatureBytes> {
        self.sign_raw(
            signing_policy_version,
            timestamp,
            request.method.to_owned(),
            request.path_and_query.to_owned(),
            request.authorization.to_owned(),
            &request.body,
        )
    }

    fn sign_raw(
        &self,
        signing_policy_version: i32,
        timestamp: DateTime<Utc>,
        method: String,
        path_and_query: String,
        authorization: String,
        body: &[u8],
    ) -> Result<XboxWebSignatureBytes> {
        let signer = josekit::jws::ES256.signer_from_jwk(&self.keypair.to_jwk_private_key())?;

        let filetime_bytes = FileTime::from(timestamp).filetime().to_be_bytes();
        let signing_policy_version_bytes = signing_policy_version.to_be_bytes();

        // Assemble the message to sign
        let message = self
            .assemble_message_data(
                &signing_policy_version_bytes,
                &filetime_bytes,
                method,
                path_and_query,
                authorization,
                body,
                self.signing_policy.max_body_bytes,
            )
            .expect("Failed to assemble message data !");

        // Sign the message
        let signed_digest: Vec<u8> = signer.sign(&message)?;

        // Return final signature
        Ok(XboxWebSignatureBytes {
            signing_policy_version: signing_policy_version_bytes.to_vec(),
            timestamp: filetime_bytes.to_vec(),
            signed_digest,
        })
    }

    pub fn verify_request(&self, request: reqwest::Request) -> Result<()> {
        let signature = request
            .try_clone()
            .ok_or("Failed to clone request")?
            .headers()
            .get("Signature")
            .ok_or("Failed to get signature header")?
            .to_str()?
            .to_owned();

        self.verify(
            XboxWebSignatureBytes::from_str(&signature)?,
            &request.into(),
        )
    }

    pub fn verify(
        &self,
        signature: XboxWebSignatureBytes,
        request: &HttpRequestToSign,
    ) -> Result<()> {
        let verifier = josekit::jws::ES256.verifier_from_jwk(&self.keypair.to_jwk_public_key())?;
        let message = self.assemble_message_data(
            &signature.signing_policy_version,
            &signature.timestamp,
            request.method.to_owned(),
            request.path_and_query.to_owned(),
            request.authorization.to_owned(),
            &request.body,
            self.signing_policy.max_body_bytes,
        )?;
        verifier
            .verify(&message, &signature.signed_digest)
            .map_err(|err| err.into())
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble_message_data(
        &self,
        signing_policy_version: &[u8],
        timestamp: &[u8],
        method: String,
        path_and_query: String,
        authorization: String,
        body: &[u8],
        max_body_bytes: usize,
    ) -> Result<Vec<u8>> {
        const NULL_BYTE: &[u8; 1] = &[0x00];

        let mut data = Vec::<u8>::new();
        // Signature version + null
        data.extend_from_slice(signing_policy_version);
        data.extend_from_slice(NULL_BYTE);

        // Timestamp + null
        data.extend_from_slice(timestamp);
        data.extend_from_slice(NULL_BYTE);

        // Method (uppercase) + null
        data.extend_from_slice(method.to_uppercase().as_bytes());
        data.extend_from_slice(NULL_BYTE);

        // Path and query + null
        data.extend_from_slice(path_and_query.as_bytes());
        data.extend_from_slice(NULL_BYTE);

        // Authorization (even if an empty string)
        data.extend_from_slice(authorization.as_bytes());
        data.extend_from_slice(NULL_BYTE);

        // Body
        let body_size_to_hash = std::cmp::min(max_body_bytes, body.len());
        data.extend_from_slice(&body[..body_size_to_hash]);
        data.extend_from_slice(NULL_BYTE);

        Ok(data)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::{
        reqwest, FileTime, HttpRequestToSign, RequestSigner, SigningReqwestBuilder,
        XboxWebSignatureBytes,
    };
    use chrono::prelude::*;
    use hex_literal::hex;
    use reqwest::{Body, Client};

    fn get_request_signer() -> RequestSigner {
        const PRIVATE_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----\n
    MHcCAQEEIObr5IVtB+DQcn25+R9n4K/EyUUSbVvxIJY7WhVeELUuoAoGCCqGSM49\n
    AwEHoUQDQgAEOKyCQ9qH5U4lZcS0c5/LxIyKvOpKe0l3x4Eg5OgDbzezKNLRgT28\n
    fd4Fq3rU/1OQKmx6jSq0vTB5Ao/48m0iGg==\n
    -----END EC PRIVATE KEY-----\n";

        RequestSigner {
            keypair: josekit::jws::ES256
                .key_pair_from_pem(PRIVATE_KEY_PEM)
                .unwrap(),
            signing_policy: Default::default(),
        }
    }

    #[test]
    fn sign() {
        let signer = get_request_signer();
        let dt = Utc.timestamp_opt(1586999965, 0).unwrap();

        let request = HttpRequestToSign {
            method: "POST".to_owned(),
            path_and_query: "/path?query=1".to_owned(),
            authorization: "XBL3.0 x=userid;jsonwebtoken".to_owned(),
            body: b"thebodygoeshere".to_vec(),
        };

        let signature = signer
            .sign_raw(
                1,
                dt,
                request.method.to_owned(),
                request.path_and_query.to_owned(),
                request.authorization.to_owned(),
                &request.body,
            )
            .expect("Signing failed!");

        signer
            .verify(signature, &request)
            .expect("Verification failed")
    }

    #[test]
    fn data_to_hash() {
        let signer = get_request_signer();
        let signing_policy_version: i32 = 1;
        let ts_bytes = FileTime::from(Utc.timestamp_opt(1586999965, 0).unwrap()).filetime().to_be_bytes();

        let message_data = signer
            .assemble_message_data(
                &signing_policy_version.to_be_bytes(),
                &ts_bytes,
                "POST".to_owned(),
                "/path?query=1".to_owned(),
                "XBL3.0 x=userid;jsonwebtoken".to_owned(),
                "thebodygoeshere".as_bytes(),
                8192,
            )
            .expect("Failed to assemble message data");

        assert_eq!(
            message_data,
            hex!("000000010001d6138d10f7cc8000504f5354002f706174683f71756572793d310058424c332e3020783d7573657269643b6a736f6e776562746f6b656e00746865626f6479676f65736865726500").to_vec()
        );
    }

    #[test]
    fn sign_reqwest() {
        let signer = get_request_signer();
        let timestamp = Utc.timestamp_opt(1586999965, 0).unwrap();

        let client = reqwest::Client::new();
        let mut request = client
            .post("https://example.com/path")
            .query(&[("query", 1)])
            .header(
                reqwest::header::AUTHORIZATION,
                "XBL3.0 x=userid;jsonwebtoken",
            )
            .body("thebodygoeshere")
            .build()
            .unwrap();

        request = signer
            .sign_request(request, Some(timestamp))
            .expect("FAILED signing request");

        let signature = request.headers().get("Signature");

        assert!(signature.is_some());
        assert!(signer.verify_request(request).is_ok());
    }

    #[test]
    fn verify_real_request() {
        let pem_priv_key = r#"-----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYhW3PQAibijp6X71
        Uua4a45KoHHpQZaUIef+gPeWOu2hRANCAAQYlLUACGI9jDRlJAkMIXyRxmQoBza1
        FZcA3pjD6j+ExFAECR1HP8lSIVEICL6BA95LdCQ8/xvI4F8rP10drPl3
            -----END PRIVATE KEY-----"#;

        let signer = RequestSigner {
            keypair: josekit::jws::ES256.key_pair_from_pem(pem_priv_key).unwrap(),
            signing_policy: Default::default(),
        };

        let request = HttpRequestToSign {
            method: "POST".to_owned(),
            path_and_query: "/device/authenticate".to_owned(),
            authorization: "".to_owned(),
            body: br#"{"RelyingParty":"http://auth.xboxlive.com","TokenType":"JWT","Properties":{"AuthMethod":"ProofOfPossession","Id":"{e51d4344-196a-4550-9e27-f6c5006a9949}","DeviceType":"Android","Version":"8.0.0","ProofKey":{"kty":"EC","alg":"ES256","crv":"P-256","x":"GJS1AAhiPYw0ZSQJDCF8kcZkKAc2tRWXAN6Yw-o_hMQ","y":"UAQJHUc_yVIhUQgIvoED3kt0JDz_G8jgXys_XR2s-Xc","use":"sig"}}}"#.to_vec(),
        };
        let signature = XboxWebSignatureBytes::from_str("AAAAAQHY4xgs5DyIujFG5E5MZ4D1xjd9Up+H4AKLoyBHd95MAUZcabUN//Y/gijed4vvKtlfp4Cd4dJzVhpK0m+sYZcYRqQjBEKAZw==")
            .expect("Failed to deserialize into XboxWebSignatureBytes");

        assert!(signer.verify(signature, &request).is_ok());
    }

    #[test]
    fn build_signed_get_request() {
        let signer = get_request_signer();
        let request = Client::new()
            .get("https://example.com")
            .sign(&signer, None)
            .expect("Failed to sign HTTP GET request")
            .build();

        assert!(request.is_ok());
    }

    #[test]
    fn build_signed_post_request() {
        let signer = get_request_signer();
        let request = Client::new()
            .post("https://example.com")
            .body(Body::from(b"somedata".to_vec()))
            .sign(&signer, None)
            .expect("Failed to sign HTTP POST request")
            .build();

        assert!(request.is_ok());
    }
}
