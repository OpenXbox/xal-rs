//! Download savegames for a specific title
//!
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use log::{info, warn, debug, trace};
use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};
use xal::client_params::CLIENT_WINDOWS;
use xal::cvlib::CorrelationVector;
use xal::oauth2::{RedirectUrl, Scope};
use xal::{
    AccessTokenPrefix, AuthPromptCallback, AuthPromptData, Error, RequestSigner, XalAppParameters
};
use xal::extensions::CorrelationVectorReqwestBuilder;
use xal::extensions::SigningReqwestBuilder;
use xal::extensions::JsonExDeserializeMiddleware;
use xal::extensions::LoggingReqwestRequestHandler;
use xal::extensions::LoggingReqwestResponseHandler;
use xal_examples::auth_main;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PagingInfo {
    pub total_items: usize,
    pub continuation_token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlobMetadata {
    pub file_name: String,
    pub display_name: Option<String>,
    pub etag: String,
    pub client_file_time: String,
    pub size: usize
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlobsResponse {
    pub blobs: Vec<BlobMetadata>,
    pub paging_info: PagingInfo,
}

#[derive(Deserialize, Debug)]
pub struct SavegameAtoms {
    pub atoms: HashMap<String,String>,
}

// Replace with your own Azure Client parameters
const CLIENT_ID: &'static str = "388ea51c-0b25-4029-aae2-17df49d23905";
const REDIRECT_URL: &'static str = "http://localhost:8080/auth/callback";
const CLIENT_SECRET: Option<&'static str> = None;

pub struct HttpCallbackHandler {
    bind_host: String,
    redirect_url_base: String,
}

#[async_trait]
impl AuthPromptCallback for HttpCallbackHandler {
    async fn call(
        &self,
        cb_data: AuthPromptData,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let prompt = cb_data.prompt();
        println!("{prompt}\n");

        let listener = TcpListener::bind(&self.bind_host).await?;
        debug!("HTTP Server listening, waiting for connection...");

        let (mut socket, addr) = listener.accept().await?;
        debug!("Connection received from {addr:?}");

        let mut buf = [0u8; 1024];

        if socket.read(&mut buf).await? == 0 {
            return Err("Failed reading http request".into());
        }

        socket.write_all(b"HTTP/1.1 200 OK\n\r\n\r").await?;

        let http_req = std::str::from_utf8(&buf)?;
        trace!("HTTP REQ: {http_req}");

        let path = http_req.split(' ').nth(1).unwrap();
        debug!("Path: {path}");

        Ok(Some(Url::parse(&format!(
            "{}{}",
            self.redirect_url_base, path
        ))?))
    }
}

pub fn assemble_filepath(root_path: &PathBuf, path: &str) -> PathBuf {
    let modified_path = path
        // Replace separator with platform-specific separator
        .replace("/", std::path::MAIN_SEPARATOR_STR)
        // Strip ,savedgame suffix
        .replace(",savedgame", "")
        .replace("X", ".")
        .replace("E", "-");

    root_path.join(modified_path)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    eprintln!("NOTE: --flow authorization-code required!");
    let ts = auth_main(
        XalAppParameters {
            client_id: CLIENT_ID.into(),
            title_id: None,
            auth_scopes: vec![
                Scope::new("Xboxlive.signin".into()),
                Scope::new("Xboxlive.offline_access".into()),
            ],
            redirect_uri: Some(RedirectUrl::new(REDIRECT_URL.into()).unwrap()),
            client_secret: CLIENT_SECRET.map(|x| x.to_string()),
        },
        CLIENT_WINDOWS(),
        "RETAIL".into(),
        AccessTokenPrefix::D,
        HttpCallbackHandler {
            bind_host: "127.0.0.1:8080".into(),
            redirect_url_base: "http://localhost:8080".into(),
        },
    )
    .await?;

    let xsts_token = ts
        .authorization_token
        .ok_or(Error::GeneralError("No XSTS token was acquired".into()))?;
    xsts_token.check_validity()?;

    let xuid = xsts_token
        .clone()
        .display_claims
        .ok_or(Error::GeneralError("No DisplayClaims".into()))?
        .xui
        .first()
        .ok_or(Error::GeneralError("No xui node".into()))?
        .get("xid")
        .ok_or(Error::GeneralError("No X(U)ID".into()))?
        .to_owned();

    // Create new instances of Correlation vector and request signer
    let mut cv = CorrelationVector::new();
    let mut signer = RequestSigner::new();

    let client = reqwest::Client::new();

    let pfn = "Microsoft.ProjectSpark-Dakota_8wekyb3d8bbwe";
    let scid = "d3d00100-7976-472f-a3f7-bc1760d19e14";

    let mut target_dir = PathBuf::new();
    target_dir.push(&pfn);
    target_dir.push(&xuid);

    if !target_dir.exists() {
        std::fs::create_dir_all(&target_dir)?;
    }

    let metadata = client
        .get(format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}"))
        .header("x-xbl-contract-version", "107")
        .header("x-xbl-pfn", pfn)
        .header("Accept-Language", "en-US")
        .header("Authorization", xsts_token.authorization_header_value())
        .add_cv(&mut cv)?
        .sign(&mut signer, None)
        .await?
        .log()
        .await?
        .send()
        .await?
        .log()
        .await?
        .json_ex::<BlobsResponse>()
        .await?;

    trace!("metadata: {metadata:?}");

    info!("Found {} blobs", metadata.blobs.len());
    for blob in metadata.blobs {
        info!("- Fetching {} ({} bytes)", &blob.file_name, blob.size);

        let filepath = assemble_filepath(&target_dir, &blob.file_name);

        let atoms = client
            .get(format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/{}", blob.file_name))
            .header("x-xbl-contract-version", "107")
            .header("x-xbl-pfn", pfn)
            .header("Accept-Language", "en-US")
            .header("Authorization", xsts_token.authorization_header_value())
            .add_cv(&mut cv)?
            .sign(&mut signer, None)
            .await?
            .log()
            .await?
            .send()
            .await?
            .log()
            .await?
            .json_ex::<SavegameAtoms>()
            .await?;

        trace!("{atoms:?}");

        debug!("* Found {} atoms", atoms.atoms.len());
        if let Some(atom_guid) = atoms.atoms.get("Data") {
            debug!("Fetching atom {atom_guid}");
            let filedata = client
                .get(format!("https://titlestorage.xboxlive.com/connectedstorage/users/xuid({xuid})/scids/{scid}/{atom_guid}"))
                .header("x-xbl-contract-version", "107")
                .header("x-xbl-pfn", pfn)
                .header("Accept-Language", "en-US")
                .header("Authorization", xsts_token.authorization_header_value())
                .add_cv(&mut cv)?
                .sign(&mut signer, None)
                .await?
                .log()
                .await?
                .send()
                .await?
                .log()
                .await?
                .bytes()
                .await?;

            if let Some(parent) = filepath.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(&parent)?;
                }
            }

            let mut filehandle = std::fs::File::create(filepath)?;
            filehandle.write_all(&filedata)?;
        } else {
            warn!("No atom with 'Data' found for blob {}", blob.file_name);
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn deserialize_blob_response() {
        let data =  r#"{"blobs":[{"fileName":"save_container,savedgame","displayName":"Save Data","etag":"\"0x8DCA185D3F40E2A\"","clientFileTime":"2024-07-11T08:45:22.5700000Z","size":6745}],"pagingInfo":{"totalItems":1,"continuationToken":null}}"#;
        let _: BlobsResponse = serde_json::from_str(data).expect("Failed to deserialize");
    }

    #[test]
    fn deserialize_savegame_atoms() {
        let data = r#"{"atoms":{"save_data":"296FB351-5F1E-4CCB-8B2B-533C23BC19EB,binary"}}"#;
        let _: SavegameAtoms = serde_json::from_str(data).expect("Failed to deserialize");
    }
}