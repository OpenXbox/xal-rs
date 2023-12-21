use std::str::from_utf8;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use xal::{
    client_params::CLIENT_ANDROID,
    oauth2::{RedirectUrl, Scope},
    url::Url,
    AuthPromptCallback, AuthPromptData, Error, XalAppParameters,
};
use xal_examples::auth_main;

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
        println!("HTTP Server listening, waiting for connection...");

        let (mut socket, addr) = listener.accept().await?;
        println!("Connection received from {addr:?}");

        let mut buf = [0u8; 1024];

        if socket.read(&mut buf).await? == 0 {
            return Err("Failed reading http request".into());
        }

        socket.write_all(b"HTTP/1.1 200 OK\n\r\n\r").await?;

        let http_req = from_utf8(&buf)?;
        println!("HTTP REQ: {http_req}");

        let path = http_req.split(' ').nth(1).unwrap();
        println!("Path: {path}");

        Ok(Some(Url::parse(&format!(
            "{}{}",
            self.redirect_url_base, path
        ))?))
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    eprintln!("NOTE: --flow authorization-code required!");
    auth_main(
        XalAppParameters {
            app_id: "388ea51c-0b25-4029-aae2-17df49d23905".into(),
            title_id: None,
            auth_scopes: vec![
                Scope::new("Xboxlive.signin".into()),
                Scope::new("Xboxlive.offline_access".into()),
            ],
            redirect_uri: Some(
                RedirectUrl::new("http://localhost:8080/auth/callback".into()).unwrap(),
            ),
        },
        CLIENT_ANDROID(),
        "RETAIL".into(),
        xal::AccessTokenPrefix::D,
        HttpCallbackHandler {
            bind_host: "127.0.0.1:8080".into(),
            redirect_url_base: "http://localhost:8080".into(),
        },
    )
    .await?;

    Ok(())
}
