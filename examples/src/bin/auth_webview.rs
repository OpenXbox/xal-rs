// Copyright 2020-2022 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use async_trait::async_trait;
use tokio::sync::mpsc::channel;
use wry::{
    application::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoopBuilder},
        platform::run_return::EventLoopExtRunReturn,
        window::WindowBuilder,
    },
    webview::WebViewBuilder,
};
use xal::{
    url::Url, AccessTokenPrefix, AuthPromptCallback, AuthPromptData, Error, XalAuthenticator,
};
use xal_examples::auth_main_default;

#[derive(Debug)]
enum UserEvent {
    Exit,
}

struct WebviewCallbackHandler {
    redirect_url_schema: String,
}

#[async_trait]
impl AuthPromptCallback for WebviewCallbackHandler {
    async fn call(
        &self,
        cb_data: AuthPromptData,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let authentication_url = cb_data.authentication_url();
        let does_expect_url = cb_data.expect_url();

        let redirect_url_schema = self.redirect_url_schema.clone();

        let mut event_loop = EventLoopBuilder::with_user_event().build();
        let event_proxy = event_loop.create_proxy();
        let window = WindowBuilder::new()
            .with_title("XAL Webview")
            .build(&event_loop)
            .unwrap();

        let (sender, mut receiver) = channel::<Url>(1);

        let _webview = WebViewBuilder::new(window)?
            // tell the webview to load the custom protocol
            .with_navigation_handler(move |url| {
                if does_expect_url {
                    // Callback wants a redirect URL (with either authorization code or implicit tokens)
                    let parsed_url = Url::parse(&url).expect("Failed to parse navigation URL");
                    if parsed_url.scheme() == redirect_url_schema {
                        sender
                            .try_send(parsed_url)
                            .expect("Failed to send redirect URL over channel");

                        event_proxy.send_event(UserEvent::Exit).unwrap();
                        return false;
                    }
                }

                true
            })
            .with_url(authentication_url.as_str())?
            .build()?;

        let _ = event_loop.run_return(|event, _, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                }
                | Event::UserEvent(_) => {
                    *control_flow = ControlFlow::Exit;
                }
                _ => {}
            }
        });

        let retval = {
            if does_expect_url {
                Some(receiver.try_recv()?)
            } else {
                None
            }
        };

        Ok(retval)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let authenticator = XalAuthenticator::default();

    let callback_handler = WebviewCallbackHandler {
        redirect_url_schema: authenticator
            .get_redirect_uri()
            .ok_or(Error::GeneralError(
                "Failure! Authenticator not configured with redirect URL".to_string(),
            ))?
            .scheme()
            .to_owned(),
    };

    auth_main_default(AccessTokenPrefix::None, callback_handler)
        .await?;

    Ok(())
}
