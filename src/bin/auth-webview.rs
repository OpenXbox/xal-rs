// Copyright 2020-2022 Tauri Programme within The Commons Conservancy
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

use chrono::Utc;
use tauri::async_runtime;
use wry::{
    application::{
        event::{Event, StartCause, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    },
    webview::{Url, WebViewBuilder},
};
use xal::oauth2::PkceCodeVerifier;
use xal::{authenticator::XalAuthenticator, utils::TokenStore};

const TOKENS_FILEPATH: &str = "tokens.json";

async fn continue_auth(
    xal: &mut XalAuthenticator,
    code_verifier: &PkceCodeVerifier,
    authorization_code: &str,
    sisu_session_id: &str,
    device_token: &str,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("Authorization Code: {}", &authorization_code);
    let local_code_verifier = PkceCodeVerifier::new(code_verifier.secret().clone());
    let wl_token = xal
        .exchange_code_for_token(authorization_code, local_code_verifier)
        .await
        .expect("Failed exchanging code for token");
    let wl_token_clone = wl_token.clone();
    println!("WL={:?}", wl_token);

    let auth_response = xal
        .do_sisu_authorization(
            sisu_session_id,
            wl_token.access_token.secret(),
            device_token,
        )
        .await?;
    println!("SISU={:?}", auth_response);

    // Fetch GSSV (gamestreaming) token
    let gssv_token = xal
        .do_xsts_authorization(
            &auth_response.device_token,
            &auth_response.title_token.token_data.token,
            &auth_response.user_token.token_data.token,
            "http://gssv.xboxlive.com/",
        )
        .await?;
    println!("GSSV={:?}", gssv_token);

    // Fetch XCloud transfer token
    let transfer_token = xal
        .exchange_refresh_token_for_xcloud_transfer_token(
            &wl_token
                .refresh_token
                .expect("Failed to unwrap refresh token"),
        )
        .await?;
    println!("Transfer token={:?}", transfer_token);

    let ts = TokenStore {
        app_params: xal.app_params(),
        client_params: xal.client_params(),
        wl_token: wl_token_clone,
        sisu_tokens: auth_response,
        gssv_token,
        xcloud_transfer_token: transfer_token,
        updated: Utc::now(),
    };
    ts.save(TOKENS_FILEPATH)
}

enum UserEvent {
    Navigation(String),
}

fn main() -> wry::Result<()> {
    let mut xal = XalAuthenticator::default();

    if let Ok(mut ts) = TokenStore::load(TOKENS_FILEPATH) {
        let refreshed_xcoud = async_runtime::block_on(
            xal.exchange_refresh_token_for_xcloud_transfer_token(&ts.xcloud_transfer_token.into()),
        )
        .expect("Failed to exchange refresh token for fresh XCloud transfer token");

        println!("{:?}", refreshed_xcoud);
        ts.xcloud_transfer_token = refreshed_xcoud;
        ts.updated = Utc::now();
        ts.save(TOKENS_FILEPATH)
            .expect("Failed to save refreshed XCloud token");

        return Ok(());
    }

    let (code_challenge, code_verifier) = XalAuthenticator::get_code_challenge();
    let device_token =
        async_runtime::block_on(xal.get_device_token()).expect("Failed to fetch device token");

    println!("Device token={:?}", device_token);

    let state = XalAuthenticator::generate_random_state();

    let (sisu_response, sisu_session_id) = async_runtime::block_on(xal.do_sisu_authentication(
        &device_token.token_data.token,
        code_challenge,
        &state,
    ))
    .unwrap();

    let redirect_uri = xal.get_redirect_uri();
    let auth_url = sisu_response.msa_oauth_redirect;

    let event_loop: EventLoop<UserEvent> = EventLoop::with_user_event();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("Hello World")
        .build(&event_loop)
        .unwrap();

    let webview = WebViewBuilder::new(window)
        .unwrap()
        // tell the webview to load the custom protocol
        .with_url(&auth_url)?
        .with_devtools(true)
        .with_navigation_handler(move |uri: String| {
            proxy.send_event(UserEvent::Navigation(uri)).is_ok()
        })
        .build()?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => println!("Wry application started!"),
            Event::WindowEvent {
                event: WindowEvent::Moved { .. },
                ..
            } => {
                let _ = webview.evaluate_script("console.log('hello');");
            }
            Event::UserEvent(UserEvent::Navigation(uri)) => {
                if uri.starts_with(redirect_uri.scheme()) {
                    let url = Url::parse(&uri).expect("Failed to parse redirect URL");

                    let mut code_query: Option<String> = None;
                    let mut state_query: Option<String> = None;

                    for i in url.query_pairs() {
                        if i.0 == "code" {
                            code_query = Some(i.1.into_owned())
                        } else if i.0 == "state" {
                            state_query = Some(i.1.into_owned())
                        }
                    }

                    if let Some(returned_state) = &state_query {
                        let valid_state = &state == returned_state;
                        println!(
                            "State valid: {} ({} vs. {})",
                            valid_state, state, returned_state
                        );
                    } else {
                        println!("WARN: No state query returned!");
                    }

                    if let Some(authorization_code) = code_query {
                        match async_runtime::block_on(continue_auth(
                            &mut xal,
                            &code_verifier,
                            &authorization_code,
                            &sisu_session_id,
                            &device_token.token_data.token,
                        )) {
                            Ok(_) => {
                                println!("SISU authentication succeeded! :)");
                            }
                            Err(err) => {
                                println!("Failed SISU auth :( - details: {}", err);
                            }
                        }
                    } else {
                        println!("No authorization code fetched :(");
                    }

                    *control_flow = ControlFlow::Exit;
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => (),
        }
    });
}
