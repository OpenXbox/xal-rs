#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
//! XAL - Xbox Live Authentication Library for Rust
//!
//! Features:
//! - OAuth2 Authentication via SISU App-Flow - see [`crate::XalAuthenticator`]
//! - HTTP Request Signing - see [`crate::RequestSigner`]
//! - Extensions for Reqwest HTTP client library - see [`crate::extensions`]
//!
//! # Examples
//!
//! For advanced usage, see [`crate::XalAuthenticator`].

pub use cvlib;
pub use oauth2;
pub use url;

mod authenticator;
mod error;
mod flows;
mod models;
mod request_signer;
mod tokenstore;

pub mod extensions;
pub use authenticator::*;
pub use error::Error;
pub use flows::*;
pub use models::*;
pub use request_signer::*;
pub use tokenstore::*;
