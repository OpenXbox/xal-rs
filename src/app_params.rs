use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Copy, Clone)]
pub enum DeviceType {
    IOS,
    ANDROID,
    WIN32,
}

impl FromStr for DeviceType {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let enm = match s.to_lowercase().as_ref() {
            "android" => DeviceType::ANDROID,
            "ios" => DeviceType::IOS,
            "win32" => DeviceType::WIN32,
            val => {
                return Err(format!("Unhandled device type: '{}'", val).into());
            }
        };
        Ok(enm)
    }
}

impl ToString for DeviceType {
    fn to_string(&self) -> String {
        let str = match self {
            DeviceType::ANDROID => "Android",
            DeviceType::IOS => "iOS",
            DeviceType::WIN32 => "Win32",
        };
        str.to_owned()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XalAppParameters {
    pub app_id: String,
    pub title_id: String,
    pub redirect_uri: String,
}

impl XalAppParameters {
    pub fn xbox_app_beta() -> Self {
        Self {
            app_id: "000000004415494b".into(),
            title_id: "177887386".into(),
            redirect_uri: "ms-xal-000000004415494b://auth".into(),
        }
    }

    pub fn xbox_app() -> Self {
        Self {
            app_id: "000000004c12ae6f".into(),
            title_id: "328178078".into(),
            redirect_uri: "ms-xal-000000004c12ae6f://auth".into(),
        }
    }

    pub fn gamepass() -> Self {
        Self {
            app_id: "000000004c20a908".into(),
            title_id: "1016898439".into(),
            redirect_uri: "ms-xal-000000004c20a908://auth".into(),
        }
    }

    pub fn gamepass_beta() -> Self {
        Self {
            app_id: "000000004c20a908".into(),
            title_id: "1016898439".into(),
            redirect_uri: "ms-xal-public-beta-000000004c20a908://auth".into(),
        }
    }

    /// Family settings is somewhat special
    /// Uses default oauth20_desktop.srf redirect uri
    pub fn family_settings() -> Self {
        Self {
            app_id: "00000000482C8F49".into(),
            title_id: "1618633878".into(),
            redirect_uri: "https://login.live.com/oauth20_desktop.srf".into(),
        }
    }
}

impl Default for XalAppParameters {
    fn default() -> Self {
        Self::gamepass_beta()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XalClientParameters {
    pub user_agent: String,
    pub device_type: DeviceType,
    pub client_version: String,
    pub query_display: String,
}

impl XalClientParameters {
    pub fn ios() -> Self {
        Self {
            user_agent: "XAL iOS 2021.11.20211021.000".into(),
            device_type: DeviceType::IOS,
            client_version: "15.6.1".into(),
            query_display: "ios_phone".into(),
        }
    }

    pub fn android() -> Self {
        Self {
            user_agent: "XAL Android 2020.07.20200714.000".into(),
            device_type: DeviceType::ANDROID,
            client_version: "8.0.0".into(),
            query_display: "android_phone".into(),
        }
    }
}

impl Default for XalClientParameters {
    fn default() -> Self {
        Self::android()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devicetype_enum_into() {
        assert_eq!(DeviceType::WIN32.to_string(), "Win32");
        assert_eq!(DeviceType::ANDROID.to_string(), "Android");
        assert_eq!(DeviceType::IOS.to_string(), "iOS");
    }

    #[test]
    fn str_into_devicetype_enum() {
        assert_eq!(DeviceType::from_str("win32").unwrap(), DeviceType::WIN32);
        assert_eq!(DeviceType::from_str("Win32").unwrap(), DeviceType::WIN32);
        assert_eq!(DeviceType::from_str("WIN32").unwrap(), DeviceType::WIN32);
        assert_eq!(
            DeviceType::from_str("android").unwrap(),
            DeviceType::ANDROID
        );
        assert_eq!(DeviceType::from_str("ios").unwrap(), DeviceType::IOS);
        assert!(DeviceType::from_str("androidx").is_err());
    }
}
