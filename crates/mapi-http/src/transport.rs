// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Blocking HTTPS transport for the MAPI/HTTP EMSMDB endpoint.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use crate::emsmdb::{Framed, parse_framed};
use crate::error::{Error, Result};

/// Connection settings. Usually built with [`Config::from_env`].
#[derive(Clone)]
pub struct Config {
    /// Full EMSMDB URL, e.g. `https://host/mapi/emsmdb/?MailboxId=<guid>@<domain>`.
    pub url: String,
    pub user: String,
    pub password: String,
    /// Mailbox legacyExchangeDN used for Connect and RopLogon.
    pub user_dn: String,
    pub client_application: String,
    /// Accept untrusted TLS certificates (test environments only).
    pub insecure_tls: bool,
    pub timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("url", &self.url)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("user_dn", &self.user_dn)
            .field("client_application", &self.client_application)
            .field("insecure_tls", &self.insecure_tls)
            .finish()
    }
}

impl Config {
    /// Reads `MAPI_HTTP_MAPI_URL`, `MAPI_HTTP_USER`, `MAPI_HTTP_PASSWORD`, `MAPI_HTTP_USER_DN`,
    /// optional `MAPI_HTTP_CLIENT_APPLICATION` and `MAPI_HTTP_INSECURE_TLS=1`.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .map_err(|_| Error::Config(format!("environment variable {name} is not set")))
        };
        Ok(Self {
            url: var("MAPI_HTTP_MAPI_URL")?,
            user: var("MAPI_HTTP_USER")?,
            password: var("MAPI_HTTP_PASSWORD")?,
            user_dn: var("MAPI_HTTP_USER_DN")?,
            client_application: std::env::var("MAPI_HTTP_CLIENT_APPLICATION")
                .unwrap_or_else(|_| concat!("mapi-http-rs/", env!("CARGO_PKG_VERSION")).into()),
            insecure_tls: matches!(
                std::env::var("MAPI_HTTP_INSECURE_TLS").as_deref(),
                Ok("1") | Ok("true")
            ),
            timeout: Duration::from_secs(120),
        })
    }
}

pub struct Transport {
    agent: ureq::Agent,
    config: Config,
    authorization: String,
    client_info: String,
    request_counter: u32,
    cookies: BTreeMap<String, String>,
}

impl Transport {
    pub fn new(config: Config) -> Result<Self> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout(config.timeout)
            .redirects(0);
        if config.insecure_tls {
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()
                .map_err(|e| Error::Http(e.to_string()))?;
            builder = builder.tls_connector(Arc::new(connector));
        } else {
            let connector =
                native_tls::TlsConnector::new().map_err(|e| Error::Http(e.to_string()))?;
            builder = builder.tls_connector(Arc::new(connector));
        }
        let credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", config.user, config.password));
        Ok(Self {
            agent: builder.build(),
            authorization: format!("Basic {credentials}"),
            client_info: format!("{{{}}}", new_guid()),
            config,
            request_counter: 0,
            cookies: BTreeMap::new(),
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// POST one MAPI/HTTP request and return the framed response after checking X-ResponseCode.
    pub fn post(&mut self, request_type: &'static str, body: &[u8]) -> Result<Framed> {
        self.request_counter += 1;
        let request_id = format!("{}:{}", self.client_info, self.request_counter);
        let mut request = self
            .agent
            .post(&self.config.url)
            .set("Authorization", &self.authorization)
            .set("Content-Type", "application/mapi-http")
            .set("Accept", "application/mapi-http")
            .set("X-RequestType", request_type)
            .set("X-ClientInfo", &format!("{}:1", self.client_info))
            .set("X-RequestId", &request_id)
            .set("X-ClientApplication", &self.config.client_application);
        if !self.cookies.is_empty() {
            let cookie = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            request = request.set("Cookie", &cookie);
        }

        let response = match request.send_bytes(body) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                return Err(Error::HttpStatus {
                    status,
                    request_type,
                    response_code: response
                        .header("X-ResponseCode")
                        .and_then(|v| v.trim().parse().ok()),
                    authenticate: response.header("WWW-Authenticate").map(str::to_string),
                });
            }
            Err(e) => return Err(Error::Http(e.to_string())),
        };

        for set_cookie in response.all("Set-Cookie") {
            if let Some((name, value)) = set_cookie
                .split(';')
                .next()
                .and_then(|pair| pair.split_once('='))
            {
                self.cookies
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
        }

        let header_code = response
            .header("X-ResponseCode")
            .and_then(|v| v.trim().parse::<u32>().ok());
        let description = response.header("X-FailureDescription").map(str::to_string);
        let mut bytes = Vec::new();
        response.into_reader().read_to_end(&mut bytes)?;
        if let Some(code) = header_code.filter(|c| *c != 0) {
            return Err(Error::ResponseCode {
                request_type,
                code,
                name: crate::error::response_code_name(code),
                description,
            });
        }
        let framed = parse_framed(&bytes)?;
        framed.check(request_type)?;
        Ok(framed)
    }

    pub fn clear_cookies(&mut self) {
        self.cookies.clear();
    }
}

/// Random version-4 GUID string without braces (no extra crate dependency).
pub fn new_guid() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
        );
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    let h = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        h(0..4),
        h(4..6),
        h(6..8),
        h(8..10),
        h(10..16)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_shape() {
        let guid = new_guid();
        assert_eq!(guid.len(), 36);
        assert_eq!(&guid[14..15], "4");
        assert_ne!(guid, new_guid());
    }

    #[test]
    fn config_debug_redacts_password() {
        let config = Config {
            url: "https://x/mapi/emsmdb/".into(),
            user: "u".into(),
            password: "secret".into(),
            user_dn: String::new(),
            client_application: String::new(),
            insecure_tls: false,
            timeout: Duration::from_secs(1),
        };
        assert!(!format!("{config:?}").contains("secret"));
    }
}
