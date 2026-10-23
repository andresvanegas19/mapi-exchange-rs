// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Blocking HTTPS transport for the MAPI/HTTP EMSMDB endpoint.

use std::time::Duration;

use crate::emsmdb::{Framed, parse_framed};
use crate::error::{Error, Result};

/// Connection settings. Usually built with [`Config::from_env`].
#[derive(Clone)]
pub struct Config {
    /// Full EMSMDB URL, e.g. `https://<server>/mapi/emsmdb/?MailboxId=<mailbox-guid>@<domain>`.
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
    ///
    /// Exchange checks `X-ClientApplication` (MS-OXCMAPIHTTP 2.2.3.1.4): it must be
    /// `Name/major.minor.build.revision` with a version the server accepts. Otherwise Connect fails
    /// with `MissingHeader`, `MAPI_E_VERSION` or `ecClientVerDisallowed`. Set
    /// `MAPI_HTTP_CLIENT_APPLICATION` for real servers; the default is only a placeholder.
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
    client: reqwest::blocking::Client,
    config: Config,
    client_info: String,
    request_counter: u32,
}

impl Transport {
    pub fn new(config: Config) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .danger_accept_invalid_certs(config.insecure_tls)
            .build()
            .map_err(http_error)?;
        Ok(Self {
            client,
            client_info: format!("{{{}}}", new_guid()),
            config,
            request_counter: 0,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// POST one MAPI/HTTP request and return the framed response after checking X-ResponseCode.
    pub fn post(&mut self, request_type: &'static str, body: &[u8]) -> Result<Framed> {
        self.request_counter += 1;
        let request_id = format!("{}:{}", self.client_info, self.request_counter);
        let request = self
            .client
            .post(&self.config.url)
            .basic_auth(&self.config.user, Some(&self.config.password))
            .header("Content-Type", "application/mapi-http")
            .header("Accept", "application/mapi-http")
            .header("X-RequestType", request_type)
            .header("X-ClientInfo", format!("{}:1", self.client_info))
            .header("X-RequestId", request_id)
            .header("X-ClientApplication", &self.config.client_application);

        let response = request.body(body.to_vec()).send().map_err(http_error)?;
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let header_code = header("X-ResponseCode").and_then(|v| v.trim().parse::<u32>().ok());
        let status = response.status();
        if !status.is_success() {
            return Err(Error::HttpStatus {
                status: status.as_u16(),
                request_type,
                response_code: header_code,
                authenticate: header("WWW-Authenticate"),
            });
        }

        let description = header("X-FailureDescription");
        let bytes = response.bytes().map_err(http_error)?;
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
}

fn http_error(e: reqwest::Error) -> Error {
    Error::Http(e.to_string())
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

    fn local_config(url: String) -> Config {
        Config {
            url,
            user: "u".into(),
            password: "p".into(),
            user_dn: String::new(),
            client_application: "test/1".into(),
            insecure_tls: false,
            timeout: Duration::from_secs(10),
        }
    }

    /// Serves canned HTTP responses on a loopback port and returns each raw request.
    fn serve(responses: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mapi/emsmdb/", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    data.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&data).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if data.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8_lossy(&data).to_string());
                stream.write_all(&response).unwrap();
            }
            requests
        });
        (url, handle)
    }

    fn reply(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for h in headers {
            out.push_str(h);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        let mut out = out.into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn post_sends_headers_and_keeps_cookies() {
        let mut ok = b"PROCESSING\r\nDONE\r\nX-ElapsedTime: 1\r\n\r\n".to_vec();
        ok.extend_from_slice(&[0u8; 8]);
        ok.push(0xAB);
        let (url, server) = serve(vec![
            reply(
                "200 OK",
                &["X-ResponseCode: 0", "Set-Cookie: sid=abc; path=/"],
                &ok,
            ),
            reply("200 OK", &["X-ResponseCode: 0"], &ok),
        ]);
        let mut transport = Transport::new(local_config(url)).unwrap();
        let framed = transport.post("Connect", b"hello").unwrap();
        assert_eq!(framed.body.last(), Some(&0xAB));
        transport.post("Execute", b"again").unwrap();
        let requests = server.join().unwrap();
        let first = requests[0].to_ascii_lowercase();
        assert!(first.starts_with("post /mapi/emsmdb/ "));
        assert!(first.contains("x-requesttype: connect"));
        assert!(first.contains("content-type: application/mapi-http"));
        assert!(first.contains("x-clientapplication: test/1"));
        assert!(first.contains("authorization: basic dtpw"));
        assert!(first.ends_with("hello"));
        assert!(!first.contains("cookie: sid"));
        assert!(requests[1].to_ascii_lowercase().contains("cookie: sid=abc"));
    }

    #[test]
    fn post_maps_http_status_and_response_code() {
        let (url, server) = serve(vec![
            reply("401 Unauthorized", &["WWW-Authenticate: Basic"], b""),
            reply("200 OK", &["X-ResponseCode: 10"], b""),
        ]);
        let mut transport = Transport::new(local_config(url)).unwrap();
        match transport.post("Connect", b"") {
            Err(Error::HttpStatus {
                status: 401,
                authenticate: Some(a),
                ..
            }) => assert_eq!(a, "Basic"),
            other => panic!("unexpected {other:?}"),
        }
        match transport.post("Connect", b"") {
            Err(Error::ResponseCode { code: 10, .. }) => {}
            other => panic!("unexpected {other:?}"),
        }
        server.join().unwrap();
    }
}
