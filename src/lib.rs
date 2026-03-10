use anyhow::{Context, Result};
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

const ALPN_ASTRALANE_TPU: &[u8] = b"astralane-tpu";

pub const MAX_TRANSACTION_SIZE: usize = 1232;

pub mod error_code {
    pub const OK: u32 = 0;
    pub const UNKNOWN_API_KEY: u32 = 1;
    pub const CONNECTION_LIMIT: u32 = 2;

    pub fn describe(code: u32) -> &'static str {
        match code {
            OK => "OK",
            UNKNOWN_API_KEY => "Unknown API key",
            CONNECTION_LIMIT => "Connection limit exceeded",
            _ => "Unknown error",
        }
    }
}

pub struct AstralaneQuicClient {
    endpoint: Endpoint,
    connection: Mutex<Connection>,
    server_addr: SocketAddr,
    #[allow(dead_code)]
    api_key: String,
}

impl AstralaneQuicClient {
    pub async fn connect(server_addr: &str, api_key: &str) -> Result<Self> {
        let addr = SocketAddr::from_str(server_addr)
            .or_else(|_| {
                use std::net::ToSocketAddrs;
                server_addr
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .ok_or_else(|| anyhow::anyhow!("Cannot resolve address: {}", server_addr))
            })
            .context("Invalid server address")?;

        let client_config = Self::build_client_config(api_key)?;

        let mut endpoint =
            Endpoint::client("0.0.0.0:0".parse()?).context("Failed to create QUIC endpoint")?;
        endpoint.set_default_client_config(client_config);

        info!("[astralane-quic] Connecting to {} ...", addr);
        let connection = endpoint
            .connect(addr, "astralane")?
            .await
            .context("Failed to connect to Astralane QUIC server")?;

        info!(
            "[astralane-quic] Connected to Astralane QUIC server at {}",
            addr
        );

        Ok(Self {
            endpoint,
            connection: Mutex::new(connection),
            server_addr: addr,
            api_key: api_key.to_string(),
        })
    }

    pub async fn send_transaction(&self, transaction_bytes: &[u8]) -> Result<()> {
        if transaction_bytes.len() > MAX_TRANSACTION_SIZE {
            anyhow::bail!(
                "Transaction too large: {} bytes (max {})",
                transaction_bytes.len(),
                MAX_TRANSACTION_SIZE
            );
        }

        let conn = {
            let mut guard = self.connection.lock().await;
            if let Some(reason) = guard.close_reason() {
                if let quinn::ConnectionError::ApplicationClosed(ref info) = reason {
                    let code = info.error_code.into_inner();
                    if code != error_code::OK as u64 {
                        anyhow::bail!(
                            "Server closed connection: {} (code {})",
                            error_code::describe(code as u32),
                            code
                        );
                    }
                }
                warn!(
                    "[astralane-quic] Connection dead, reconnecting to {} ...",
                    self.server_addr
                );
                *guard = self
                    .endpoint
                    .connect(self.server_addr, "astralane")?
                    .await
                    .context("Failed to reconnect to Astralane QUIC server")?;
                info!("[astralane-quic] Reconnected to {}", self.server_addr);
            }
            guard.clone()
        };

        let mut send_stream = conn
            .open_uni()
            .await
            .context("Failed to open unidirectional stream")?;

        send_stream
            .write_all(transaction_bytes)
            .await
            .context("Failed to write transaction data")?;

        send_stream
            .finish()
            .await
            .context("Failed to finish stream")?;

        Ok(())
    }

    pub async fn reconnect(&self) -> Result<()> {
        let mut guard = self.connection.lock().await;
        if guard.close_reason().is_some() {
            *guard = self
                .endpoint
                .connect(self.server_addr, "astralane")?
                .await
                .context("Failed to reconnect to Astralane QUIC server")?;
        }
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        self.connection.lock().await.close_reason().is_none()
    }

    pub async fn close(&self) {
        self.connection
            .lock()
            .await
            .close(error_code::OK.into(), b"client closing");
    }

    fn build_client_config(api_key: &str) -> Result<ClientConfig> {
        let mut cert_params = rcgen::CertificateParams::default();
        cert_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String(api_key.to_string()),
        );
        let cert = rcgen::Certificate::from_params(cert_params)
            .context("Failed to generate self-signed certificate")?;

        let cert_der = rustls::Certificate(cert.serialize_der()?);
        let key_der = rustls::PrivateKey(cert.serialize_private_key_der());

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_client_auth_cert(vec![cert_der], key_der)
            .context("Failed to set client certificate")?;

        crypto.alpn_protocols = vec![ALPN_ASTRALANE_TPU.to_vec()];

        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(25)));

        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }
}

impl Drop for AstralaneQuicClient {
    fn drop(&mut self) {
        self.connection
            .get_mut()
            .close(error_code::OK.into(), b"client closing");
    }
}

struct SkipServerVerification;

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
