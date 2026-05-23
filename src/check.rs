use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use ::time::OffsetDateTime;
use chrono::{DateTime, TimeZone, Utc};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::error::TlsdaysError;

fn offset_to_utc(dt: OffsetDateTime) -> Result<DateTime<Utc>, String> {
    Utc.timestamp_opt(dt.unix_timestamp(), dt.nanosecond())
        .single()
        .ok_or_else(|| format!("invalid timestamp: {dt}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub host: String,
    pub port: u16,
    pub days_until_expiry: i64,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub subject_cn: String,
    pub issuer: String,
}

fn build_tls_connector() -> Result<TlsConnector, TlsdaysError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

fn parse_cert_der(host: &str, port: u16, der: &[u8]) -> Result<CertInfo, TlsdaysError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| TlsdaysError::CertParse {
        host: host.to_string(),
        port,
        message: e.to_string(),
    })?;

    let not_before =
        offset_to_utc(cert.validity().not_before.to_datetime()).map_err(|message| {
            TlsdaysError::CertParse {
                host: host.to_string(),
                port,
                message: format!("invalid not_before: {message}"),
            }
        })?;
    let not_after = offset_to_utc(cert.validity().not_after.to_datetime()).map_err(|message| {
        TlsdaysError::CertParse {
            host: host.to_string(),
            port,
            message: format!("invalid not_after: {message}"),
        }
    })?;
    let now = Utc::now();
    let seconds = (not_after - now).num_seconds();
    let days_until_expiry = seconds.div_euclid(86_400);

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .unwrap_or("")
        .to_string();

    let issuer = cert
        .issuer()
        .iter_common_name()
        .filter_map(|cn| cn.as_str().ok())
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| cert.issuer().to_string());

    Ok(CertInfo {
        host: host.to_string(),
        port,
        days_until_expiry,
        not_before,
        not_after,
        subject_cn,
        issuer,
    })
}

pub async fn check_host(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<CertInfo, TlsdaysError> {
    let host_owned = host.to_string();
    let addrs: Vec<_> = tokio::task::spawn_blocking(move || {
        (host_owned.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| TlsdaysError::Resolve {
                host: host_owned.clone(),
                source: e,
            })
            .map(|iter| iter.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| TlsdaysError::Argument(format!("resolve task failed: {e}")))??;

    if addrs.is_empty() {
        return Err(TlsdaysError::Resolve {
            host: host.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses resolved"),
        });
    }

    let connector = build_tls_connector()?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| TlsdaysError::Argument(format!("invalid DNS name for TLS SNI: {host}")))?;

    let mut last_tcp_err = None;
    for addr in addrs {
        let tcp = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                last_tcp_err = Some(e);
                continue;
            }
            Err(_) => {
                return Err(TlsdaysError::Tcp {
                    host: host.to_string(),
                    port,
                    source: std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "connection timed out",
                    ),
                });
            }
        };

        let tls = match timeout(connect_timeout, connector.connect(server_name.clone(), tcp)).await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(TlsdaysError::Tls {
                    host: host.to_string(),
                    port,
                    message: e.to_string(),
                });
            }
            Err(_) => {
                return Err(TlsdaysError::Tls {
                    host: host.to_string(),
                    port,
                    message: "tls handshake timed out".to_string(),
                });
            }
        };

        let (_, session) = tls.get_ref();
        let certs = session
            .peer_certificates()
            .ok_or_else(|| TlsdaysError::Tls {
                host: host.to_string(),
                port,
                message: "no peer certificates presented".to_string(),
            })?;

        let leaf = certs.first().ok_or_else(|| TlsdaysError::Tls {
            host: host.to_string(),
            port,
            message: "empty peer certificate chain".to_string(),
        })?;

        return parse_cert_der(host, port, leaf.as_ref());
    }

    Err(TlsdaysError::Tcp {
        host: host.to_string(),
        port,
        source: last_tcp_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "all resolved addresses failed",
            )
        }),
    })
}
