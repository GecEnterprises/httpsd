use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{
        header::{self, HeaderMap, HeaderValue},
        Request, Response, StatusCode, Uri,
    },
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rcgen::{
    date_time_ymd, CertificateParams, DistinguishedName, DnType, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};

const CERT_FILE: &str = "cert.pem";
const KEY_FILE: &str = "key.pem";
const FINGERPRINT_FILE: &str = "fingerprint.txt";
const BIND_ADDR: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

struct ProxyState {
    client: Client<HttpConnector, Body>,
    upstream_port: u16,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        log_error("httpsd", &format!("{err:#}"));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let (upstream_port, listen_port) = parse_args()?;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_dir = cert_dir()?;
    let cert_path = cert_dir.join(CERT_FILE);
    let key_path = cert_dir.join(KEY_FILE);
    let fingerprint_path = cert_dir.join(FINGERPRINT_FILE);

    if !cert_exists(&cert_dir) {
        generate_cert(&cert_dir)?;
        log(
            "tls",
            &format!(
                "generated self-signed certificate in {}",
                cert_dir.display()
            ),
        );
    } else {
        log(
            "tls",
            &format!("using certificate in {}", cert_dir.display()),
        );
    }

    let fingerprint = std::fs::read_to_string(&fingerprint_path)
        .context("read certificate fingerprint")
        .map(|raw| raw.trim().to_string())?;
    log(
        "tls",
        &format!("sha256 fingerprint {}", format_fingerprint(&fingerprint)),
    );

    let tls = RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .with_context(|| {
            format!(
                "load tls certificate from {} and {}",
                cert_path.display(),
                key_path.display()
            )
        })?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let client = Client::builder(TokioExecutor::new()).build::<_, Body>(connector);

    let state = Arc::new(ProxyState {
        client,
        upstream_port,
    });

    let app = Router::new().fallback(proxy_handler).with_state(state);

    let listener = std::net::TcpListener::bind(SocketAddr::from((BIND_ADDR, listen_port)))
        .with_context(|| format!("bind https on 0.0.0.0:{listen_port}"))?;
    listener
        .set_nonblocking(true)
        .context("make listener nonblocking")?;

    log(
        "httpsd",
        &format!("listening on https://0.0.0.0:{listen_port} -> http://127.0.0.1:{upstream_port}"),
    );

    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            log("httpsd", "shutting down");
            shutdown.graceful_shutdown(Some(Duration::from_secs(5)));
        }
    });

    axum_server::from_tcp_rustls(listener, tls)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("https server error")
}

fn parse_args() -> Result<(u16, u16)> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let second = args.next();
    let extra = args.next();

    if first.as_deref() == Some("-h") || first.as_deref() == Some("--help") {
        print_usage();
        std::process::exit(0);
    }

    let (Some(first), Some(second)) = (first, second) else {
        print_usage();
        std::process::exit(2);
    };
    if extra.is_some() {
        return Err(anyhow!("too many arguments; run `httpsd --help`"));
    }

    let upstream = first
        .parse::<u16>()
        .with_context(|| format!("invalid server port: {first}"))?;
    let listen = second
        .parse::<u16>()
        .with_context(|| format!("invalid listen port: {second}"))?;

    if upstream == 0 || listen == 0 {
        return Err(anyhow!("ports must be between 1 and 65535"));
    }
    if upstream == listen {
        return Err(anyhow!("server port and listen port must differ"));
    }

    Ok((upstream, listen))
}

fn print_usage() {
    eprintln!("usage: httpsd <server-port> <listen-port>");
    eprintln!();
    eprintln!("  server-port   http server on 127.0.0.1 to proxy to");
    eprintln!("  listen-port   port to serve https on, on every interface");
    eprintln!();
    eprintln!("example: httpsd 8000 8443");
}

fn cert_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("HTTPSD_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::config_dir().ok_or_else(|| anyhow!("could not find config directory"))?;
    Ok(base.join("httpsd"))
}

fn cert_exists(dir: &Path) -> bool {
    [CERT_FILE, KEY_FILE, FINGERPRINT_FILE]
        .iter()
        .all(|name| dir.join(name).exists())
}

fn generate_cert(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "httpsd".to_string());

    let mut alt_names = vec!["localhost".to_string(), hostname.clone()];
    alt_names.sort();
    alt_names.dedup();

    let mut params = CertificateParams::new(alt_names)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2039, 1, 1);
    for ip in local_ipv4_addrs() {
        params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(ip)));
    }

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    let fingerprint = fingerprint_sha256(cert.der().as_ref());

    std::fs::write(dir.join(CERT_FILE), cert.pem()).context("write certificate")?;
    std::fs::write(dir.join(KEY_FILE), key_pair.serialize_pem()).context("write key")?;
    std::fs::write(dir.join(FINGERPRINT_FILE), fingerprint).context("write fingerprint")?;
    Ok(())
}

fn local_ipv4_addrs() -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if let IpAddr::V4(ip) = iface.addr.ip() {
                if !ip.is_unspecified() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    if !ips.contains(&Ipv4Addr::LOCALHOST) {
        ips.push(Ipv4Addr::LOCALHOST);
    }
    ips
}

fn fingerprint_sha256(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn format_fingerprint(raw: &str) -> String {
    raw.as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect::<Vec<_>>()
        .join(":")
}

async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
) -> Response<Body> {
    let method = request.method().as_str().to_ascii_lowercase();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let original_host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    let upgrading = wants_upgrade(request.headers());
    let client_upgrade = if upgrading {
        Some(hyper::upgrade::on(&mut request))
    } else {
        None
    };

    let uri = match format!("http://127.0.0.1:{}{}", state.upstream_port, path).parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => {
            log_access(peer, StatusCode::BAD_REQUEST, &method, &path, "-");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // The client connector sets Host from the URI, but the upstream often
    // cares about the exact authority it was addressed with.
    if let Ok(host) = HeaderValue::from_str(&format!("127.0.0.1:{}", state.upstream_port)) {
        request.headers_mut().insert(header::HOST, host);
    }
    request
        .headers_mut()
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Some(host) = original_host {
        if let Ok(value) = HeaderValue::from_str(&host) {
            request.headers_mut().insert("x-forwarded-host", value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&peer.ip().to_string()) {
        request.headers_mut().insert("x-forwarded-for", value);
    }
    strip_hop_headers(request.headers_mut(), upgrading);
    *request.uri_mut() = uri;
    *request.version_mut() = axum::http::Version::HTTP_11;

    let result = state.client.request(request).await;
    let response = match result {
        Ok(response) => response,
        Err(err) => {
            log_access(peer, StatusCode::BAD_GATEWAY, &method, &path, "-");
            log_error(
                "proxy",
                &format!("upstream request failed for {path}: {err}"),
            );
            return (
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {err}"),
            )
                .into_response();
        }
    };

    let status = response.status();
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let (mut parts, body) = response.into_parts();
    strip_hop_headers(
        &mut parts.headers,
        status == StatusCode::SWITCHING_PROTOCOLS,
    );
    let mut response = Response::from_parts(parts, Body::new(body));

    if status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            if response.headers().get(header::UPGRADE).is_some() {
                let server_upgrade = hyper::upgrade::on(&mut response);
                tokio::spawn(pipe_upgrade(client_upgrade, server_upgrade));
            }
        }
    }

    log_access(
        peer,
        status,
        &method,
        &path,
        content_length.as_deref().unwrap_or("-"),
    );
    response
}

fn wants_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

fn strip_hop_headers(headers: &mut HeaderMap, keep_upgrade: bool) {
    headers.remove("keep-alive");
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::TRANSFER_ENCODING);
    if !keep_upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
}

async fn pipe_upgrade(
    client_upgrade: hyper::upgrade::OnUpgrade,
    server_upgrade: hyper::upgrade::OnUpgrade,
) {
    match tokio::try_join!(client_upgrade, server_upgrade) {
        Ok((client, server)) => {
            let mut client = TokioIo::new(client);
            let mut server = TokioIo::new(server);
            if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
                if !is_normal_close(&err) {
                    log_error("proxy", &format!("upgraded connection failed: {err}"));
                }
            }
        }
        Err(err) => log_error("proxy", &format!("connection upgrade failed: {err}")),
    }
}

fn is_normal_close(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    ) || err.to_string().contains("close_notify")
}

use axum::response::IntoResponse;

fn log(src: &str, msg: &str) {
    let ts = chrono::Local::now().format("%H:%M:%S");
    println!("\x1b[36m{ts}\x1b[0m \x1b[33m{src:<26}\x1b[0m {msg}");
}

fn log_error(src: &str, msg: &str) {
    let ts = chrono::Local::now().format("%H:%M:%S");
    println!("\x1b[36m{ts}\x1b[0m \x1b[33m{src:<26}\x1b[0m \x1b[31m{msg}\x1b[0m");
}

fn log_access(peer: SocketAddr, status: StatusCode, method: &str, path: &str, bytes: &str) {
    let color = match status.as_u16() {
        100..=199 => 36,
        200..=299 => 32,
        300..=399 => 36,
        400..=499 => 33,
        _ => 31,
    };
    let src = format!("{} {}", peer.ip(), peer.port());
    log(
        &src,
        &format!(
            "{method} {path} \x1b[{color}m{}\x1b[0m {bytes}",
            status.as_u16()
        ),
    );
}
