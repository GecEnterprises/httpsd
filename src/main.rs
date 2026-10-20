use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, State},
    http::{
        header::{self, HeaderMap, HeaderValue},
        Method, Request, Response, StatusCode, Uri,
    },
    response::IntoResponse,
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
const MAX_REWRITE_BODY: usize = 16 * 1024 * 1024;
const MAX_CACHE_BODY: usize = 8 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 128;
const CACHE_TTL: Duration = Duration::from_secs(300);

struct ProxyState {
    client: Client<HttpConnector, Body>,
    upstream_port: u16,
    listen_port: u16,
    cache: ResponseCache,
}

#[derive(Clone)]
struct CacheEntry {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    stored: Instant,
}

struct ResponseCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl ResponseCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<CacheEntry> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries.get(key)?;
        if entry.stored.elapsed() > CACHE_TTL {
            entries.remove(key);
            return None;
        }
        Some(entry.clone())
    }

    fn put(&self, key: String, entry: CacheEntry) {
        if entry.body.len() > MAX_CACHE_BODY {
            return;
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, cached| cached.stored.elapsed() <= CACHE_TTL);
        if entries.len() >= MAX_CACHE_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, cached)| cached.stored)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, entry);
    }

    fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
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
        listen_port,
        cache: ResponseCache::new(),
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
        .map(ToString::to_string)
        // HTTP/2 carries the authority in the request URI instead of Host.
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str().to_string())
        });
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);

    if request.method() == Method::OPTIONS {
        if let Some(origin) = cors_preflight(request.headers()) {
            let response = preflight_response(request.headers(), &origin);
            log_access(peer, response.status(), &method, &path, "-");
            return response;
        }
    }

    let public = public_origin(original_host.as_deref(), state.listen_port);
    let cache_key = cache_key(&public, origin.as_deref(), &path, request.headers());

    let upgrading = wants_upgrade(request.headers());
    if method == "get" && !upgrading {
        if let Some(entry) = state.cache.get(&cache_key) {
            let CacheEntry {
                status,
                headers,
                body,
                ..
            } = entry;
            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            log_access(peer, status, &method, &path, "-");
            return response;
        }
    }

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
    if let Some(host) = &original_host {
        if let Ok(value) = HeaderValue::from_str(host) {
            request.headers_mut().insert("x-forwarded-host", value);
        }
    }
    if let Ok(value) = HeaderValue::from_str(&peer.ip().to_string()) {
        request.headers_mut().insert("x-forwarded-for", value);
    }
    // Rewriting needs plain text; ask upstream not to compress it.
    request.headers_mut().insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
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
    let (mut parts, body) = response.into_parts();
    let body = Body::new(body);
    strip_hop_headers(
        &mut parts.headers,
        status == StatusCode::SWITCHING_PROTOCOLS,
    );

    if status != StatusCode::SWITCHING_PROTOCOLS {
        let rewrites = rewrite_map(original_host.as_deref(), state.upstream_port, &public);
        rewrite_header_values(&mut parts.headers, &rewrites);
        apply_cors(&mut parts.headers, origin.as_deref());

        let rewritable = method != "head"
            && status == StatusCode::OK
            && is_rewritable_text(&parts.headers)
            && !is_content_encoded(&parts.headers);

        let mut body = Some(body);
        let mut rewritten_body = None;
        if rewritable {
            let raw = body.take().expect("response body");
            match to_bytes(raw, MAX_REWRITE_BODY).await {
                Ok(bytes) => {
                    let original = bytes.to_vec();
                    let rewritten = rewrite_bytes(&original, &rewrites).unwrap_or(original);
                    parts.headers.remove(header::CONTENT_ENCODING);
                    parts.headers.remove(header::ETAG);
                    parts.headers.remove("content-md5");
                    parts.headers.remove(header::ACCEPT_RANGES);
                    if let Ok(value) = HeaderValue::from_str(&rewritten.len().to_string()) {
                        parts.headers.insert(header::CONTENT_LENGTH, value);
                    }
                    if is_cacheable(&parts.headers) {
                        state.cache.put(
                            cache_key.clone(),
                            CacheEntry {
                                status,
                                headers: parts.headers.clone(),
                                body: rewritten.clone(),
                                stored: Instant::now(),
                            },
                        );
                    }
                    rewritten_body = Some(rewritten);
                }
                Err(err) => {
                    log_access(peer, StatusCode::BAD_GATEWAY, &method, &path, "-");
                    log_error(
                        "proxy",
                        &format!("read rewritable response for {path}: {err}"),
                    );
                    return StatusCode::BAD_GATEWAY.into_response();
                }
            }
        }

        let body = match rewritten_body {
            Some(bytes) => Body::from(bytes),
            None => body.take().expect("response body"),
        };
        let response = Response::from_parts(parts, body);

        if method != "get" && method != "head" && status.is_success() {
            state.cache.clear();
        }

        let content_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        log_access(
            peer,
            status,
            &method,
            &path,
            content_length.as_deref().unwrap_or("-"),
        );
        return response;
    }

    let mut response = Response::from_parts(parts, body);
    if let Some(client_upgrade) = client_upgrade {
        if response.headers().get(header::UPGRADE).is_some() {
            let server_upgrade = hyper::upgrade::on(&mut response);
            tokio::spawn(pipe_upgrade(client_upgrade, server_upgrade));
        }
    }

    log_access(peer, status, &method, &path, "-");
    response
}

fn public_origin(original_host: Option<&str>, listen_port: u16) -> String {
    match original_host {
        Some(host) if !host.trim().is_empty() => format!("https://{host}"),
        _ => format!("https://localhost:{listen_port}"),
    }
}

fn cache_key(public: &str, origin: Option<&str>, path: &str, headers: &HeaderMap) -> String {
    let identity = request_identity(headers);
    format!(
        "{public}\x00{}\x00{path}\x00{identity}",
        origin.unwrap_or("")
    )
}

fn request_identity(headers: &HeaderMap) -> String {
    let mut hasher = Sha256::new();
    let mut present = false;
    for name in [header::COOKIE, header::AUTHORIZATION] {
        if let Some(value) = headers.get(&name) {
            hasher.update(name.as_str().as_bytes());
            hasher.update(b":");
            hasher.update(value.as_bytes());
            hasher.update(b"\n");
            present = true;
        }
    }
    if present {
        fingerprint_sha256(&hasher.finalize())
    } else {
        String::new()
    }
}

fn rewrite_map(
    original_host: Option<&str>,
    upstream_port: u16,
    public: &str,
) -> Vec<(String, String)> {
    let mut pairs = vec![
        (
            format!("http://127.0.0.1:{upstream_port}"),
            public.to_string(),
        ),
        (
            format!("http://localhost:{upstream_port}"),
            public.to_string(),
        ),
        (
            format!("http://0.0.0.0:{upstream_port}"),
            public.to_string(),
        ),
        (format!("http://[::1]:{upstream_port}"), public.to_string()),
    ];
    if let Some(host) = original_host {
        if !host.trim().is_empty() {
            pairs.push((format!("http://{host}"), public.to_string()));
        }
    }
    pairs.sort_by_key(|pair| std::cmp::Reverse(pair.0.len()));
    pairs.dedup_by(|a, b| a.0 == b.0);
    pairs
}

fn rewrite_bytes(body: &[u8], rewrites: &[(String, String)]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let mut changed = false;
    let mut rewritten = text.to_string();
    for (from, to) in rewrites {
        if rewritten.contains(from) {
            rewritten = rewritten.replace(from, to);
            changed = true;
        }
    }
    changed.then(|| rewritten.into_bytes())
}

fn rewrite_header_values(headers: &mut HeaderMap, rewrites: &[(String, String)]) {
    rewrite_header(headers, header::LOCATION, rewrites);
    rewrite_header(headers, header::CONTENT_LOCATION, rewrites);
    rewrite_header(headers, header::LINK, rewrites);
    rewrite_header(headers, header::REFRESH, rewrites);
}

fn rewrite_header(
    headers: &mut HeaderMap,
    name: header::HeaderName,
    rewrites: &[(String, String)],
) {
    let Some(value) = headers
        .get(&name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
    else {
        return;
    };
    let mut rewritten = value.clone();
    for (from, to) in rewrites {
        rewritten = rewritten.replace(from, to);
    }
    if rewritten != value {
        if let Ok(value) = HeaderValue::from_str(&rewritten) {
            headers.insert(name, value);
        }
    }
}

fn is_rewritable_text(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.starts_with("text/html")
                || value.starts_with("application/xhtml+xml")
                || value.starts_with("text/css")
                || value.starts_with("image/svg+xml")
        })
        .unwrap_or(false)
}

fn is_content_encoded(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.trim();
            !value.is_empty() && !value.eq_ignore_ascii_case("identity")
        })
        .unwrap_or(false)
}

fn is_cacheable(headers: &HeaderMap) -> bool {
    if headers.contains_key(header::SET_COOKIE) {
        return false;
    }
    if let Some(value) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    {
        let value = value.to_ascii_lowercase();
        if value.contains("no-store") || value.contains("no-cache") || value.contains("private") {
            return false;
        }
    }
    true
}

fn cors_preflight(headers: &HeaderMap) -> Option<String> {
    let origin = headers.get(header::ORIGIN)?.to_str().ok()?.to_string();
    headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .is_some()
        .then_some(origin)
}

fn preflight_response(headers: &HeaderMap, origin: &str) -> Response<Body> {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let response_headers = response.headers_mut();
    apply_cors(response_headers, Some(origin));

    let methods = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD");
    if let Ok(value) = HeaderValue::from_str(methods) {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, value);
    }

    let allow_headers = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("content-type, authorization");
    if let Ok(value) = HeaderValue::from_str(allow_headers) {
        response_headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, value);
    }
    response_headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
    response
}

fn apply_cors(headers: &mut HeaderMap, origin: Option<&str>) {
    let Some(origin) = origin else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    add_vary(headers, "Origin");
}

fn add_vary(headers: &mut HeaderMap, token: &str) {
    let existing = headers
        .get(header::VARY)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();
    if existing
        .split(',')
        .any(|value| value.trim().eq_ignore_ascii_case(token))
    {
        return;
    }
    let value = if existing.trim().is_empty() {
        token.to_string()
    } else {
        format!("{existing}, {token}")
    };
    if let Ok(value) = HeaderValue::from_str(&value) {
        headers.insert(header::VARY, value);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrites() -> Vec<(String, String)> {
        rewrite_map(Some("localhost:8443"), 8000, "https://localhost:8443")
    }

    fn rewrite(input: &str) -> String {
        let output = rewrite_bytes(input.as_bytes(), &rewrites()).expect("content changed");
        String::from_utf8(output).expect("utf-8")
    }

    #[test]
    fn rewrites_img_and_video_markup() {
        let html = concat!(
            r#"<img src="http://127.0.0.1:8000/a.png" "#,
            r#"srcset="http://localhost:8000/a.png 1x, http://127.0.0.1:8000/b.png 2x">"#,
            r#"<video poster="http://localhost:8000/p.jpg">"#,
            r#"<source src="http://127.0.0.1:8000/v.mp4" type="video/mp4">"#,
            r#"<track src="http://127.0.0.1:8000/c.vtt">"#,
            r#"</video>"#
        );
        let output = rewrite(html);

        assert!(output.contains(r#"src="https://localhost:8443/a.png""#));
        assert!(output.contains(
            r#"srcset="https://localhost:8443/a.png 1x, https://localhost:8443/b.png 2x""#
        ));
        assert!(output.contains(r#"poster="https://localhost:8443/p.jpg""#));
        assert!(output.contains(r#"src="https://localhost:8443/v.mp4""#));
        assert!(output.contains(r#"src="https://localhost:8443/c.vtt""#));
        assert!(!output.contains("http://"));
    }

    #[test]
    fn rewrites_css_media_urls() {
        let css = concat!(
            r#"body { background: url(http://127.0.0.1:8000/bg.webp); }"#,
            r#"video { background-image: url("http://localhost:8000/p.jpg"); }"#
        );
        let output = rewrite(css);

        assert!(output.contains("url(https://localhost:8443/bg.webp)"));
        assert!(output.contains(r#"url("https://localhost:8443/p.jpg")"#));
        assert!(!output.contains("http://"));
    }

    #[test]
    fn rewrites_svg_image_references() {
        let svg = concat!(
            r#"<svg xmlns="http://www.w3.org/2000/svg">"#,
            r#"<image href="http://127.0.0.1:8000/logo.png"/>"#,
            r#"<image xlink:href="http://localhost:8000/poster.jpg"/>"#,
            r#"</svg>"#
        );
        let output = rewrite(svg);

        assert!(output.contains(r#"href="https://localhost:8443/logo.png""#));
        assert!(output.contains(r#"xlink:href="https://localhost:8443/poster.jpg""#));
        assert!(output.contains(r#"xmlns="http://www.w3.org/2000/svg""#));
    }

    #[test]
    fn leaves_unrelated_urls_alone() {
        let html = r#"<img src="https://cdn.example.com/a.png"><a href="http://example.com">x</a>"#;
        assert!(rewrite_bytes(html.as_bytes(), &rewrites()).is_none());
    }
}
