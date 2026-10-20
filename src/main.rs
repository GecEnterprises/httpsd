use std::{
    borrow::Cow,
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
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
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
const MAX_CACHE_TOTAL: usize = 128 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 512;
const UPSTREAM_CACHE_TTL: Duration = Duration::from_secs(300);
const GATEWAY_CACHE_TTL: Duration = Duration::from_secs(3600);
/// Everything fetched from a third party is routed through this prefix so the
/// browser only ever talks to httpsd.
const GATEWAY_PREFIX: &str = "/_httpsd/";

type HttpsClient = Client<HttpsConnector<HttpConnector>, Body>;

struct ProxyState {
    client: HttpsClient,
    upstream_port: u16,
    listen_port: u16,
    cache: ResponseCache,
}

#[derive(Clone)]
struct CacheEntry {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    expires: Instant,
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
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.get(key).is_some_and(|entry| entry.expires <= now) {
            entries.remove(key);
        }
        entries.get(key).cloned()
    }

    fn put(&self, key: String, entry: CacheEntry) {
        if entry.body.len() > MAX_CACHE_BODY || entry.body.len() > MAX_CACHE_TOTAL {
            return;
        }
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, cached| cached.expires > now);

        let mut total: usize = entries.values().map(|cached| cached.body.len()).sum();
        while entries.len() >= MAX_CACHE_ENTRIES
            || total.saturating_add(entry.body.len()) > MAX_CACHE_TOTAL
        {
            let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, cached)| cached.expires)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(removed) = entries.remove(&oldest) {
                total = total.saturating_sub(removed.body.len());
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

/// Per-request knowledge needed to rewrite a document so that every fetch goes
/// back through httpsd.
struct RewriteContext {
    /// `https://<host>[:port]` for the request currently being served.
    public: String,
    /// Lowercased authority of the public origin (`host` or `host:port`).
    authority: String,
    upstream_port: u16,
    /// Lowercased `Host` the browser used, if it sent one.
    original_host: Option<String>,
    /// For gateway responses: the third-party `(scheme, authority)` the body
    /// came from. Root-relative URLs belong to that origin, not to httpsd.
    external: Option<(String, String)>,
}

impl RewriteContext {
    fn new(original_host: Option<&str>, upstream_port: u16, listen_port: u16) -> Self {
        let original_host = original_host
            .filter(|host| !host.trim().is_empty())
            .map(str::to_ascii_lowercase);
        let authority = original_host
            .clone()
            .unwrap_or_else(|| format!("localhost:{listen_port}"));
        Self {
            public: public_origin(original_host.as_deref(), listen_port),
            authority,
            upstream_port,
            original_host,
            external: None,
        }
    }
}

/// Extracts the `(scheme, authority)` from an absolute URL.
fn target_parts(target: &str) -> Option<(String, String)> {
    let (scheme, rest) = target.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), rest[..end].to_string()))
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

    // The same client handles the plain-http upstream and https third-party
    // origins, using the system trust store for the latter.
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .context("load system tls roots")?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
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
    log(
        "httpsd",
        "external resources are proxied and cached under /_httpsd/",
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
    let route_path = request.uri().path().to_string();
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

    if route_path.starts_with(GATEWAY_PREFIX) {
        return match gateway_route(&route_path, request.uri().query()) {
            Ok(target) => {
                gateway_handler(&state, peer, request, target, original_host.as_deref()).await
            }
            Err(status) => {
                log_access(peer, status, &method, &path, "-");
                status.into_response()
            }
        };
    }

    let ctx = RewriteContext::new(
        original_host.as_deref(),
        state.upstream_port,
        state.listen_port,
    );
    let cache_key = cache_key(&ctx.public, origin.as_deref(), &path, request.headers());

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
        rewrite_header_values(&mut parts.headers, &ctx);
        apply_cors(&mut parts.headers, origin.as_deref());

        let html = is_html(&parts.headers);
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
                    let rewritten = rewrite_body(&original, &ctx, html).unwrap_or(original);
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
                                expires: Instant::now() + UPSTREAM_CACHE_TTL,
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

/// Fetches a third-party URL on behalf of the browser, rewrites nested
/// references so they also come back through httpsd, and caches the result.
async fn gateway_handler(
    state: &ProxyState,
    peer: SocketAddr,
    request: Request<Body>,
    target: String,
    original_host: Option<&str>,
) -> Response<Body> {
    let mut ctx = RewriteContext::new(original_host, state.upstream_port, state.listen_port);
    ctx.external = target_parts(&target);
    let method = request.method().clone();
    let method_name = method.as_str().to_ascii_lowercase();
    let log_path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    if method != Method::GET && method != Method::HEAD {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        log_access(peer, response.status(), &method_name, &log_path, "-");
        return response;
    }

    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let range = request.headers().contains_key(header::RANGE);
    // Rewritten bodies embed the public origin, so cache per public origin.
    let cache_key = format!("gateway\x00{}\x00{target}", ctx.public);

    if method == Method::GET && !range {
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
            response
                .headers_mut()
                .insert("x-httpsd-cache", HeaderValue::from_static("hit"));
            apply_cors(response.headers_mut(), origin.as_deref());
            log_access(peer, status, &method_name, &log_path, "-");
            return response;
        }
    }

    let uri = match target.parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => {
            log_access(peer, StatusCode::BAD_REQUEST, &method_name, &log_path, "-");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let mut builder = Request::builder().method(method.clone()).uri(uri);
    {
        let headers = builder.headers_mut().expect("gateway request headers");
        if let Some(value) = request.headers().get(header::ACCEPT) {
            headers.insert(header::ACCEPT, value.clone());
        } else {
            headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        }
        if let Some(value) = request.headers().get(header::ACCEPT_LANGUAGE) {
            headers.insert(header::ACCEPT_LANGUAGE, value.clone());
        }
        if let Some(value) = request.headers().get(header::RANGE) {
            headers.insert(header::RANGE, value.clone());
        }
        let user_agent = request
            .headers()
            .get(header::USER_AGENT)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("httpsd/0.1"));
        headers.insert(header::USER_AGENT, user_agent);
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }

    let gateway_request = match builder.body(Body::empty()) {
        Ok(request) => request,
        Err(_) => {
            log_access(peer, StatusCode::BAD_REQUEST, &method_name, &log_path, "-");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let response = match state.client.request(gateway_request).await {
        Ok(response) => response,
        Err(err) => {
            log_access(peer, StatusCode::BAD_GATEWAY, &method_name, &log_path, "-");
            log_error("gateway", &format!("fetch failed for {target}: {err}"));
            return (
                StatusCode::BAD_GATEWAY,
                format!("gateway fetch failed: {err}"),
            )
                .into_response();
        }
    };

    let status = response.status();
    let (mut parts, body) = response.into_parts();
    let body = Body::new(body);
    strip_hop_headers(&mut parts.headers, false);
    // Cookies and origin-bound security policies from the third party must not
    // leak onto (or apply to) the httpsd origin.
    parts.headers.remove(header::SET_COOKIE);
    for name in [
        "strict-transport-security",
        "alt-svc",
        "clear-site-data",
        "report-to",
        "nel",
    ] {
        parts.headers.remove(name);
    }
    // Keep redirects inside the gateway too, otherwise the browser follows an
    // absolute third-party Location and bypasses httpsd.
    rewrite_header_values(&mut parts.headers, &ctx);

    let html = is_html(&parts.headers);
    let rewritable = method != Method::HEAD
        && status == StatusCode::OK
        && !range
        && is_rewritable_text(&parts.headers)
        && !is_content_encoded(&parts.headers);
    let cacheable =
        method == Method::GET && status == StatusCode::OK && !range && is_cacheable(&parts.headers);
    let content_length = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    let mut response = if rewritable {
        match to_bytes(Body::new(body), MAX_REWRITE_BODY).await {
            Ok(bytes) => {
                let original = bytes.to_vec();
                let rewritten = rewrite_body(&original, &ctx, html).unwrap_or(original);
                parts.headers.remove(header::CONTENT_ENCODING);
                parts.headers.remove(header::ETAG);
                parts.headers.remove("content-md5");
                parts.headers.remove(header::ACCEPT_RANGES);
                if let Ok(value) = HeaderValue::from_str(&rewritten.len().to_string()) {
                    parts.headers.insert(header::CONTENT_LENGTH, value);
                }
                if cacheable {
                    state.cache.put(
                        cache_key,
                        CacheEntry {
                            status,
                            headers: parts.headers.clone(),
                            body: rewritten.clone(),
                            expires: Instant::now() + gateway_ttl(&parts.headers),
                        },
                    );
                }
                Response::from_parts(parts, Body::from(rewritten))
            }
            Err(err) => {
                log_access(peer, StatusCode::BAD_GATEWAY, &method_name, &log_path, "-");
                log_error(
                    "gateway",
                    &format!("read rewritable response for {target}: {err}"),
                );
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    } else if cacheable && content_length.is_none_or(|len| len <= MAX_CACHE_BODY) {
        match to_bytes(Body::new(body), MAX_CACHE_BODY).await {
            Ok(bytes) => {
                let body = bytes.to_vec();
                if let Ok(value) = HeaderValue::from_str(&body.len().to_string()) {
                    parts.headers.insert(header::CONTENT_LENGTH, value);
                }
                state.cache.put(
                    cache_key,
                    CacheEntry {
                        status,
                        headers: parts.headers.clone(),
                        body: body.clone(),
                        expires: Instant::now() + gateway_ttl(&parts.headers),
                    },
                );
                Response::from_parts(parts, Body::from(body))
            }
            Err(err) => {
                log_access(peer, StatusCode::BAD_GATEWAY, &method_name, &log_path, "-");
                log_error(
                    "gateway",
                    &format!("read cacheable response for {target}: {err}"),
                );
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    } else {
        Response::from_parts(parts, Body::new(body))
    };

    response
        .headers_mut()
        .insert("x-httpsd-cache", HeaderValue::from_static("miss"));
    apply_cors(response.headers_mut(), origin.as_deref());

    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    log_access(
        peer,
        status,
        &method_name,
        &log_path,
        content_length.as_deref().unwrap_or("-"),
    );
    response
}

/// Splits `/_httpsd/<scheme>/<authority>/<path>?<query>` back into the URL to
/// fetch. Returns an HTTP status when the request is not a valid gateway URL.
fn gateway_route(path: &str, query: Option<&str>) -> Result<String, StatusCode> {
    let rest = path
        .strip_prefix(GATEWAY_PREFIX)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let (scheme, rest) = rest.split_once('/').ok_or(StatusCode::BAD_REQUEST)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (authority, tail) = match rest.split_once('/') {
        Some((authority, tail)) => (authority, format!("/{tail}")),
        None => (rest, String::new()),
    };
    if authority.is_empty() || !authority_is_valid(authority) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if host_is_forbidden(authority) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut target = format!("{scheme}://{authority}{tail}");
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }
    Ok(target)
}

fn authority_is_valid(authority: &str) -> bool {
    !authority.contains('@')
        && !authority.is_empty()
        && authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        })
}

/// Gatewaying loopback/link-local addresses would turn httpsd into an SSRF
/// bridge to services on the machine it runs on.
fn host_is_forbidden(authority: &str) -> bool {
    let host = authority_host(authority)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || match ip {
                    IpAddr::V4(ip) => ip.is_link_local(),
                    IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
                }
        }
        Err(_) => false,
    }
}

fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

fn split_authority(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end];
            let port = authority
                .get(end + 1..)
                .and_then(|rest| rest.strip_prefix(':'));
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host, Some(port))
        }
        _ => (authority, None),
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum UrlKind {
    Absolute,
    ProtocolRelative,
    RootRelative,
}

/// Rewrites every absolute (and protocol-relative) URL in a text document.
fn rewrite_text(text: &str, ctx: &RewriteContext) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut changed = false;
    let mut i = 0;

    while i < bytes.len() {
        let Some((start, body_start, kind)) = url_hit(text, i) else {
            i += 1;
            continue;
        };
        let end = url_end(bytes, body_start);
        if end <= start {
            i += 1;
            continue;
        }
        let raw = &text[start..end];
        if let Some(replacement) = rewrite_url(raw, ctx, kind) {
            if replacement != raw {
                out.push_str(&text[copied..start]);
                out.push_str(&replacement);
                copied = end;
                changed = true;
            }
        }
        i = end.max(i + 1);
    }

    if !changed {
        return None;
    }
    out.push_str(&text[copied..]);
    Some(out)
}

/// Finds a URL beginning at `i`, returning the URL start and the byte index
/// just past its scheme (or `//` for protocol-relative URLs).
fn url_hit(text: &str, i: usize) -> Option<(usize, usize, UrlKind)> {
    let rest = &text[i..];
    let bytes = rest.as_bytes();

    if bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://") {
        return Some((i, i + 8, UrlKind::Absolute));
    }
    if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://") {
        return Some((i, i + 7, UrlKind::Absolute));
    }

    // Protocol-relative URLs only in value position, to avoid mistaking `//`
    // comments for hosts.
    if bytes.starts_with(b"//") && i > 0 {
        let previous = text.as_bytes()[i - 1];
        if matches!(previous, b'"' | b'\'' | b'=' | b'(') {
            let body = &text[i + 2..];
            let end = body
                .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
                .unwrap_or(body.len());
            let host = &body[..end];
            let valid = !host.is_empty()
                && (host.contains('.') || host.contains(':'))
                && host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'-' | b':' | b'[' | b']' | b'_')
                });
            if valid {
                return Some((i, i + 2, UrlKind::ProtocolRelative));
            }
        }
    }

    // Root-relative URLs in external content belong to the third-party origin.
    // Only treat them as URLs in value position (`href="/x"`, `url(/x)`), and
    // keep the first character restrictive so regex literals are not touched.
    if bytes[0] == b'/' && i > 0 && bytes.get(1).is_some_and(|byte| url_path_start(*byte)) {
        let previous = text.as_bytes()[i - 1];
        if matches!(previous, b'"' | b'\'' | b'=' | b'(') {
            return Some((i, i + 1, UrlKind::RootRelative));
        }
    }

    None
}

fn url_path_start(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_'
                | b'-'
                | b'~'
                | b'%'
                | b'!'
                | b'$'
                | b'&'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

fn url_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte.is_ascii_whitespace()
            || matches!(
                byte,
                b'"' | b'\'' | b'<' | b'>' | b'`' | b'(' | b')' | b'\\'
            )
        {
            break;
        }
        i += 1;
    }
    i
}

/// Returns the replacement for `raw`, or `None` when the URL should be left
/// untouched (relative URLs never reach this function).
fn rewrite_url(raw: &str, ctx: &RewriteContext, kind: UrlKind) -> Option<String> {
    if kind == UrlKind::RootRelative {
        let (scheme, authority) = ctx.external.as_ref()?;
        return Some(format!(
            "{}{}{}/{}{}",
            ctx.public, GATEWAY_PREFIX, scheme, authority, raw
        ));
    }

    let protocol_relative = kind == UrlKind::ProtocolRelative;
    let (scheme, after) = if protocol_relative {
        ("https", &raw[2..])
    } else {
        let scheme_end = raw.find("://")?;
        (&raw[..scheme_end], &raw[scheme_end + 3..])
    };
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
        return None;
    }

    let split = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..split];
    let rest = &after[split..];
    if authority.is_empty() {
        return None;
    }
    let authority_lower = authority.to_ascii_lowercase();

    // Already talking to httpsd.
    if authority_lower == ctx.authority {
        return None;
    }

    // The upstream server referring to itself, by any of its local aliases.
    if is_upstream_authority(&authority_lower, ctx.upstream_port)
        || ctx
            .original_host
            .as_deref()
            .is_some_and(|host| same_authority(&authority_lower, host))
    {
        return Some(format!("{}{}", public_scheme(&ctx.public, &scheme), rest));
    }

    // Third-party resources are only interesting over http(s); websockets are
    // left to the browser.
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if is_namespace_authority(&authority_lower, rest) || host_is_forbidden(authority) {
        return None;
    }

    Some(gateway_url(ctx, &scheme, authority, rest))
}

fn public_scheme(public: &str, scheme: &str) -> String {
    if scheme.starts_with("ws") {
        public.replacen("https://", "wss://", 1)
    } else {
        public.to_string()
    }
}

fn is_upstream_authority(authority: &str, upstream_port: u16) -> bool {
    let (host, port) = split_authority(authority);
    let expected = upstream_port.to_string();
    port == Some(expected.as_str())
        && matches!(
            host,
            "127.0.0.1" | "localhost" | "0.0.0.0" | "[::1]" | "::1"
        )
}

fn same_authority(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let (a_host, a_port) = split_authority(a);
    let (b_host, b_port) = split_authority(b);
    a_host == b_host && (a_port.is_none() || b_port.is_none() || a_port == b_port)
}

/// XML namespace identifiers look like URLs but are never fetched.
fn is_namespace_authority(authority: &str, rest: &str) -> bool {
    let host = authority_host(authority).to_ascii_lowercase();
    matches!(
        host.as_str(),
        "www.w3.org" | "w3.org" | "schemas.xmlsoap.org" | "purl.org" | "xmlns.com" | "ns.adobe.com"
    ) || (host == "www.apple.com" && (rest.starts_with("/DTDs/") || rest.starts_with("/DTD/")))
}

fn gateway_url(ctx: &RewriteContext, scheme: &str, authority: &str, rest: &str) -> String {
    let mut url = format!("{}{}{}/{}", ctx.public, GATEWAY_PREFIX, scheme, authority);
    // A trailing slash makes relative URLs inside documents resolve back to
    // the third-party root instead of the gateway path's parent.
    if rest.is_empty() || rest.starts_with('?') || rest.starts_with('#') {
        url.push('/');
    }
    url.push_str(rest);
    url
}

fn rewrite_body(body: &[u8], ctx: &RewriteContext, html: bool) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let text = if html {
        strip_integrity(text)
    } else {
        Cow::Borrowed(text)
    };
    match rewrite_text(&text, ctx) {
        Some(rewritten) => Some(rewritten.into_bytes()),
        None if matches!(text, Cow::Owned(_)) => Some(text.into_owned().into_bytes()),
        None => None,
    }
}

/// Proxied bodies are modified, so subresource-integrity hashes no longer
/// match. The `integrity` attribute has to go or the browser rejects the file.
fn strip_integrity(html: &str) -> Cow<'_, str> {
    let lower = html.to_ascii_lowercase();
    let mut out = String::new();
    let mut copied = 0;
    let mut search = 0;

    while let Some(offset) = lower[search..].find("integrity") {
        let start = search + offset;
        search = start + "integrity".len();
        if start == 0 || !html.as_bytes()[start - 1].is_ascii_whitespace() {
            continue;
        }
        // Only inside a tag, never in text or inline script content.
        if html[..start].rfind('<') <= html[..start].rfind('>') {
            continue;
        }
        let mut cursor = search;
        while cursor < html.len() && html.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= html.len() || html.as_bytes()[cursor] != b'=' {
            continue;
        }
        cursor += 1;
        while cursor < html.len() && html.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= html.len() {
            break;
        }
        let quote = html.as_bytes()[cursor];
        let end = if quote == b'"' || quote == b'\'' {
            match html[cursor + 1..].find(quote as char) {
                Some(offset) => cursor + 1 + offset + 1,
                None => continue,
            }
        } else {
            html[cursor..]
                .find(|c: char| c.is_ascii_whitespace() || c == '>')
                .map(|offset| cursor + offset)
                .unwrap_or(html.len())
        };
        out.push_str(&html[copied..start]);
        copied = end;
        search = end;
    }

    if copied == 0 {
        Cow::Borrowed(html)
    } else {
        out.push_str(&html[copied..]);
        Cow::Owned(out)
    }
}

fn rewrite_header_values(headers: &mut HeaderMap, ctx: &RewriteContext) {
    rewrite_header(headers, header::LOCATION, ctx);
    rewrite_header(headers, header::CONTENT_LOCATION, ctx);
    rewrite_header(headers, header::LINK, ctx);
    rewrite_header(headers, header::REFRESH, ctx);
}

fn rewrite_header(headers: &mut HeaderMap, name: header::HeaderName, ctx: &RewriteContext) {
    let Some(value) = headers
        .get(&name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
    else {
        return;
    };
    let Some(rewritten) = rewrite_text(&value, ctx) else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&rewritten) {
        headers.insert(name, value);
    }
}

fn is_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.starts_with("text/html") || value.starts_with("application/xhtml+xml")
        })
        .unwrap_or(false)
}

fn is_rewritable_text(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let value = value.to_ascii_lowercase();
            if value.starts_with("text/event-stream") {
                return false;
            }
            value.starts_with("text/")
                || value.contains("javascript")
                || value.contains("json")
                || value.contains("xml")
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

fn gateway_ttl(headers: &HeaderMap) -> Duration {
    if let Some(value) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    {
        let value = value.to_ascii_lowercase();
        for part in value.split(',') {
            let part = part.trim();
            if let Some(max_age) = part.strip_prefix("max-age=") {
                if let Ok(seconds) = max_age.trim_matches('"').trim().parse::<u64>() {
                    return Duration::from_secs(seconds.clamp(60, 86_400));
                }
            }
        }
        if value.contains("immutable") {
            return Duration::from_secs(86_400);
        }
    }
    GATEWAY_CACHE_TTL
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

    fn ctx() -> RewriteContext {
        RewriteContext::new(Some("localhost:8443"), 8000, 8443)
    }

    fn rewrite(input: &str) -> String {
        rewrite_text(input, &ctx()).expect("content changed")
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
        assert!(!output.contains("http://127.0.0.1"));
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
    fn routes_external_images_through_gateway() {
        let html = r#"<img src="https://cdn.example.com/a.png">"#;
        let output = rewrite(html);

        assert_eq!(
            output,
            r#"<img src="https://localhost:8443/_httpsd/https/cdn.example.com/a.png">"#
        );
    }

    #[test]
    fn routes_google_fonts_through_gateway() {
        let html = concat!(
            r#"<link href="https://fonts.googleapis.com/css2?family=Inter&display=swap" "#,
            r#"rel="stylesheet">"#
        );
        let output = rewrite(html);

        assert!(output.contains(
            r#"https://localhost:8443/_httpsd/https/fonts.googleapis.com/css2?family=Inter&display=swap"#
        ));
    }

    #[test]
    fn rewrites_nested_css_urls_from_gateway() {
        let css = r#"@font-face { src: url(https://fonts.gstatic.com/s/inter/v1/x.woff2) format("woff2"); }"#;
        let output = rewrite(css);

        assert!(output.contains(
            "url(https://localhost:8443/_httpsd/https/fonts.gstatic.com/s/inter/v1/x.woff2)"
        ));
    }

    #[test]
    fn routes_protocol_relative_assets_through_gateway() {
        let html = r#"<script src="//cdn.example.com/app.js"></script>"#;
        let output = rewrite(html);

        assert_eq!(
            output,
            r#"<script src="https://localhost:8443/_httpsd/https/cdn.example.com/app.js"></script>"#
        );
    }

    #[test]
    fn leaves_data_relative_and_namespace_urls_alone() {
        let html = concat!(
            r#"<img src="/a.png">"#,
            r#"<img src="data:image/png;base64,AAAA">"#,
            r#"<a href="mailto:someone@example.com">x</a>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"></svg>"#
        );
        assert!(rewrite_text(html, &ctx()).is_none());
    }

    #[test]
    fn rewrites_root_relative_urls_in_external_documents() {
        let mut external = ctx();
        external.external = Some(("https".to_string(), "cdn.example.com".to_string()));
        let css = r#"body{background:url(/pic.png)}"#;

        assert_eq!(
            rewrite_text(css, &external).unwrap(),
            r#"body{background:url(https://localhost:8443/_httpsd/https/cdn.example.com/pic.png)}"#
        );
        // Upstream content is same-origin, so its root-relative URLs stay put.
        assert!(rewrite_text(css, &ctx()).is_none());
    }

    #[test]
    fn does_not_gateway_itself_twice() {
        let html = r#"<img src="https://localhost:8443/_httpsd/https/cdn.example.com/a.png">"#;
        assert!(rewrite_text(html, &ctx()).is_none());
    }

    #[test]
    fn strips_integrity_attributes() {
        let html = concat!(
            r#"<script src="/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>"#,
            r#"<link rel="stylesheet" href="/b.css" integrity='sha256-def'>"#
        );
        let output = strip_integrity(html);

        assert!(!output.contains("integrity"));
        assert!(output.contains(r#"src="/a.js""#));
        assert!(output.contains(r#"href="/b.css""#));
    }

    #[test]
    fn parses_gateway_routes() {
        assert_eq!(
            gateway_route("/_httpsd/https/example.com/a", Some("b=1")).unwrap(),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            gateway_route("/_httpsd/http/example.com:8080/a/b", None).unwrap(),
            "http://example.com:8080/a/b"
        );
        assert_eq!(
            gateway_route("/_httpsd/https/example.com", None).unwrap(),
            "https://example.com"
        );
        assert_eq!(
            gateway_route("/_httpsd/ftp/example.com/a", None).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn blocks_gateway_to_loopback() {
        assert_eq!(
            gateway_route("/_httpsd/https/127.0.0.1/secret", None).unwrap_err(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            gateway_route("/_httpsd/https/localhost/secret", None).unwrap_err(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn builds_gateway_urls_with_relative_safe_paths() {
        assert_eq!(
            gateway_url(&ctx(), "https", "example.com", ""),
            "https://localhost:8443/_httpsd/https/example.com/"
        );
        assert_eq!(
            gateway_url(&ctx(), "https", "example.com", "?q=1"),
            "https://localhost:8443/_httpsd/https/example.com/?q=1"
        );
    }
}
