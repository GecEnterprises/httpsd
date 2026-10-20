# httpsd

a dead simple 2-argument https proxy.

```sh
httpsd <server-port> <listen-port>
```

`server-port` is an http server on `127.0.0.1`. `listen-port` is where httpsd serves https on every interface. requests are forwarded unchanged except hop-by-hop headers; websocket upgrades are passed through too. html responses are rewritten, cached, and given permissive cors headers (see below).

```sh
httpsd 8000 8443
```

then open `https://localhost:8443` (or `https://<lan-ip>:8443`).

## rewriting and caching

httpsd rewrites every URL it can find, not just the upstream's own `http://` self-references. third-party resources such as google fonts, cdn scripts, and externally hosted images are pointed back at httpsd, fetched by httpsd, cached, and served from the httpsd origin. the browser never needs to contact those hosts directly. it handles:

- `text/html` and `application/xhtml+xml` bodies, including `href`, `src`, `action`, `srcset`, `poster`, `<source>`, inline css `url(...)`, and urls inside inline scripts
- `text/css` stylesheets, javascript, json, xml, and `image/svg+xml` documents
- absolute `http://` / `https://` urls, protocol-relative `//host/...` urls, and root-relative `/asset` urls inside third-party documents
- `location`, `content-location`, `link`, and `refresh` response headers
- `integrity` attributes are stripped from rewritten html because proxied bodies no longer match their subresource hashes

the upstream origins `http://127.0.0.1:<server-port>`, `http://localhost:<server-port>`, `http://0.0.0.0:<server-port>`, `http://[::1]:<server-port>`, and `http://<request-host>` are replaced with `https://<request-host>`.

### external gateway

third-party urls are rewritten to:

```
https://<request-host>/_httpsd/<scheme>/<authority>/<path>?<query>
```

httpsd fetches that url over https (using the system trust store), rewrites any nested urls in the response, and caches it. relative and root-relative references inside a third-party css or html file are resolved against that third-party origin, so font files, images, and imports keep working. redirects are rewritten into gateway urls as well. the `/_httpsd/` prefix is reserved by httpsd.

loopback, unspecified, multicast, and link-local addresses are refused (`403`) so the gateway cannot be used to reach services on the machine running httpsd.

### cache

rewritten upstream responses are cached for five minutes. gateway responses use the origin's `cache-control: max-age` clamped to 1 minute - 24 hours, defaulting to one hour. at most 512 entries / 8 mib per entry / 128 mib total are kept in memory. upstream cache keys include the requested host, `origin`, and a hash of `cookie`/`authorization`, so responses are not shared across identities. gateway cache keys include the public origin and target url; cookies are never forwarded to third parties. responses with `set-cookie` or `cache-control: no-store`, `no-cache`, or `private` are not cached. successful non-GET requests clear the upstream cache. responses carry `x-httpsd-cache: hit` or `miss`.

## cors

when a request carries an `origin`, httpsd reflects it in `access-control-allow-origin`, enables credentials, and adds `vary: origin`. cors preflight (`OPTIONS` with `access-control-request-method`) is answered directly with the requested method and headers, and a ten minute max-age.

## tls

the first run generates a self-signed ecdsa p-256 certificate and keeps it stable across restarts. the certificate covers `localhost`, the machine hostname, `127.0.0.1`, and every local ipv4 address. files live in the platform config directory:

- linux: `~/.config/httpsd/`
- macos: `~/Library/Application Support/httpsd/`
- windows: `%APPDATA%\httpsd\`

override with `HTTPSD_CONFIG_DIR`.

the sha-256 fingerprint is printed on startup. browsers will warn about the untrusted certificate; that is expected for a self-signed local tool.

## logging

console output follows copyparty's compact style: cyan time, yellow source, lowercase words, colour-coded status.

```
12:34:56 tls                         using certificate in /home/you/.config/httpsd
12:34:56 tls                         sha256 fingerprint ab:cd:...
12:34:56 httpsd                      listening on https://0.0.0.0:8443 -> http://127.0.0.1:8000
12:34:57 192.168.1.20 51234          get / 200 1234
```
