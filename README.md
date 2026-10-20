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

httpsd rewrites the upstream's `http://` self-references so the page keeps working over https. it handles:

- `text/html` and `application/xhtml+xml` bodies, including `href`, `src`, `action`, `srcset`, inline css `url(...)`, and urls inside inline scripts
- `location`, `content-location`, `link`, and `refresh` response headers

the upstream origins `http://127.0.0.1:<server-port>`, `http://localhost:<server-port>`, `http://0.0.0.0:<server-port>`, `http://[::1]:<server-port>`, and `http://<request-host>` are replaced with `https://<request-host>`.

rewritten html is cached in memory for five minutes (at most 128 entries / 8 mib per entry). cache keys include the requested host, `origin`, and a hash of `cookie`/`authorization`, so responses are not shared across identities. responses with `set-cookie` or `cache-control: no-store`, `no-cache`, or `private` are not cached. successful non-GET requests clear the cache.

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
