# Mihomo_Deployment

One self-contained Bash script that turns a fresh **Ubuntu 22.04 / 24.04 / 26.04** server
into a multi-protocol **mihomo (Clash.Meta)** proxy node — enumerating every valid
protocol × transport × security-layer combination the core implements, picking a free port
for each, generating every secret, validating the config before it ever restarts the
service, tuning the kernel, and emitting ready-to-import client bundles.

```bash
sudo bash Mihomo_Deployment.sh
```

---

## Why mihomo, next to the other two scripts

`Singbox_Deployment.sh` and `Xray_Deployment.sh` already cover the mainstream set. mihomo is
here for what **only mihomo** does server-side:

| Only in mihomo | What it is |
|---|---|
| `shadowquic` | 0-RTT QUIC with JLS SNI camouflage — no certificate at all |
| `sudoku` | ED25519-keyed obfuscation with optional HTTP masking |
| `mieru` | Google-authored obfuscated transport, TCP or UDP |
| `trusttunnel` | TCP or QUIC tunnel with mutual auth |
| `jls` / `res-tls` | Certificate-less TLS camouflage layers usable under six protocols |
| `tlsmirror` | Mirrors a real upstream TLS connection (VMess only) |
| `mekya` / `mkcp` | h2-over-KCP and raw mKCP transports for VMess |
| `snell` v1–v4 | Native, no separate `snell-server` binary needed |

Neither sing-box nor Xray-core implements any of those.

---

## The combination space

The catalogue is not a hand-written list — it is the **cross product** of three axes, minus
the combinations the core rejects or cannot actually use. `--protocols all` deploys all 74.

| Base | Transports | Security layers | Count |
|---|---|---|---|
| `vless` | tcp, ws, grpc, xhttp | tls, reality, shadowtls, restls, jls | 18 |
| `vmess` | tcp, ws, grpc, mkcp, mekya | the above five | 15 |
| `trojan` | tcp, ws, grpc | the above five | 13 |
| `anytls` | — | tls, shadowtls, restls, jls | 4 |
| `ss` | plain, obfs-http, obfs-tls, kcptun | none, shadowtls, restls, jls | 7 |
| `snell` | plain, obfs-http, obfs-tls | none, shadowtls, restls, jls | 6 |
| `hysteria2` | QUIC | own TLS, optional salamander obfs, + realm server | 3 |
| `tuic`, `shadowquic` | QUIC | own TLS / JLS | 2 |
| `mieru` | TCP, UDP | own | 2 |
| `sudoku` | raw, http-mask | own | 2 |
| `trusttunnel` | TCP, QUIC | TLS | 2 |

```bash
sudo bash Mihomo_Deployment.sh --list-protocols     # print the whole catalogue
```

### What is deliberately excluded, and why

Every exclusion is traced to mihomo's own source, not guessed:

- **Two security layers on one listener.** Each TCP-family listener builds a `securityModes`
  slice and hard-errors on more than one. That is why there is one listener *per*
  combination rather than one listener with several layers.
- **`ws` + `reality`.** The listener accepts it and binds, but `case "ws":` in
  `adapter/outbound/{vless,vmess,trojan}.go` builds a plain `tls.Config` and never passes
  `Reality` — unlike the tcp / grpc / xhttp branches, which do. No mihomo client can complete
  the handshake; the server treats it as an unauthenticated prober and forwards it to the
  decoy, so the connection returns `unexpected status: 200 OK`. Confirmed end-to-end.
- **`grpc` + `restls`.** Both halves work alone — gRPC carries tls / reality / shadow-tls /
  jls, and RestLS carries tcp / ws / anytls / snell / shadowsocks — but together the
  connection hangs with no error on either side. gun skips its negotiated-ALPN check for
  RestLS precisely because RestLS reports none (`transport/gun/gun.go:282`), and the h2
  framing never establishes. Reproduced on an isolated three-listener rig where
  `vless-tcp-restls` and `vless-grpc-jls` both passed in the same run, before and after.
- **`tlsmirror`** (VMess-only). The listener binds, but a working connection needs the
  *client* to carry an `embedded-traffic-generator` — a hand-authored steps profile of HTTP
  requests driving the mirrored carrier against that specific decoy. Upstream only exercises
  it against a controlled carrier and a v2ray peer. Without a matching generator the client
  just hangs. The emitter for it is still in the script, so you can add the listener by hand
  to `/etc/mihomo/config.yaml` if you have a generator profile.
- **`mkcp` + shadow-tls / res-tls / jls** — `"<Mode> only supports TCP transports"`.
- **`mekya` + ws/grpc**, and **`mekya` + `mkcp`** — mutually exclusive in source.
- **`kcptun` / `simple-obfs` + a security layer** — kcptun replaces the TCP listener
  entirely, so the layer would be configured and silently never applied.
- **Plain (unencrypted-transport) `vless` / `trojan` / `anytls`** — the core refuses to
  start them without one of certificate / reality / shadow-tls / res-tls / jls.

---

## Certificates and camouflage

Only some protocols want a certificate. REALITY, ShadowTLS, RestLS, JLS, TLS-mirror and
ShadowQUIC deliberately want **none** — they borrow a real external site's TLS identity.

```bash
sudo bash Mihomo_Deployment.sh --reality-sni www.microsoft.com --steal-sni www.apple.com
```

- `--reality-sni` — the site REALITY steals its handshake from.
- `--steal-sni` — the decoy that ShadowTLS / RestLS / JLS / TLS-mirror / ShadowQUIC forward
  unauthenticated probes to, and that Hysteria2 masquerades as.

**Both must be reachable from the server**; pre-flight checks this and warns if not. If the
server cannot reach the decoy, the disguise fails open and looks anomalous — worse than not
using it.

### How the certificate is obtained

The script asks for the domain first (`--domain`, required — there is no default and `-y`
without it aborts), then:

1. `certbot certonly --standalone --http-01-port 80 -d <domain>` — mihomo is stopped for the
   request, though it never binds :80 itself, so renewals need no downtime.
2. The issued pair is **copied into `/etc/mihomo/cert/`** rather than referenced in
   `/etc/letsencrypt`, because mihomo's `SAFE_PATHS` check rejects any path outside its home
   directory — a listener pointing at `/etc/letsencrypt/live/...` fails to bind, and does so
   *non-fatally*, leaving the service `active` with a dead listener.
3. A deploy hook is installed at `/etc/letsencrypt/renewal-hooks/deploy/mihomo-<domain>.sh`
   that re-copies and reloads on every renewal.
4. If issuance fails — DNS not pointing here, :80 taken, rate limit — it warns and falls back
   to a self-signed certificate rather than leaving you with none.

Pre-flight `dig`s the A record first and warns when it does not resolve to this host, since
that is the usual reason HTTP-01 fails.

`certbot`'s challenge needs inbound tcp/80, but the firewall step runs *after* the
certificate step. On a host where ufw is already active that would silently break issuance,
so :80 is opened for the duration of the request and closed again afterwards; the permanent
rule is added later only if issuance actually succeeded.

**Not every deployment needs a certificate at all.** `setup_cert` is skipped entirely when no
selected protocol wants one — a `--protocols reality,jls,shadowtls,shadowquic` node deploys
34 listeners with no certificate anywhere on disk and no `certificate:` key in the config
(verified: 34/34 bind, zero errors).

---

## Release channels

| Channel | What you get |
|---|---|
| `stable` (default) | the newest tagged release |
| `alpha` | the rolling `Prerelease-Alpha` build of the Alpha branch |
| `pinned` | an exact tag you name with `--version` |

The listener set is currently **identical** between stable and Alpha — `listener/parse.go`
and all 31 files under `listener/inbound/` are byte-identical. There is no server-side
protocol you gain by running Alpha today.

### The amd64 trap

Upstream's `mihomo-linux-amd64-<ver>.gz` asset is a **GOAMD64=v3** build. It `SIGILL`s on
anything older than Haswell/Excavator and on VPS hosts that mask AVX2. The script probes
`/proc/cpuinfo`, picks the explicit `-v1` / `-v2` / `-v3` asset accordingly, and falls back
to the legacy `amd64-compatible` name if `-v1` is missing. Override with
`--amd64-level v1`.

---

## Client bundles

Written to `/root/mihomo-clients/`:

| File | For |
|---|---|
| `client-mihomo.yaml` | mihomo / Clash.Meta — **all 73 proxy nodes**; the complete bundle |
| `links.txt` | share links, portable subset only |
| `subscription.txt` | base64 of `links.txt` (v2rayN, NekoBox, Streisand, Shadowrocket) |
| `client-singbox.json` | sing-box client config, compatible subset |
| `README.txt` | full port map, per-node artefact matrix, all credentials |

**Only 24 of the 74 nodes have a share-link form**, and that is not a shortcut — no URI
grammar exists in any client for Snell, ShadowQUIC, Sudoku, Mieru, TrustTunnel, the
mKCP/Mekya/TLS-mirror transports, or any ShadowTLS / RestLS / JLS wrapper. Emitting a link
for those would produce something no client can import. They all live in the YAML instead.

`README.txt` carries a per-node matrix — `yaml` / `link` / `sing-box` / `port` — with a
totals row, so it is always explicit which artefact carries which node:

```
  key                          l4     yaml   link   sing-box  port
  vless-tcp-tls                tcp    yes    yes    yes       40000
  ...
  hysteria2-realm              tcp    no     no     no        40065
  TOTAL 74                            73     24     20
```

**73 of the 74, not all 74.** The YAML holds every node you can actually dial. The one
exception is `hysteria2-realm`, which is not a proxy at all: it is the HTTPS rendezvous
endpoint that Hysteria2 nodes register with through `realm-opts`, so there is no `proxies:`
entry it could have. It is deployed and listening, but nothing in the generated config
points at it — wire it up by hand if you want realm mode, or leave it out with
`--protocols` to save the port.

`--serve-sub` additionally serves the bundle over plain HTTP at a secret path, picking the
right artefact from the client's `User-Agent`.

---

## Subcommands

```bash
sudo bash Mihomo_Deployment.sh                 # deploy
sudo bash Mihomo_Deployment.sh info            # reprint links / subscription / credentials
sudo bash Mihomo_Deployment.sh status          # service + listening ports
sudo bash Mihomo_Deployment.sh check           # re-run every health check
sudo bash Mihomo_Deployment.sh update          # upgrade mihomo
sudo bash Mihomo_Deployment.sh regen-sub       # rebuild client bundles from state
sudo bash Mihomo_Deployment.sh uninstall       # remove configuration
```

After a deploy the script installs itself as `/usr/local/sbin/mihomoctl` (when run from a saved file — a piped `wget -O- … | bash` run skips this and says so).

---

## Options

| Option | Default | Notes |
|---|---|---|
| `-y`, `--yes` | off | Non-interactive; requires `--domain` |
| `--domain <fqdn>` | *required* | e.g. `vpn.example.com`; no default |
| `--ip <ipv4>` | auto-detected | Public IPv4 |
| `--channel <stable\|alpha\|pinned>` | `stable` | `alpha` = rolling `Prerelease-Alpha` build |
| `--version <tag>` | — | Exact tag for `--channel pinned`, e.g. `v1.19.30` |
| `--amd64-level <auto\|v1\|v2\|v3>` | `auto` | Plain `amd64` asset is a v3 build; see the amd64 trap |
| `--protocols <all\|recommended\|core\|list>` | `all` | Keys, families or security layers, comma-separated |
| `--listen <addr>` | `::` | Bare IP; `::` dual-stack, `0.0.0.0` v4-only |
| `--cert-mode <letsencrypt\|self>` | `letsencrypt` | Only if a selected protocol wants a cert |
| `--le-email <email>` | — | Let's Encrypt contact |
| `--reality-sni <host>` | `www.microsoft.com` | REALITY steal target |
| `--steal-sni <host>` | `www.apple.com` | ShadowTLS / RestLS / JLS / TLS-mirror / ShadowQUIC decoy |
| `--ss-method <cipher>` | `2022-blake3-aes-128-gcm` | Shadowsocks cipher |
| `--snell-version <1..4>` | `4` | Snell protocol version |
| `--api-listen <ip:port>` | `127.0.0.1:9090` | RESTful controller; `''` disables |
| `--no-kernel-tuning` | tuning on | |
| `--firewall <auto\|ufw\|iptables\|none>` | `auto` | |
| `--serve-sub` | off | Also serve the subscription over plain HTTP |
| `--skip-preflight` | off | Skip pre-flight checks |

---

## Selecting a subset

`--protocols` accepts individual keys, base-protocol families, transport families and
security-layer families, comma-separated:

```bash
# just the certificate-less camouflage layers
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols reality,jls,shadowtls

# every UDP-based listener (QUIC + mKCP/KCPTun)
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols quic

# the mihomo-exclusive protocols plus a couple of classics
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols exotic,vless-tcp-reality,hysteria2

# a curated 14 that cover every distinct technique
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols recommended
```

| Preset | Meaning |
|---|---|
| `all` | every valid combination (74) — the default |
| `recommended` | a curated 14 covering every distinct technique |
| `core` | the 8 classics the sing-box / Xray scripts also offer |
| families | `vless` `vmess` `trojan` `anytls` `ss` `snell` `mieru` `sudoku` `trusttunnel` `shadowquic` `quic` `exotic` |
| by security | `reality` `shadowtls` `restls` `jls` `tls` |
| by transport | `ws` `grpc` `xhttp` `mkcp` `mekya` `kcptun` |

Deploying all 74 means 74 listening sockets and 74 firewall openings. It works — but
`recommended` is the saner default for a production node, and the script says so.

---

## Hardening notes

- The systemd unit runs as an unprivileged `mihomo` user with **only**
  `CAP_NET_BIND_SERVICE`. Upstream's unit runs as root with `NET_ADMIN`, `NET_RAW`,
  `SYS_TIME`, `SYS_PTRACE`, `DAC_OVERRIDE` and more; a server-only node needs none of them.
  `NET_ADMIN` is normally required so quic-go can force its receive buffer past the kernel
  ceiling — the sysctl drop-in raises `net.core.rmem_max` instead, so that path is never taken.
- `ProtectSystem=strict` with `ReadWritePaths=/etc/mihomo`, plus the usual `Protect*` /
  `Restrict*` set. `AF_NETLINK` stays allowed — Go's `net` package needs it.
- The RESTful controller binds `127.0.0.1:9090` with a generated secret. An
  unauthenticated controller is remote code execution; `--api-listen ''` disables it.
- The generated server config is validated with `mihomo -t -d /etc/mihomo` **before** the
  service is restarted. That only catches parse errors, though: a listener that cannot bind
  is logged and skipped while the unit stays `active`, so the script also greps the journal
  for `listen err` and probes every port individually in `check`.

---

## Verification

The catalogue was booted end-to-end against **mihomo v1.19.30**: all 74 listeners bind with
zero errors, both the server config and the generated client YAML pass `mihomo -t`, and real
traffic was proxied through the nodes with a real mihomo client — including every
mihomo-exclusive protocol (ShadowQUIC, Sudoku with and without HTTP masking, Mieru over TCP
and UDP, TrustTunnel over TCP and QUIC, Mekya, mKCP, KCPTun, Snell under all three
camouflage layers).

All three exclusions above came out of that run rather than out of the documentation — each
was then traced back to the specific line of mihomo source that explains it.

One operational note the test surfaced: every camouflage layer opens a **real TLS connection
to the decoy** on each client connection. A burst of hundreds of handshakes from one IP will
get throttled by a large CDN, which looks exactly like a broken config. Pick a decoy that can
absorb your traffic, and do not read a single failed probe as a broken node.
