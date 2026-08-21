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
the combinations the core rejects or cannot actually use. `--protocols all` deploys all 81.

| Base | Transports | Security layers | Count |
|---|---|---|---|
| `vless` | tcp, ws, grpc, xhttp | tls, reality, shadowtls, restls, jls | 18 |
| `vmess` | tcp, ws, grpc, mkcp x5, mekya | the above five | 19 |
| `trojan` | tcp, ws, grpc | the above five | 13 |
| `anytls` | — | tls, shadowtls, restls, jls | 4 |
| `ss` | plain, obfs-http, obfs-tls, kcptun x4 | none, shadowtls, restls, jls | 10 |
| `snell` | plain, obfs-http, obfs-tls | none, shadowtls, restls, jls | 6 |
| `hysteria2` | QUIC | own TLS, optional salamander obfs, + realm server | 3 |
| `tuic`, `shadowquic` | QUIC | own TLS / JLS | 2 |
| `mieru` | TCP, UDP | own | 2 |
| `sudoku` | raw, http-mask | own | 2 |
| `trusttunnel` | TCP, QUIC | TLS | 2 |

```bash
sudo bash Mihomo_Deployment.sh --list-protocols     # print the whole catalogue
```

### Variants: one parameter changed, its own listener

`mkcp` and `kcptun` each carry parameters whose right value is a judgement call rather than a
fact — which packet header to wear, whether to run congestion control, how much FEC to buy,
whether to rotate source ports. Each of those choices gets its **own listener on its own
port**, so it can be measured on the live path instead of argued about.

| Key | Differs from the baseline by |
|---|---|
| `vmess-mkcp` | baseline: `header: srtp`, congestion on |
| `vmess-mkcp-dtls` | `header: dtls` |
| `vmess-mkcp-wechat` | `header: wechat-video` |
| `vmess-mkcp-utp` | `header: utp` |
| `vmess-mkcp-nocong` | `congestion: false` — wider window through loss, paid for in retransmits |
| `ss-kcptun` | baseline: `mode fast2`, FEC 10/1, `conn 4` + `autoexpire 25` source-port rotation |
| `ss-kcptun-static` | no rotation — the control for measuring what rotation buys |
| `ss-kcptun-fec` | FEC 10/3 (30% overhead) for a path lossy enough to need it |
| `ss-kcptun-fast3` | `mode fast3` — lower latency, higher packet rate and CPU |

Compare them with `mihomoctl amplification`, which reports wire bytes over payload bytes per
port. That ratio, not throughput, is what decides how long an IP survives.

`wireguard` is a valid mKCP header and is deliberately **not** offered: WireGuard's own
handshake is DPI-classified and throttled on Iranian carriers, so wearing it as a disguise
attracts exactly the attention the disguise exists to avoid.

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

### `--decoy local`: be a real site instead of impersonating one

Borrowing `www.apple.com` has two costs that are easy to miss.

The first is a **disagreement a passive observer can score**: your client presents
`servername: www.apple.com` to an IP that demonstrably is not Apple's. The second is
**latency and sockets**: RestLS dials `dest` before it reads a single client byte, relays the
real handshake through, and — in mihomo — keeps that socket open for the whole session. So
every proxied connection is one live connection to the decoy, and your TLS handshake
completes one decoy-RTT after your TCP handshake did, which a prober can time.

`--decoy local` replaces the third party with a TLS 1.3 nginx site on `127.0.0.1:8443`
serving **your own domain's real certificate**:

```bash
sudo bash Mihomo_Deployment.sh --domain vpn.example.com --decoy local
```

SNI, certificate and IP now all agree, the extra round trip disappears, and the held-open
sockets are loopback.

**It is opt-in, and `--decoy auto` resolves to `steal`.** That is deliberate. Local is better
against SNI/IP-mismatch scoring, but it is a different bet rather than a strictly better one:
every borrowed-identity layer then presents *your* domain, so a single blocklist entry against
a name that is already public in the Certificate Transparency logs takes out ShadowTLS, RestLS
and JLS together — whereas a large third party's name is not realistically blockable. Iran's
dominant censorship mechanism is still cleartext SNI blocklisting, which is exactly the axis
where borrowing wins. Choosing that trade is the operator's call, so nothing picks it for you.

The nginx site is configured for what RestLS and JLS actually need, not for general web
serving:

- `ssl_session_tickets off` — NewSessionTicket records count toward the server flight and
  **consume RestLS script lines**, so a dest whose ticket count varies shifts the script
  alignment from connection to connection.
- `ssl_ecdh_curve X25519:prime256v1` — both RestLS and JLS reject a HelloRetryRequest
  outright, so the curve the browser fingerprint puts its first key_share on has to be
  accepted first time.
- `TLSv1.2 TLSv1.3` — 1.3 for the normal path, 1.2 kept so an old prober gets a real answer
  rather than an alert no real site would send.
- No `listen 80` — certbot renews standalone on port 80 and nginx must not hold it.

The honest trade: you are no longer impersonating a large site, you are a small one. That is
the Trojan model, and it is a different bet, not a strictly better one.

### The RestLS script is the protocol

`res-tls` without a `restls-script` is **not** "RestLS with no shaping" — both halves fall
back to the same built-in default string, so every untouched RestLS deployment on the
internet emits one identical record-length sequence. That is a stable, publicly known
signature, and an easier one to match than the TLS-in-TLS record pattern RestLS exists to
hide. Shipping the upstream README's example string has the same problem for the same reason.

This script therefore **generates one per deployment, per direction** — the server's programme
shapes server→client records, the client's shapes client→server, and they are independent
programmes (commands travel in-band; neither side ever compares its script against the
peer's). Both are printed in `README.txt` and kept in state so `regen-sub` does not change
them.

```
<target>[ ('?'|'~') <range> ][ '<' <n> ]      comma-separated
  ~   re-rolls per record — this is what actually randomises anything
  ?   resolves ONCE at parse time and is then cached per process, so it is a
      per-server constant shared by every user until restart. Only honest on
      record 1, where a fixed-size preamble is plausible.
  <n  asks the peer for n fake records AND blocks the sender until one comes
      back: one full round trip each, on every connection. Budget: 1-2 total.
```

Override with `--restls-script`, which is validated against the parser's real limits
(`target ≤ 32767`, `range ≤ 32767`, `target+range ≤ 32768`, `n < 255`, no empty entries, no
`?0`). **Do not ship a script anyone else has** — the entire claim of the design is that no
two deployments share one.

`--restls-min-record-len` defaults to `0`, meaning "leave the server's built-in 15". Raising
it pads every short record to a uniform floor, which is a signature in its own right; set it
only if you have measured genuinely short records on your own path. `rate-limit` is left
unset on both `res-tls` and `jls-config` for the same class of reason: it throttles only the
relay a failed prober gets, so any value makes the server deliver the decoy at a capped,
unnaturally smooth bitrate the real site does not — turning a byte-perfect impersonation into
a measurable one.

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

**Only 24 of the 81 nodes have a share-link form**, and that is not a shortcut — no URI
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
  TOTAL 81                            80     24     20
```

**80 of the 81, not all 81.** The YAML holds every node you can actually dial. The one
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
sudo bash Mihomo_Deployment.sh amplification   # wire bytes vs payload bytes, per port
sudo bash Mihomo_Deployment.sh pmtu <host>     # largest unfragmented UDP payload to <host>
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
| `--no-metering` | metering on | Skip the nftables byte counters behind `amplification` |
| `--serve-sub` | off | Also serve the subscription over plain HTTP |
| `--skip-preflight` | off | Skip pre-flight checks |
| `--decoy <auto\|local\|steal>` | `auto` → `steal` | Where probers get relayed; see camouflage above |
| `--decoy-port <n>` | `8443` | Loopback port for the local decoy |
| `--restls-script <s>` | generated | Override the RestLS record programme |
| `--restls-min-record-len <n>` | `0` | `0` leaves the server's built-in 15 |
| `--client-down-mbps <n>` | `60` | Client downlink — sizes the download window |
| `--client-up-mbps <n>` | `15` | Client uplink — the expensive one to get wrong |
| `--server-up-mbps <n>` | `1000` | Server uplink |
| `--server-down-mbps <n>` | `1000` | Server downlink |
| `--rtt-ms <n>` | `120` | Round-trip time to the clients |
| `--loss-pct <n>` | `2` | Guides the FEC ratio only |
| `--kcp-mtu <n>` | `1200` | QUIC's safe-datagram floor; survives mobile paths |
| `--mkcp-tti <n>` | `25` | mKCP tick, ms; must divide 1000 exactly |
| `--probe-interval <n>` | `60` | Client health-check interval, seconds |
| | | `lazy: false` is set on `FAILOVER` only — see below |
| `--brutal` / `--no-brutal` | off | TCP Brutal over smux; see below |

---

## Transport tuning

mKCP and kcp-tun are **window-based**, and a window is sized from the link of the side that
writes the number. A German VPS and an Iranian handset do not share a link, so one set of
numbers cannot be correct for both ends — and the end it is wrong for is always the client,
where a window meant for a 1 Gbps port becomes seconds of standing queue that every DNS
lookup and TCP ACK then waits behind.

Nothing here is hard-coded. Six numbers describe the path, and every window, buffer, rate
limit and FEC ratio is derived from them:

```bash
sudo bash Mihomo_Deployment.sh --domain vpn.example.com \
     --client-down-mbps 60 --client-up-mbps 15 --rtt-ms 120
```

The derivation inverts mihomo's own formula
(`transport/mkcp/config.go`: `inFlight = capacity × 1048576 / mtu / (1000/tti)`), so
`uplink-capacity` is treated as what it is — a window dial whose product with `tti` sets
bytes in flight — rather than as the link speed its name suggests. The two sides then carry
**deliberately different** values:

| | server writes | client writes |
|---|---|---|
| `uplink-capacity` / `sndwnd` | sized for your **download** | sized for your **upload** |
| `downlink-capacity` / `rcvwnd` | window advertised for uploads | window advertised for downloads |
| `write-buffer` / `sockbuf` | two windows of queue, no more | same, at client scale |

Only `seed`/`header`/`mtu`/`tti` (mKCP) and
`key`/`crypt`/`mode`/`mtu`/`datashard`/`parityshard`/`nocomp` (kcp-tun) have to match. A
`nocomp` mismatch in particular corrupts the stream silently rather than failing.

Things worth knowing that are not obvious from the upstream docs:

- **Compression is ON by default** in kcp-tun and the payload is already AEAD ciphertext, so
  snappy expands it by 8 bytes per write while burning CPU on both ends. `nocomp: true` is
  set on both sides.
- **FEC cannot be turned off.** `FillDefaults` rewrites `datashard: 0` → 10 and
  `parityshard: 0` → 3, so `0/0` does not mean "no FEC", it means 30% overhead. The only real
  knob is the ratio, and `--loss-pct` picks it: `<1%` → 10/1, `1–3%` → 10/2, `4–9%` → 10/3,
  `≥10%` → 20/10 (a longer group averages bursts out better than 10/5 at the same overhead).
  `ss-kcptun-fec` always sits exactly one tier above that baseline, so the pair is a real A/B.
- **`ratelimit` caps the WIRE rate, and FEC is charged against it.** It is set to 90% of the
  link so the bottleneck queue stays short, which means payload throughput lands at roughly
  `0.9 × link ÷ (1 + parity/data)` — about 82% of the link at 10/1, 69% at 10/3. That is the
  honest price of running FEC behind a sender with no congestion control; the alternative is
  an uncapped blast.
- **`mode: fast` does not enable nodelay** (it is `nodelay 0, interval 30`). The baseline
  uses `fast2`; `mode` overwrites any explicit nodelay/interval/resend/nc, so those are never
  emitted.
- **`conn` / `autoexpire` / `scavengettl` are client-only in effect** — they exist in the
  listener struct but `transport/kcptun/server.go` never reads them, so they are emitted in
  `plugin-opts` and nowhere else. With `conn 4` the client's windows are divided by four, or
  rotation would quietly multiply the queue it exists to shorten.
- **`ratelimit`** is the only real rate limiter kcp-tun has: every mode sets `nc=1`, i.e. no
  congestion control at all. It counts FEC and retransmits, so it also bounds amplification.
- **`read-buffer` on mKCP is inert** in current mihomo — `receivingBufferSize()` has no call
  site. It is emitted for symmetry and does nothing today.
- **`--kcp-mtu` is a conservative constant, not a discovered value.** PMTU discovery relies on
  ICMP, and ICMP is filtered on exactly the networks this matters for, so discovery
  black-holes silently. `mihomoctl pmtu <client-ip>` measures the largest unfragmented
  datagram to a real client address by binary search on the don't-fragment bit — an ICMP
  payload of *P* bytes and a KCP packet of *P* bytes put the same *P+28* bytes on the wire, so
  the answer is directly the largest safe `--kcp-mtu`. It measures **this server's path to
  that address**, and no answer at any size means "ICMP is filtered", not "the MTU is tiny".

### ALPN: a correction worth recording

A natural-looking bug report is that the generated client YAML carries no `alpn:` while the
share links do, so the YAML nodes "advertise no ALPN" — which no browser does. Reading the
source, the premise is wrong.

Every node here sets `client-fingerprint: chrome`, so the ClientHello is assembled by uTLS
from the Chrome parrot template, and **that template's ALPN extension is what goes on the
wire** — not `tls.Config.NextProtos`. mihomo demonstrates this itself: the only way it can
force `http/1.1` for WebSocket is `BuildWebsocketHandshakeState`, which walks
`conn.Extensions` and rewrites the `ALPNExtension` by hand *after* the handshake state is
built. If `NextProtos` were sufficient, that function would not need to exist.

So `alpn:` is emitted only where it can actually matter and cannot hurt:

| Security layer | What `alpn:` reaches | Emitted? |
|---|---|---|
| `reality` | nothing — `GetRealityConn` never receives the `tls.Config` | no |
| `shadowtls` | already defaults to `["h2","http/1.1"]` when unset | no |
| `jls` | passed to `jls.NewClient`; a non-nil value calls `overrideUTLSALPN`, which rewrites the ALPN extension inside a pristine Chrome ClientHello **and drops the ApplicationSettings extension when `h2` is absent** | **no** |
| `tls`, `restls` | `NextProtos`, which the non-uTLS path and RestLS's own config consume | yes |

Where it is emitted, the value is the **browser's** list (`h2`, `http/1.1`), not the
transport-minimal one the share links use — bare `h2` would be a novel fingerprint if it ever
reached the wire, and the server still selects `h2` for gRPC/XHTTP by preference order.
WebSocket gets `http/1.1` alone, since an `h2` selection there breaks the Upgrade.

### TCP Brutal is off by default

`--brutal` is available and deliberately not the default. Brutal is a **fixed-rate** sender
that ignores loss by design. On a path where loss is frequently the censor rather than
congestion, that converts every loss event into a sustained burst — and a sudden burst is one
of the documented triggers for having a flow killed and the IP graylisted. If you turn it on,
the rates must be **measured**: they are negotiated down to
`min(peer receive rate, own send rate)`, so an inflated number does not go faster, it
retransmits into a policer.

### Multiplexing

The four stream-oriented families (`vless`, `vmess`, `trojan`, `ss`) get sing-mux: `smux` on
the client, `mux-option` on the listener. The payoff is not throughput, it is **connection
count** — ISP QoS is reported to bite past roughly 4–8 concurrent connections to one IP, and
every new connection is another first-two-packets event for a protocol whitelister to score.

`anytls` and `snell` are excluded because their listeners have no `mux-option` at all
(`anytls` has native session multiplexing and never routes through the sing handler, so a
client `smux` on it is silently never demultiplexed). The QUIC family already multiplexes
natively, and kcp-tun runs its own smux inside the tunnel.

Padding is set on the **client** side only, and that is deliberate. On a listener,
`mux-option.padding: true` is an *enforcement*: sing-mux rejects every unpadded mux connection
once the server demands it. The generated `client-mihomo.yaml` pads — but a `vless://` share
link has no field that can express sing-mux padding, and neither does the generated sing-box
config, so enforcing it server-side would turn "this client enabled mux" into a hard, silent
failure for everyone outside this script's own YAML. Setting it client-side puts the same
padding on the wire (the server honours a padded connection whether or not it demands one)
with nobody locked out.

The listener therefore emits `mux-option` only when `--brutal` is on, since brutal rates are
the one thing that genuinely has to be declared server-side. The mux *service* itself is
always active on the eight supported inbound types — there is no on/off switch.

### Failover

The client config carries two automatic groups, because they fail over on different principles
and this network kills flows on a timescale neither covers alone:

| Group | Type | Behaviour |
|---|---|---|
| `AUTO` | `url-test` | Lowest latency of everything alive. Best steady-state pick, but it memoises its choice in a singleflight with a **10-second TTL**, so it can keep handing out a node the health checker has already buried. |
| `FAILOVER` | `fallback` | First node in list order that is alive, and it moves the moment it is not. No latency optimisation, no 10 s cache — the one to select when nodes are dying. |

`interval` is seconds (the stock default is 300 — five minutes of a dead node selected, against
flow kills measured at 7–35 s), `tolerance` is milliseconds, and `timeout` is milliseconds.
`timeout` does double duty: it is both the per-probe deadline *and* the window in which
`max-failed-times` failures must occur, so shortening one shortens the other — hence the
matching drop to `max-failed-times: 2`.

`lazy: false` is set on `FAILOVER` alone. `lazy` only decides whether the group you are *not*
using stays warm — the group you have selected is being dialled through, so it probes on every
tick regardless. Setting it on both groups would double the probe traffic to buy nothing, since
the two groups have separate health checkers and do not share results. With the full catalogue
that difference is ~80 extra dials a minute to one IP across ~80 ports, which is a
port-scan-shaped pattern and the opposite of what the multiplexing above is for.

### Measuring instead of guessing

```bash
mihomoctl amplification            # wire bytes / payload bytes, per listener port
mihomoctl amplification --reset    # zero the counters and re-snapshot the baseline
mihomoctl pmtu 1.2.3.4             # largest unfragmented UDP payload to a client address
```

`check` answers "is the port bound", which is the wrong question here. The number that
decides how many days an IP survives is bytes-on-wire over bytes-delivered, because the
graylist that matters is volume-driven — blocks have been reported after roughly 40 GB in two
hours. Every retransmit, FEC parity packet and padding record is charged against that budget.
The wire side is counted by nftables byte counters (chain priority `-300`, so a packet the
firewall later drops still counts — it still crossed the wire); the payload side comes from
mihomo's own RESTful API.

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
| `all` | every valid combination (81) — the default |
| `recommended` | a curated 14 covering every distinct technique |
| `core` | the 8 classics the sing-box / Xray scripts also offer |
| families | `vless` `vmess` `trojan` `anytls` `ss` `snell` `mieru` `sudoku` `trusttunnel` `shadowquic` `quic` `exotic` |
| by security | `reality` `shadowtls` `restls` `jls` `tls` |
| by transport | `ws` `grpc` `xhttp` `mkcp` `mekya` `kcptun` |

Deploying all 81 means 81 listening sockets and 81 firewall openings. It works — but
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

The catalogue was booted end-to-end against **mihomo v1.19.30**: all 81 listeners bind with
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
