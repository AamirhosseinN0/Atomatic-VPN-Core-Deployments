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
the combinations the core rejects or cannot actually use. `--protocols all` deploys all 81;
the default is `sampler`, which deploys exactly one of each base protocol.

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
| `--protocols <sampler\|iran\|antidpi\|recommended\|core\|all\|list>` | `sampler` | Keys, families or security layers, comma-separated. `iran` / `antidpi` are the pinned-port Iranian profiles. Omit it on an interactive run to get the checkbox picker |
| `--no-picker` | picker on | Skip the checkbox picker; use the typed prompt |
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
| `--mtu <n>` | `1280` | Client TUN MTU, 576–9000. The IPv6 minimum, so every network carries it |
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

### No health checks

The client config has exactly **one** proxy group: `PROXY`, of type `select`, holding every
node plus `DIRECT`. There is no `url-test` group, no `fallback` group, and nothing anywhere
with an `interval`.

That is deliberate. A health-checked group is the only thing in a client config that puts
packets on the wire while you are sending none: one dial per node, per group, per interval,
forever. With a full bundle that is a steady drip of connections to a single IP across dozens
of ports — port-scan shaped, on a metered mobile link, whether or not the tunnel is in use.
An idle client here is genuinely idle.

**The trade is real and it is yours to make:** nothing fails over for you. If the node you
picked stops passing traffic, you pick another one in the client. `profile.store-selected: true`
means the choice survives a restart. On this path that is not much of a loss — a url-test group
memoises its pick with a 10-second TTL and can keep handing out a node the checker has already
buried, so it was never the instant escape hatch it looks like.

If you want automatic failover back, add a group to the generated YAML by hand:

```yaml
  - name: AUTO
    type: fallback
    url: https://cp.cloudflare.com/generate_204
    interval: 60
    expected-status: '204'
    proxies: [ ... ]
```

and put `AUTO` at the top of `PROXY`'s list. Know what you are buying: one dial per listed node
per minute, permanently.

### What else was cut, and why

| Setting | Why |
|---|---|
| `unified-delay: false` | It sends a **second** `HEAD` on every latency check so the reported number excludes the handshake (`adapter/adapter.go:259`) — and upstream warns against it on a plain `http://` URL. Dead weight with no automatic checks, and still wrong if you add one back. |
| no `external-controller` | It stands up an HTTP server plus a websocket streaming every connection event, and the tables feeding it are retained. A GUI client injects its own. Add it back if you drive mihomo from the command line. |
| `geo-auto-update: false`, no GEOIP/GEOSITE rules | The geo databases are tens of megabytes resident and are the largest single thing a mihomo client can be made to hold. Every rule in the generated config is a plain CIDR. |

`sniffer` is off, `store-fake-ip` is off, `log-level` is `silent`, `tcp-concurrent` is off, and
`keep-alive-idle` is raised to 600 s so an idle mobile link is not woken every 15 s to hold a
NAT binding open.

---

## MTU: the setting that fails without failing

`--mtu` (default **1280**) is the size of the packet an application hands to the tunnel. It is
the single most likely thing to be wrong on an Iranian path and the least likely to look wrong.

The failure is silent. PMTU discovery needs the router that drops an over-large packet to send
back an ICMP *fragmentation needed*, and MCI/MTN suppress it after a couple of packets. So an
MTU above what the path really carries is never corrected downward — the packets simply
vanish. Handshakes, DNS answers and control frames are small enough to fit and succeed, which
is why **the client reports connected**; full-size TLS records and QUIC datagrams do not, which
is why pages hang half-loaded and image-heavy apps crawl. It also changes between sessions and
between networks, because Wi-Fi over PPPoE (1492), mobile GTP encapsulation (~1400) and CGNAT
each shave off a different amount.

1280 is the IPv6 minimum, so every network on the path is *required* to carry it. That is what
makes it the value to ship on a client that roams: one number, no per-network retuning.
Under-declaring costs about 4% of throughput; over-declaring costs the session.

mihomo's own default is 9000, which assumes a path that will fragment or report back. This one
does neither, so the generated client config writes a `tun:` block — disabled, since TUN needs
`NET_ADMIN` and a GUI toggles it itself — carrying the MTU, so that when TUN *is* switched on
it comes up at a size the path can carry rather than at 9000.

### `--mtu` and `--kcp-mtu` are different numbers

They sit on opposite sides of the encapsulation and neither follows the other:

| Flag | Layer | Default |
|---|---|---|
| `--mtu` | the **inner** packet an app hands to the tunnel | `1280` |
| `--kcp-mtu` | the **outer** UDP datagram mKCP / kcp-tun writes to the wire | `1200` |

`mihomoctl pmtu <host>` measures once and sizes both — the measured payload is directly the
safe `--kcp-mtu`, and the safe `--mtu` is that path MTU less 80 bytes, which covers the worst
case here (IPv4 + UDP + QUIC long header + the AEAD tag a hysteria2/tuic/shadowquic datagram
adds). It measures **this server's path to that address**, so it is a floor for one network and
not a value to ship to a phone that roams; no answer at any size means "ICMP is filtered", not
"the MTU is tiny".

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
| `sampler` | **the default** — exactly one listener per base protocol (12) |
| `iran` | Iran_FucedUPMODE — 11 pinned-port listeners tuned for Iranian mobile carriers |
| `antidpi` | Iran Anti-DPI v2 — 14 pinned-port listeners (JLS / RestLS / ShadowQUIC / mKCP-dtls / kcptun), the six SNI-accepting ones doubled across two port bands (aliases `adpi`, `v2`) |
| `recommended` | a curated 14 covering every distinct technique |
| `core` | the 8 classics the sing-box / Xray scripts also offer |
| `all` | every valid combination (81) |
| families | `vless` `vmess` `trojan` `anytls` `ss` `snell` `mieru` `sudoku` `trusttunnel` `shadowquic` `quic` `exotic` |
| by security | `reality` `shadowtls` `restls` `jls` `tls` |
| by transport | `ws` `grpc` `xhttp` `mkcp` `mekya` `kcptun` |

Deploying all 81 means 81 listening sockets and 81 firewall openings. It works — but it is
the wrong shape for a first deploy, and the script says so.

### `sampler`: one of each, so you can tune

`sampler` is the default because the question you actually have on a censored path is not
"which VLESS transport is fastest" but **"which of these families still passes traffic here at
all"**. `recommended` and `core` both lean towards VLESS, because that is what is popular;
neither answers that question.

`sampler` deploys one node per base protocol — twelve listeners, each the least exotic member
of its family, so a failure is the family's fault and not some transport's:

```
vless-tcp-reality   vmess-ws-tls    trojan-tcp-tls   anytls-tls
ss-plain            snell-plain     hysteria2        tuic
shadowquic          mieru-tcp       sudoku           trusttunnel-tcp
```

Run it, watch which nodes survive on your own path for a day, then re-deploy with
`--protocols <the winner>` and spend the ports on *its* variants instead:

```bash
# tuning deploy: one of everything
sudo bash Mihomo_Deployment.sh --domain vpn.example.com

# hysteria2 held up best -> now deploy its variants and measure those
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols hysteria2,tuic,shadowquic
```

The preference list names *which member* of a family to use; it is not the source of truth for
which families exist. Anything in the catalogue that the list does not cover is picked up
automatically, so a protocol added upstream cannot go missing from the one preset that claims
to cover everything.

### `iran` — Iran_FucedUPMODE

A pinned-port profile for MCI / MTN / Irancell, selectable as `--protocols iran`
or from the preset list in the menu. Eleven listeners, and **it is not part of
`all`**: each entry is one specific (protocol × camouflage × port × tuning)
instance chosen for one path, and sweeping them into `all` would put two
differently-tuned copies of the same combination on one host.

Every listener answers one question rather than just existing:

| Pair | Isolates |
|---|---|
| `443` vs `30443` | identical vless+JLS. Is the carrier filtering the **port**, or the protocol? |
| `8801` vs `41821` | the same question for UDP, on identical kcptun listeners |
| `3478` vs `19302` | identical mKCP except `congestion` |
| `8801` vs `8802` | FEC 10/3 + interval 20 against 10/4 + interval 10 |
| `443` `2053` `2083` `2087` `2096` | five protocol × camouflage pairs on ports that carry plausible HTTPS |

```
ir-jls-vless-443       tcp/443    vless  + JLS      -> cdn.jsdelivr.net
ir-jls-vless-30443     tcp/30443  vless  + JLS      -> cdn.jsdelivr.net   (port control)
ir-restls-vless-2053   tcp/2053   vless  + RestLS   -> cdn.jsdelivr.net
ir-jls-trojan-2083     tcp/2083   trojan + JLS      -> cdnjs.cloudflare.com
ir-restls-vmess-2087   tcp/2087   vmess  + RestLS   -> unpkg.com
ir-restls-anytls-2096  tcp/2096   anytls + RestLS   -> www.bing.com
ir-mkcp-vmess-3478     udp/3478   vmess  + mKCP srtp, congestion on
ir-mkcp-vmess-19302    udp/19302  vmess  + mKCP srtp, congestion off
ir-kcptun-ss-8801      udp/8801   ss2022 + kcptun manual, FEC 10/3, interval 20
ir-kcptun-ss-8802      udp/8802   ss2022 + kcptun manual, FEC 10/4, interval 10
ir-kcptun-ss-41821     udp/41821  ss2022 + kcptun manual, FEC 10/3   (port control)
```

**Ports are not interchangeable with the headers they carry.** 3478/udp is the
IANA STUN port and mKCP wears `header: srtp` there, so the packets look like
WebRTC media on the port WebRTC actually uses; srtp on a random high port is a
contradiction a classifier can see. 19302 is Google's public STUN port, same
reasoning. 8801/8802 sit in Zoom's media range. 8443 is deliberately unused —
the local decoy nginx binds `127.0.0.1:8443` and a `::` listener would collide.

**Each TCP listener relays failed probes to a different site.** Pointing all of
them at one CDN repeats the mistake of pointing all of them at Apple: one
reclassification and the whole family goes at once.

**Every listener has its own secrets.** The rest of the catalogue shares a UUID
across a family, which is fine when the nodes differ only by transport. Here two
listeners are the same protocol on different ports specifically so they can be
compared, so a leaked config for the `30443` control must not also hand over
`443`, and the three kcptun nodes must not share the key identifying their
stream. Each RestLS listener also gets its own record programme — sharing one
would give all three the same record-length signature, which is the one thing
RestLS exists to remove.

#### `mode: manual` is load-bearing

`transport/kcptun/common.go` defaults an **empty** mode to `"fast"` and then
switches on it; `normal`/`fast`/`fast2`/`fast3` each overwrite
`nodelay`/`interval`/`resend`/`nc` wholesale. There is no `default:` arm, so only
a value outside that set leaves your timers alone. Setting the timers next to a
preset mode is not an error — they are silently discarded, which is worse.

| mode | nodelay, interval, resend, nc |
|---|---|
| `normal` | 0, 40, 2, 1 |
| `fast` | 0, 30, 2, 1 |
| `fast2` | 1, 20, 2, 1 |
| `fast3` | 1, 10, 2, 1 |
| `manual` | whatever you set |

#### The two MTUs

`mtu: 1232` on kcptun/mKCP is the **outer UDP datagram**: 1280 − 40 (IPv6
header) − 8 (UDP header). The listener binds `::` so it must survive the IPv6
case; on IPv4 the packet lands at 1260. `mtu: 1280` in the client `tun:` block is
the **inner packet**. Lowering one does not lower the other, and both are correct
at the same time.

#### Before deploying

```bash
ss -ulnp | grep 3478       # coturn likes this port
sysctl net.core.rmem_max   # must be >= 16777216 or sockbuf is clamped to ~200 KB
```

The script's own kernel tuning sets `rmem_max` to exactly 16777216, so that is
satisfied unless you ran `--no-kernel-tuning`. Port 443 needs
`CAP_NET_BIND_SERVICE`; the generated unit already grants it.

Only mihomo-based clients can dial any of this — JLS, RestLS, mKCP and kcptun
have no share-link grammar, so it is `client-mihomo.yaml` import, not a
subscription URL.

The profile is named `Iran_FucedUPMODE`; the CLI token is `iran` (aliases
`iran-mobile`, `ir`) because the original name contains a `*`, which a shell
expands before the script ever sees the word.

### `antidpi` — Iran Anti-DPI v2

```bash
sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols antidpi
```

A second pinned-port profile (`--protocols antidpi`, aliases `adpi` / `v2`),
built to the "Circumventing DPI on Iranian Cellular Networks" specification: the
five evasion transports it names — **RestLS**, **JLS**, **ShadowQUIC**,
**mKCP**, **kcptun** — on the ports it names. Like `iran` it is a separate
catalogue and is **not** part of `--protocols all`.

Its guiding requirement is *SNI variety*. Iranian DPI does destination-based
graylisting, so every listener that carries a Server Name presents a **different**
one, drawn from the spec's Tier-1 list (device / OS-update / enterprise-cloud
names millions of idle handsets already query). The six SNI-accepting listeners
are **doubled across two port bands**, giving twelve distinct names — so a name
burned on one node does not take the rest with it.

```
adpi-restls-vless-443     tcp/443    vless  + RestLS   -> teams.microsoft.com
adpi-jls-trojan-2053      tcp/2053   trojan + JLS      -> login.live.com
adpi-restls-vmess-2083    tcp/2083   vmess  + RestLS   -> graph.microsoft.com
adpi-jls-vless-2087       tcp/2087   vless  + JLS      -> outlook.office.com
adpi-restls-anytls-2096   tcp/2096   anytls + RestLS   -> www.bing.com
adpi-squic-8443           udp/8443   shadowquic (JLS)  -> cloudflare-quic.com
adpi-mkcp-vmess-4500      udp/4500   vmess  + mKCP dtls, congestion off
adpi-kcptun-ss-3478       udp/3478   ss2022 + kcptun fast2, FEC 10/3
adpi-restls-vless-8443    tcp/8443   vless  + RestLS   -> gateway.icloud.com
adpi-jls-trojan-4443      tcp/4443   trojan + JLS      -> swdist.apple.com
adpi-restls-vmess-9443    tcp/9443   vmess  + RestLS   -> download.visualstudio.microsoft.com
adpi-jls-vless-8843       tcp/8843   vless  + JLS      -> datadoghq.com
adpi-restls-anytls-7443   tcp/7443   anytls + RestLS   -> registry.npmjs.org
adpi-squic-8444           udp/8444   shadowquic (JLS)  -> dl.google.com
```

**mKCP and kcptun carry no TLS/SNI, so they are single** — one mKCP on udp/4500
(the IPSec NAT-T port carriers keep open) and one kcptun on udp/3478 (the
STUN/WebRTC port real-time media keeps alive).

#### What this profile pins, and where it departs from the spec

- **MTU 1280 everywhere.** The spec names several MTUs (1350, 1280, …); on the
  measured path anything above 1280 black-holes, so 1280 is used for *both* the
  outer KCP/mKCP datagram *and* the inner client TUN. This overrides the spec's
  1350 and the `iran` profile's 1232.
- **mKCP** wears the `dtls` header with `congestion: false` (the spec's choice),
  server capacities 50/100 and 4 MB buffers; the client mirror carries 20/80.
- **kcptun** runs `mode: fast2`, FEC 10/3, compression on (`nocomp: false`),
  `dscp: 46`, `conn: 2`, 512 windows — the spec's block verbatim, with one
  correction: `crypt` is **`aes-128`**, not the spec's `aes-128-gcm` (kcp-go has
  no `-gcm` cipher, and that value fails to boot). No rate cap is set, as the
  spec omits one — watch it with `mihomoctl amplification`.
- **ShadowQUIC** relays to its per-listener SNI via the source-verified
  `jls-upstream:` block (mihomo's real schema; the spec's top-level `dest:` is a
  different tool's). The client carries `zero-rtt: false`, `bbr-profile:
  aggressive`, `disable-mtu-discovery: true` and `max-datagram-frame-size: 1280`.
  Its `up`/`down` come from `--client-up-mbps` / `--client-down-mbps` (default
  15/60) rather than the spec's fixed 40/100, so an over-declared uplink cannot
  burst you into a policer — pass `--client-up-mbps 40 --client-down-mbps 100`
  for the spec's exact figures.
- **Certificate-less.** All five transports borrow a TLS identity or carry no
  TLS, so an `antidpi` node needs no domain certificate, no Let's Encrypt order
  and no port 80 — `CERT_MODE` drops to `self` automatically.
- **Per-listener secrets.** Like `iran`, every listener gets its own UUID /
  password / JLS credentials / RestLS record programme, so a leaked config for
  one SNI/port does not hand over the others.

#### Client DNS and routing (shared with `iran`)

Selecting either Iranian profile switches the generated `client-mihomo.yaml` to
the hardened DNS and routing the spec calls for:

- **Plain UDP resolvers only** — `1.1.1.1` and `8.8.8.8` on `:53`. No DoH/DoT:
  encrypted DNS fails closed on networks that block `:443` to public resolvers,
  which is exactly this path. `fake-ip` still keeps the real hostname inside the
  tunnel, so the local ISP resolver never sees it and `10.10.34.34`-style
  poisoning has nothing to catch.
- **`.ir` stays domestic** — filtered out of `fake-ip` and pinned to Shecan
  (`10.202.10.202`) and 403 (`178.22.122.100`) so banking / gov / university
  sites resolve and route inside Iran, via a `DOMAIN-SUFFIX,ir,DIRECT` rule that
  needs no geo database.
- **Browser QUIC dropped** — `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT` forces
  browsers off HTTP/3 (which stalls under mobile UDP throttling) back onto the
  TCP tunnels. It matches app traffic to `:443/udp`, not the tunnel's own dial to
  the ShadowQUIC servers, which sit on 8443/8444.

Only mihomo-based clients can dial `antidpi` — JLS, RestLS, mKCP, kcptun and
ShadowQUIC have no share-link grammar, so it is a `client-mihomo.yaml` import,
not a subscription URL.

### The interactive menu

Run the script with no flags and you get one screen holding **every setting it has** — with its
current value — instead of a thirty-question interrogation you cannot go back in. Arrow keys
move, `Enter` edits the highlighted row, `d` deploys.

```
   mihomo deployment settings   12 listener(s)
   Every setting this script has. Enter edits the highlighted row.

   ── Server identity
 ❯ Domain (FQDN)              <required>
   Public IPv4                203.0.113.10
   Node label                 <from the domain>
   ── mihomo build
   Release channel            stable
   GOAMD64 level              auto
   ── Protocols
   Selection                  sampler  (12 listeners)
   Bind address               ::
   Auto-assign ports          yes
   ── Certificate and camouflage
   Certificate source         letsencrypt
   ...

   the name clients dial, and the certificate CN. Required.
   enter edit   ←/→ cycle a choice   d deploy   q cancel
```

| Key | Does |
|---|---|
| `↑` `↓` / `k` `j` | move between settings |
| `←` `→` | cycle a multiple-choice setting without leaving the row |
| `Enter` | edit — a text prompt, a toggle, or the protocol picker |
| `PgUp` `PgDn`, `g` `G` | page, jump to top or bottom |
| `d` | deploy with these settings |
| `q` / `Esc` | cancel the run |

The line above the key list is the help for whatever row you are on, so the explanation is
where you are looking rather than in `--help`.

**Rows appear and disappear as you answer.** A setting that cannot matter given your other
answers is hidden, not greyed out — a control you can see and change but that is never read is
worse than one that is absent, because it reads as having taken effect. Pick `sampler` and you
are asked about the Shadowsocks cipher and the Snell version; pick `--protocols quic` and both
vanish along with the RestLS record floor. Set the channel to `pinned` and a tag row appears
directly beneath it. Choose a selection that wants no certificate and the whole certificate
section goes.

At a text field, `Enter` on an empty line keeps the current value and `-` clears it — which is
how you say "no Let's Encrypt contact address", "auto-detect the IP" or "turn the RESTful
controller off".

Two things are checked before `d` will deploy: a domain that is actually a domain, and a
version tag if the channel is `pinned`. Both fail with a message at the top of the menu rather
than eight steps into an install.

### The protocol picker

`Enter` on the **Selection** row opens the picker. First screen is the presets as radio
buttons; `e` opens the highlighted preset as an editable checklist, and `custom` opens the full
81-entry catalogue:

```
 ❯ (●) sampler       one listener per protocol family  12 listener(s)
   ( ) iran          Iran_FucedUPMODE — pinned ports, mobile-carrier tuning  11 listener(s)
   ( ) antidpi       Iran Anti-DPI v2 — JLS/RestLS/ShadowQUIC/mKCP/kcptun, multi-SNI  14 listener(s)
   ( ) recommended   a curated spread of every distinct technique  14 listener(s)
   ( ) core          the classics the sing-box / Xray scripts also offer  8 listener(s)
   ( ) all           every valid combination in the catalogue  81 listener(s)
   ( ) custom …      tick individual protocols on the next screen

 ── vless
 ❯ [✓] vless-tcp-reality       tcp  tcp        reality
   [ ] vless-tcp-tls           tcp  tcp        tls
   [ ] vless-ws-tls            tcp  ws         tls
```

| Key | Does |
|---|---|
| `space` | tick or untick the node under the cursor |
| `f` | tick or untick the **whole family** the cursor is in |
| `a` / `n` / `i` | all / none / invert |
| `Enter` | accept |
| `q` / `Esc` | back to the menu, unchanged |

A hand-ticked set that happens to equal a preset is stored under the preset's name rather than
as an 81-key comma string.

### When the menu is skipped

`-y`, a `TERM` the script cannot drive, a terminal smaller than 50x14, or `--no-picker` all fall
back to asking the same settings one line at a time. Both front ends walk **one** table, so a
parameter cannot be editable in the menu and invisible in the typed prompt — which is exactly
how the older version ended up asking about eleven settings and silently defaulting twenty.
With `-y` nothing is asked at all and every value comes from a flag or its default.

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
