# Xray_Deployment

One self-contained Bash script that turns a fresh **Ubuntu 22.04 / 24.04 / 26.04** server
into a multi-protocol **Xray-core** proxy node — picking free ports, generating every
secret, validating the config before it ever restarts the service, tuning the kernel, and
emitting ready-to-import client bundles.

```bash
sudo bash Xray_Deployment.sh
```

---

## What you get

You choose **all** protocols or just a few:

| Key | Protocol | Certificate |
|---|---|---|
| `vless-reality` | VLESS + Vision + REALITY (RAW/TCP) | none |
| `vless-xhttp-reality` | VLESS + XHTTP + REALITY | none |
| `vless-encryption` | VLESS post-quantum Encryption (ML-KEM-768) + Vision | none |
| `vless-ws` | VLESS + WebSocket + TLS | yes |
| `vless-xhttp` | VLESS + XHTTP + TLS | yes |
| `vmess-ws` | VMess + WebSocket + TLS | yes |
| `trojan` | Trojan + TLS | yes |
| `hysteria2` | Hysteria2 (QUIC/UDP) — native in Xray since v26.3.27 | yes |
| `ss2022` | Shadowsocks 2022 (TCP+UDP) | none |

Each deployment writes six client artefacts to `/root/xray-clients/`:

| File | For |
|---|---|
| `links.txt` | one share link per line |
| `subscription.txt` | base64 subscription (v2rayN, NekoBox, Streisand, Shadowrocket) |
| `client-xray.json` | Xray client config — understands **every** protocol here |
| `client-singbox.json` | sing-box client config (compatible subset — see below) |
| `client-clash.yaml` | mihomo / Clash.Meta config |
| `README.txt` | port map, credentials, per-protocol client notes |

---

## Two port layouts

**`dedicated`** (default) — every protocol listens on its own auto-discovered free port.

**`fallback`** — Xray's signature feature. VLESS+Vision owns **TCP/443 with one
certificate** and routes VLESS-ws / VMess-ws / Trojan-ws to loopback inbounds by path.
To a probe the server looks like a single ordinary HTTPS site.

```bash
sudo bash Xray_Deployment.sh --port-mode fallback --fallback-dest 80
```

REALITY, XHTTP, Hysteria2 and Shadowsocks always keep their own port — REALITY consumes
the ClientHello and cannot share a certificate-based TLS listener, and fallbacks are a
TCP-only mechanism. Hysteria2 on **UDP/443** coexists happily with the TCP/443 gateway.

---

## Release channels

Xray uses CalVer (`vYY.M.D`) and **has published no new *stable* tag since 2026-03-27** —
every build since is flagged pre-release. A bare `install` therefore gives you a
months-old binary.

| `--channel` | Meaning |
|---|---|
| `latest` *(default)* | newest build of any kind (`install --beta`) |
| `stable` | GitHub's latest non-prerelease |
| `pinned` | an exact tag: `--version v26.7.28` |

---

## Quick start

```bash
sudo bash Xray_Deployment.sh --domain vpn.example.com
```

Fully unattended, a subset of protocols:

```bash
sudo bash Xray_Deployment.sh -y --domain vpn.example.com --protocols vless-reality,hysteria2,ss2022
```

Afterwards the script installs itself as `/usr/local/sbin/xrayctl` (when run from a saved file — a piped `wget -O- … | bash` run skips this and says so):

```bash
xrayctl info        # reprint links / subscription / credentials
xrayctl status      # service + listening ports
xrayctl check       # re-run every health check
xrayctl update      # upgrade Xray in the chosen channel
xrayctl regen-sub   # rebuild client bundles from saved state
xrayctl uninstall   # remove configuration
```

---

## Options

| Option | Default | Notes |
|---|---|---|
| `--domain <fqdn>` | *required* | what clients connect to; the certificate CN |
| `--ip <ipv4>` | auto-detected | |
| `--channel <latest\|stable\|pinned>` | `latest` | |
| `--version <tag>` | | implies `--channel pinned` |
| `--protocols <all\|list>` | `all` | comma list of keys (menu numbers work at the interactive prompt only) |
| `--port-mode <dedicated\|fallback>` | `dedicated` | |
| `--fallback-dest <target>` | none | catch-all decoy, e.g. `80` |
| `--cert-mode <letsencrypt\|self>` | `letsencrypt` | |
| `--reality-sni <host>` | `www.microsoft.com` | REALITY steal target |
| `--firewall <auto\|ufw\|iptables\|none>` | `auto` | |
| `--no-kernel-tuning` | tuning on | |
| `--serve-sub` | off | serve the subscription over HTTP at a secret path |
| `-y, --yes` | off | Unattended; requires `--domain` |
| `--le-email <email>` | — | Let's Encrypt contact (blank = register without one) |
| `--skip-preflight` | off | Skip the OS/arch/DNS pre-flight checks |

---

## Client compatibility

Not every client speaks every protocol. The script generates three formats precisely
because of this, and omits nodes a given client cannot use rather than emitting configs
that silently fail:

| Feature | Xray client | sing-box | mihomo |
|---|---|---|---|
| VLESS + REALITY + Vision | yes | yes | yes |
| VLESS / VMess + WS + TLS | yes | yes | yes |
| Trojan, Shadowsocks 2022 | yes | yes | yes |
| Hysteria2 | yes | yes | yes |
| **XHTTP** | yes | **no** | yes (VLESS only) |
| **VLESS Encryption** | yes | **no** | **no** |

`client-singbox.json` therefore contains only the protocols upstream sing-box implements.
Use `client-xray.json` for XHTTP and VLESS Encryption nodes.

> **VLESS Encryption** needs an Xray-core client v25.9.5+ (v2rayN 7.14.9+).

---

## Correctness notes

Xray changed a great deal through 2025–2026, and most guides on the internet are stale.
This script was written against the current source and every generated config is
validated with `xray run -test` **before** the service is restarted. Things it gets right
that older guides do not:

- **`allowInsecure` is a hard error** now. Self-signed mode pins the certificate with
  `pinnedPeerCertSha256` — a *hex string* of the SHA-256 over the whole DER certificate,
  not base64, and not an array.
- **`alterId` is no longer parsed at all** — VMess is AEAD-only.
- **Hysteria2's credential field is `auth`, not `password`**, `version` must be `2` in
  *both* `settings` and `hysteriaSettings`, and Xray's Hysteria has **no obfs field** —
  Salamander is not supported, so it is absent from the server and every client artefact.
- **WebSocket advertises only `http/1.1`.** Offering `h2` invites a client or CDN to
  negotiate HTTP/2 and break the Upgrade handshake.
- **`h2`, `h3`, `http` and `quic` transports are removed** (hard errors), as are mKCP's
  `header`/`seed` and legacy `xtls` security.
- VLESS inbounds always carry `decryption`, which is mandatory even when it is `"none"`.
- REALITY is only offered on RAW and XHTTP — it is rejected on WebSocket.
- Fallback `dest` is emitted as `127.0.0.1:<port>` rather than a bare port number, which
  Xray rewrites to `localhost:<port>` and can resolve to `::1` first on a dual-stack host.
- The script emits the *older* spelling of renamed-but-still-accepted keys (`network`,
  `tcp`, `clients`, `dest`, `freedom`) so one config is valid on every channel.

> **REALITY and older clients:** current Xray defaults `minClientVer` to `26.3.27`.
> If a non-Xray client (sing-box, mihomo) fails the REALITY handshake against an
> otherwise-working server, set `minClientVer` explicitly in
> `/usr/local/etc/xray/config.json` and restart.

---

## Kernel tuning

Applied as a `/etc/sysctl.d/99-xray.conf` drop-in, so keys the running kernel does not
know are skipped rather than aborting. BBR + `fq`, 16 MiB UDP buffer ceilings, larger
backlogs, TCP Fast Open, MTU probing, and conntrack timeouts sized for a proxy.

Xray gained QUIC with native Hysteria2 in v26.3.27, so the large UDP buffers are
warranted. They are also free: `rmem_max`/`wmem_max` are *ceilings on what a socket may
request*, not allocations — TCP autotuning uses `tcp_rmem`/`tcp_wmem` and ignores them
entirely.

Obsolete keys that old guides still set (`tcp_tw_recycle`, `tcp_low_latency`,
`fs.file-max`) are deliberately absent.

---

## Security notes

- `/root/xray-clients/` contains **private keys, UUIDs and cleartext passwords**. Copy
  what you need over `scp`, then delete the rest.
- `--serve-sub` publishes your credentials over **plain HTTP** at a secret path. It is a
  convenience for the first import, not a long-term hosting solution — the token in the
  URL is the only access control.
- The service runs as an unprivileged user (`nobody` with the official installer's
  unit, `xray` with the built-in fallback unit); certificates are chowned to that
  user rather than loosening their permissions.
- Routing blocks clients from reaching the server's own private ranges and loopback.
- Nothing server-specific is committed — `.gitignore` is deny-by-default and blocks keys,
  bundles and state files.

---

## Troubleshooting

```bash
xrayctl check                                  # every health check
journalctl -u xray -f                          # live log
xray run -test -c /usr/local/etc/xray/config.json   # validate the config
ss -tulpn | grep xray                          # is it actually listening?
```

---

## License

MIT — see [LICENSE](LICENSE).
